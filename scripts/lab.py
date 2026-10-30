#!/usr/bin/env python3
"""Create and validate a loopback-only Compose lab; never contacts routers or production endpoints."""
import argparse
import base64
import hashlib
import hmac
import http.cookiejar
import json
from pathlib import Path
import secrets
import ssl
import subprocess
import time
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[1]
DATA = Path("/tmp/lantern-lab-data")
ENV = Path("/tmp/lantern-lab.env")
ORIGIN = "https://localhost:18443"
COMPOSE = ["docker", "compose", "-p", "lantern-lab", "--env-file", str(ENV), "-f", str(ROOT / "compose.yaml"),
           "-f", str(ROOT / "infrastructure/docker/compose.lab.yaml")]


def run(arguments, **kwargs):
    return subprocess.run(arguments, cwd=ROOT, check=True, **kwargs)


def prepare():
    if ENV.exists():
        text = ENV.read_text()
        if f"PUBLIC_ORIGIN={ORIGIN}\n" not in text or f"LAB_DATA_DIR={DATA}\n" not in text:
            raise SystemExit("Existing lab configuration does not match fixed safe paths; preserved without modification.")
        print("Existing loopback lab preserved.")
        return
    if DATA.exists() and any(DATA.iterdir()):
        raise SystemExit("Existing nonempty lab directory preserved. Recover its matching env instead of rotating keys.")
    retained = subprocess.run(["docker", "volume", "ls", "--quiet", "--filter", "label=com.docker.compose.project=lantern-lab"],
                              capture_output=True, text=True, check=False)
    if retained.returncode:
        raise SystemExit("Cannot inspect retained lab storage. Start Docker before preparing test keys.")
    if retained.stdout.strip():
        raise SystemExit("Retained lab database found without its matching configuration. Restore /tmp/lantern-lab.env and /tmp/lantern-lab-data from the same backup; existing volumes were preserved and no keys generated.")
    (DATA / "keys").mkdir(parents=True, exist_ok=True, mode=0o700)
    (DATA / "tls").mkdir(exist_ok=True)
    for name in ("ca", "signing"):
        run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072", "-out", str(DATA / f"keys/{name}.key")], stderr=subprocess.DEVNULL)
        (DATA / f"keys/{name}.key").chmod(0o600)
        run(["openssl", "pkey", "-in", str(DATA / f"keys/{name}.key"), "-pubout", "-out", str(DATA / f"keys/{name}.pub")])
    run(["openssl", "req", "-x509", "-new", "-key", str(DATA / "keys/ca.key"), "-days", "2", "-subj", "/CN=Lantern Lab CA",
         "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0", "-out", str(DATA / "keys/ca.crt")], stderr=subprocess.DEVNULL)
    run(["openssl", "req", "-x509", "-newkey", "rsa:3072", "-nodes", "-days", "2", "-subj", "/CN=localhost",
         "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1", "-out", str(DATA / "tls/server.crt"), "-keyout", str(DATA / "tls/server.key")], stderr=subprocess.DEVNULL)
    password = secrets.token_hex(32)
    values = {"LAB_ENV_FILE": str(ENV), "LAB_DATA_DIR": str(DATA), "POSTGRES_USER": "lantern", "POSTGRES_DB": "lantern",
              "POSTGRES_PASSWORD": password, "DATABASE_URL": f"postgresql+psycopg://lantern:{password}@db/lantern",
              "ENCRYPTION_KEY": base64.urlsafe_b64encode(secrets.token_bytes(32)).decode(), "DATA_DIR": "/data",
              "PUBLIC_ORIGIN": ORIGIN, "TRUSTED_HOSTS": "localhost,127.0.0.1", "COOKIE_SECURE": "true",
              "LOW_RESOURCE_MODE": "true", "OPERATION_MODE": "read_only", "ROUTER_ALLOWED_NETWORKS": "127.0.0.1/32", "ROUTER_WRITES_ENABLED": "false", "DEPLOYMENT_ENABLED": "false", "SSH_ENABLED": "false", "LANTERN_TAG": "0.1.0"}
    ENV.write_text("".join(f"{k}={v}\n" for k, v in values.items()))
    ENV.chmod(0o600)
    print("Prepared test-only keys and configuration. Build/import images, then run lab.py up.")


def up():
    prepare()
    code = """import os
from pathlib import Path
for root, directories, files in os.walk('/data'):
    os.chown(root,10001,10001)
    for name in files: os.chown(os.path.join(root,name),10001,10001)
os.chmod('/data',0o700)
os.chown('/data/tls',10001,101)
os.chmod('/data/tls',0o750)
os.chown('/data/tls/server.key',10001,101)
os.chmod('/data/tls/server.key',0o640)
os.chmod('/data/tls/server.crt',0o644)
"""
    run(["docker", "run", "--rm", "--user", "0", "--entrypoint", "python", "-v", f"{DATA}:/data", "lantern-backend:0.1.0", "-c", code])
    run(COMPOSE + ["up", "-d", "--no-build", "--wait", "--wait-timeout", "180"])


def smoke():
    password, secret = secrets.token_urlsafe(32), base64.b32encode(secrets.token_bytes(20)).decode()
    code = """import json,sys
from sqlalchemy import select
from argon2 import PasswordHasher
from app.config import Settings
from app.db import database
from app.models import Role,Administrator,AdminSession
from app.auth.dependencies import PERMISSIONS
from app.security.crypto import Vault
s=Settings(); assert s.public_origin=='https://localhost:18443'
data=json.load(sys.stdin);_,sessions=database(s.database_url)
with sessions.begin() as db:
    for name,permissions in PERMISSIONS.items():
        if not db.get(Role,name): db.add(Role(name=name,permissions=list(permissions)))
    db.flush()
    admin=db.scalar(select(Administrator).where(Administrator.username=='lab-smoke'))
    if not admin:
        admin=Administrator(username='lab-smoke',role='owner',password_hash='');db.add(admin);db.flush()
    admin.password_hash=PasswordHasher().hash(data['password'])
    admin.totp_secret=Vault(s).seal(data['secret']);admin.totp_last_step=-1;admin.enabled=True
    for session in db.scalars(select(AdminSession).where(AdminSession.admin_id==admin.id)):db.delete(session)
print('Isolated MFA test identity prepared.')
"""
    run(COMPOSE + ["exec", "-T", "backend", "python", "-c", code], input=json.dumps({"password": password, "secret": secret}), text=True)
    # The test certificate is a trust anchor for this HTTPS client; never bypass TLS validation.
    certificate = subprocess.check_output(COMPOSE + ["exec", "-T", "backend", "cat", "/data/tls/server.crt"], cwd=ROOT).decode()
    context = ssl.create_default_context(cadata=certificate)
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()), urllib.request.HTTPSHandler(context=context))
    csrf = ""
    def request(path, method="GET", body=None):
        payload = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(ORIGIN + path, data=payload, method=method,
              headers={"Content-Type": "application/json", "Origin": ORIGIN, "X-CSRF-Token": csrf})
        with opener.open(req, timeout=30) as response:
            raw = response.read()
            return json.loads(raw) if "application/json" in response.headers.get("content-type", "") else raw.decode()
    assert "Suro" in request("/")
    code_bytes = hmac.new(base64.b32decode(secret), (int(time.time()) // 30).to_bytes(8, "big"), hashlib.sha1).digest()
    index = code_bytes[-1] & 15
    totp = str((int.from_bytes(code_bytes[index:index+4], "big") & 0x7fffffff) % 1000000).zfill(6)
    identity = request("/api/v1/auth/login", "POST", {"username": "lab-smoke", "password": password, "totp": totp})
    csrf = identity["csrf"]
    assert identity["mfa"] is True
    request('/api/v1/auth/logout','POST')
    identity=request('/api/v1/auth/login','POST',{'username':'lab-smoke','password':password})
    csrf=identity['csrf']
    assert not identity['mfa'] and identity['mfa_available']
    suffix = uuid.uuid4().hex[:10]
    mac = "00:" + ":".join(f"{b:02X}" for b in secrets.token_bytes(5))
    device = request("/api/v1/devices", "POST", {"hostname": "Lab-" + suffix, "primary_mac": mac})
    policy = request("/api/v1/policies", "POST", {"name": "Lab-" + suffix})
    version = request(f'/api/v1/policies/{policy["id"]}/publish', "POST", {"document": {"schema_version": 1}, "reason": "Isolated HTTPS smoke test"})
    request(f'/api/v1/policies/{policy["id"]}/assign', "POST", {"version_id": version["id"], "device_ids": [device["id"]]})
    inventory = request("/api/v1/devices?q=Lab-" + suffix)
    assert inventory["total"] == 1 and inventory["items"][0]["state"] == "UNVERIFIED"
    compliance = request(f'/api/v1/devices/{device["id"]}/compliance')
    assert compliance["score"] < 100
    request(f'/api/v1/devices/{device["id"]}/owner','PUT',{'full_name':'Արամ Սարգսյան','military_rank':None,'verified':True,'reason':'Isolated Unicode owner smoke test'})
    group=request('/api/v1/groups','POST',{'name':'Lab group '+suffix,'device_ids':[device['id']]})
    assert group['id']
    ap_group=request('/api/v1/mikrotik/groups','POST',{'name':'Lab AP group '+suffix,'router_ids':[]})
    assert ap_group['id']
    assert request('/api/v1/devices?q='+urllib.parse.quote('Արամ'))['total']>=1
    assert request('/api/v1/system/monitoring-settings')['recovery_enabled'] is False
    assert request('/api/v1/network/topology')['unknown_links']
    assert request('/api/v1/incidents')['items']==[]
    result = {"https": True, "mfa_login": True, "password_only_login":True,"unicode_owners":True,"separate_groups":True,"topology":True,"safe_monitoring_defaults":True,"device_registration": True, "policy_publish_assign": True,
              "unverified_evidence_gate": True, "resources": request("/api/v1/system/resources")}
    request("/api/v1/auth/logout", "POST")
    Path("/tmp/lantern-lab-verification.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["prepare", "build", "up", "smoke", "down", "logs"])
    action = parser.parse_args().action
    if action == "prepare": prepare()
    elif action == "build":
        prepare()
        run(COMPOSE + ["build"])
        run(COMPOSE + ["pull", "db"])
    elif action == "up": up()
    elif action == "smoke": smoke()
    elif action == "down": run(COMPOSE + ["down"])
    else: run(COMPOSE + ["logs", "--tail", "60"])


if __name__ == "__main__":
    main()
