import base64
import secrets
import time
from datetime import timedelta
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509.oid import NameOID
from sqlalchemy import select
from app.db import utcnow
from app.models import Device, DeviceCredential, Enrollment, AdminSession
from app.security.crypto import canonical, digest
from app.policies.schema import PolicyDocument
from test_foundation import create_device, create_policy


def signed_request(client, key, fingerprint, method, path, payload=None, nonce=None, timestamp=None, **kwargs):
    raw = canonical(payload) if payload is not None else b""
    nonce, timestamp = nonce or secrets.token_hex(24), timestamp or str(int(time.time()))
    message = f"{method}\n{path}\n{timestamp}\n{nonce}\n{digest(raw)}".encode()
    headers = {"X-Device-Certificate": fingerprint, "X-Device-Time": timestamp, "X-Device-Nonce": nonce,
               "X-Device-Signature": base64.b64encode(key.sign(message, padding.PKCS1v15(), hashes.SHA256())).decode(), "Content-Type": "application/json"}
    headers.update(kwargs.pop("headers", {}))
    return client.request(method, path, content=raw, headers=headers, **kwargs)


@pytest.fixture
def enrolled(admin, app):
    d = create_device(admin)
    p, v = create_policy(admin)
    admin.post(f'/api/v1/policies/{p["id"]}/assign', json={"device_ids": [d["id"]], "version_id": v["id"]})
    token = admin.post(f'/api/v1/devices/{d["id"]}/enrollment-token').json()["token"]
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "PC-001")])).sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode()
    body = {"token": token, "csr": csr, "primary_mac": d["primary_mac"]}
    first = admin.post("/api/v1/agent/enroll", json=body)
    assert first.status_code == 202
    with app.state.sessions.begin() as db:
        e = db.scalar(select(Enrollment).where(Enrollment.device_id == d["id"]))
        e.approved = True
    approved = admin.post("/api/v1/agent/enroll", json=body)
    assert approved.status_code == 200, approved.text
    return d, key, approved.json()["fingerprint"], v


def test_enrollment_requires_token_and_approval(admin, app):
    d = create_device(admin)
    bad = admin.post("/api/v1/agent/enroll", json={"token": "x"*40, "csr": "fake", "primary_mac": d["primary_mac"]})
    assert bad.status_code == 401
    assert admin.get("/api/v1/agent/policy").status_code == 401


def test_signed_policy_heartbeat_evidence_and_replay(admin, app, enrolled):
    d, key, fingerprint, version = enrolled
    response = signed_request(admin, key, fingerprint, "GET", "/api/v1/agent/policy")
    assert response.status_code == 200, response.text
    envelope = response.json()
    app.state.vault.signer.public_key().verify(base64.b64decode(envelope["signature"]), base64.b64decode(envelope["payload"]), padding.PKCS1v15(), hashes.SHA256())
    assert signed_request(admin, key, fingerprint, "GET", "/api/v1/agent/policy", headers={"if-none-match": response.headers["etag"]}).status_code == 304
    payload = {"agent_version": "0.1.0", "os_version": "Windows 11", "policy_version_id": version["id"], "health": {"cpu_percent": 5, "password": "never store"}}
    nonce = secrets.token_hex(24)
    assert signed_request(admin, key, fingerprint, "POST", "/api/v1/agent/heartbeat", payload, nonce=nonce).status_code == 200
    assert signed_request(admin, key, fingerprint, "POST", "/api/v1/agent/heartbeat", payload, nonce=nonce).status_code == 401
    assert signed_request(admin, key, fingerprint, "POST", "/api/v1/agent/heartbeat", payload, timestamp=str(int(time.time())-200)).status_code == 401
    assert "password" not in str(admin.get(f'/api/v1/devices/{d["id"]}/health').json())
    # A device must never supply independently verified network evidence.
    rejected = signed_request(admin, key, fingerprint, "POST", "/api/v1/agent/compliance", {"policy_version_id": version["id"], "claims": {"network.isolation.valid": {"status": "PASS"}}})
    assert rejected.status_code == 422
    result = signed_request(admin, key, fingerprint, "POST", "/api/v1/agent/compliance", {"policy_version_id": version["id"], "claims": {"firewall.enabled": {"status": "PASS"}}, "inventory": {"volumes": [{"drive": "C"}, {"drive": "D"}], "personal_files": ["secret"]}})
    assert result.status_code == 200 and result.json()["score"] < 100
    assert "personal_files" not in admin.get('/api/v1/devices/'+d["id"]).json()["inventory"]


def test_revocation_immediate(admin, app, enrolled):
    d, key, fingerprint, _ = enrolled
    assert admin.delete('/api/v1/devices/'+d["id"]).status_code == 200
    assert signed_request(admin, key, fingerprint, "GET", "/api/v1/agent/policy").status_code == 401


def test_exceptions_are_device_specific_and_core_not_waivable(admin, app):
    d = create_device(admin)
    other = create_device(admin, "00:11:22:33:44:66")
    r = admin.post(f'/api/v1/devices/{d["id"]}/exceptions', json={"controls": ["disk.d.valid"], "reason": "Small SSD requires approved exemption"})
    assert r.status_code == 200
    assert admin.get(f'/api/v1/devices/{other["id"]}/exceptions').json() == []
    assert admin.post(f'/api/v1/devices/{d["id"]}/exceptions', json={"controls": ["agent.integrity_valid"], "reason": "Attempt to bypass critical gate"}).status_code == 422
    assert admin.delete(f'/api/v1/devices/{d["id"]}/exceptions/{r.json()["id"]}').status_code == 200
