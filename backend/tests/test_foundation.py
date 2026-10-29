import base64
from datetime import timedelta
from app.db import utcnow
from app.compliance.engine import evaluate
from app.policies.schema import PolicyDocument, CATALOG, merge_layers
from app.models import Device, PolicyVersion, Policy, Administrator
from app.security.crypto import canonical, digest
import pytest


def create_device(client, mac="00:11:22:33:44:55", cls="STANDARD"):
    result = client.post("/api/v1/devices", json={"hostname": "PC-001", "primary_mac": mac, "device_class": cls})
    assert result.status_code == 201, result.text
    return result.json()


def create_policy(client):
    p = client.post("/api/v1/policies", json={"name": "Standard"}).json()
    v = client.post(f'/api/v1/policies/{p["id"]}/publish', json={"document": PolicyDocument().model_dump(), "reason": "Initial audit baseline"})
    assert v.status_code == 200, v.text
    return p, v.json()


def test_auth_csrf_rbac(client):
    assert client.get("/api/v1/devices").status_code == 401
    assert client.post("/api/v1/auth/login", json={"username": "viewer", "password": "test-password-at-least-16"}).status_code == 403
    r = client.post("/api/v1/auth/login", headers={"origin": "https://testserver"}, json={"username": "viewer", "password": "test-password-at-least-16"})
    assert r.status_code == 200
    assert "HttpOnly" in r.headers["set-cookie"] and "Secure" in r.headers["set-cookie"]
    client.headers.update({"origin": "https://testserver", "x-csrf-token": r.json()["csrf"]})
    assert client.get("/api/v1/devices").status_code == 200
    assert client.post("/api/v1/devices", json={"hostname": "X", "primary_mac": "00:11:22:33:44:55"}).status_code == 403
    client.headers.pop("x-csrf-token")
    assert client.post("/api/v1/auth/logout").status_code == 403


def test_duplicate_mac_and_unmanaged(admin):
    d = create_device(admin, cls="DEVELOPER")
    assert d["state"] == "UNVERIFIED" and d["compliance_score"] is None
    assert admin.get(f'/api/v1/devices/{d["id"]}/compliance').json()["score"] is None
    assert admin.post("/api/v1/devices", json={"hostname": "X", "primary_mac": "001122334455"}).status_code == 409
    assert admin.post(f'/api/v1/devices/{d["id"]}/enrollment-token').status_code == 409


def test_compliance_missing_stale_version_and_sources():
    p = PolicyDocument().model_dump()
    now = utcnow()
    agent, network = {}, {}
    for key, (source, _) in CATALOG.items():
        if source != "server":
            (network if source == "network" else agent)[key] = {"status": "PASS", "verified_at": now.isoformat(), "source": source, "version_id": "v1"}
    assert evaluate(p, "v1", "v1", agent, network)["score"] == 100
    agent.pop("firewall.enabled")
    r = evaluate(p, "v1", "v1", agent, network)
    assert r["score"] < 100 and r["state"] == "UNVERIFIED"
    assert evaluate(p, "v2", "v1", agent, network)["state"] == "NONCOMPLIANT"
    for c in network.values():
        c["verified_at"] = (now - timedelta(hours=1)).isoformat()
    assert evaluate(p, "v1", "v1", agent, network)["score"] < 100
    assert all(c["status"] == "UNKNOWN" for c in evaluate(p, "v1", "v1", agent, network)["checks"] if c["source"] == "network")


def test_policy_publication_and_rollback_invalidate_compliance(admin, app):
    d = create_device(admin)
    p, v = create_policy(admin)
    assert admin.post(f'/api/v1/policies/{p["id"]}/assign', json={"version_id": v["id"], "device_ids": [d["id"]]}).status_code == 200
    with app.state.sessions.begin() as db:
        device = db.get(Device, d["id"])
        device.state, device.compliance_score, device.last_verified, device.last_heartbeat = "COMPLIANT", 100, utcnow(), utcnow()
    new = admin.post(f'/api/v1/policies/{p["id"]}/publish', json={"document": PolicyDocument(require_d=False).model_dump(), "reason": "Approved D drive exception baseline", "expected_version_id": v["id"]})
    assert new.status_code == 200
    current = admin.get(f'/api/v1/devices/{d["id"]}').json()
    assert current["state"] == "UNVERIFIED" and current["compliance_score"] == 0
    assert current["policy_version_id"] == new.json()["id"]
    assert admin.post(f'/api/v1/policies/{p["id"]}/publish', json={"document": PolicyDocument().model_dump(), "reason": "Stale concurrent update", "expected_version_id": v["id"]}).status_code == 409
    rollback = admin.post(f'/api/v1/policies/{p["id"]}/rollback', json={"version_id": v["id"], "expected_version_id": new.json()["id"], "reason": "Restore original configuration"})
    assert rollback.status_code == 200 and rollback.json()["id"] != v["id"]


def test_precedence_restrictions_need_approval():
    p = PolicyDocument().model_dump()
    layer = {"id": "override", "priority": 30, "controls": {"require_d": False}}
    with pytest.raises(ValueError):
        merge_layers(p, [layer])
    layer["approved_relaxation"] = True
    assert merge_layers(p, [layer])["require_d"] is False


def test_stale_heartbeat_not_compliant(admin, app):
    d = create_device(admin)
    with app.state.sessions.begin() as db:
        device = db.get(Device, d["id"])
        device.state, device.compliance_score = "COMPLIANT", 100
        device.last_verified, device.last_heartbeat = utcnow(), utcnow() - timedelta(hours=1)
    assert admin.get(f'/api/v1/devices/{d["id"]}').json()["state"] == "UNVERIFIED"


def test_storage_migration_does_not_execute(admin, app):
    d = create_device(admin)
    r = admin.post(f'/api/v1/devices/{d["id"]}/migration-assessment')
    assert r.status_code == 200
    assert r.json()["status"] == "MANUAL_INTERVENTION_REQUIRED"
    assert r.json()["destructive_execution_available"] is False


def test_mfa_setup_and_replay(client):
    import pyotp
    from urllib.parse import urlparse, parse_qs
    r = client.post("/api/v1/auth/login", headers={"origin": "https://testserver"}, json={"username": "owner", "password": "test-password-at-least-16"})
    client.headers.update({"origin": "https://testserver", "x-csrf-token": r.json()["csrf"]})
    assert client.post("/api/v1/policies/nope/publish", json={"document": PolicyDocument().model_dump(), "reason": "test baseline"}).status_code == 403
    setup = client.post("/api/v1/auth/mfa/setup").json()
    secret = parse_qs(urlparse(setup["uri"]).query)["secret"][0]
    code = pyotp.TOTP(secret).now()
    assert client.post("/api/v1/auth/mfa/confirm", json={"challenge": setup["challenge"], "code": code}).status_code == 200
    assert client.post("/api/v1/auth/mfa/reauthenticate", json={"code": code}).status_code == 401
