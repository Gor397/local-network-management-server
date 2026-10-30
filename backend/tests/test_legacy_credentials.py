import base64
import json
import re
from sqlalchemy import select
from app.models import AdminCredential, AuditLog, Device
from test_agent_protocol import enrolled  # noqa: F401  (fixture)
from app.services.legacy_credentials import legacy_mac_v1, legacy_mac_candidates, legacy_state, random_password

# Produced by this port and by an independent statement-by-statement JavaScript transliteration of
# Convert-MacToUniquePassword (5,004 vectors agreed). Not yet confirmed by running the original in
# Windows PowerShell; see docs/developers/legacy-credentials.md for that one-line check.
VECTORS = {
    "00-11-22-33-44-55": "TNW20StG!Y",
    "A4-C3-F0-85-7E-21": "DCP83vUt*Y",
    "FF-FF-FF-FF-FF-FF": "DHS49dtI&8",
    "00-00-00-00-00-01": "FHC33IQA&K",
}


def test_legacy_algorithm_vectors_and_mac_formats():
    for mac, password in VECTORS.items():
        assert legacy_mac_v1(mac) == password
        assert legacy_mac_v1(mac.replace("-", ":").lower()) == password
        assert legacy_mac_v1(mac.replace("-", "")) == password
    shape = re.compile(r"^[A-Z]{3}[0-9]{2}[A-Za-z]{3}[!@#$%^&*][0-9A-Z]$")
    assert all(shape.match(legacy_mac_v1(f"02-00-00-00-{i // 256:02X}-{i % 256:02X}")) for i in range(2000))
    for bad in ("", "00-11-22-33-44", "GG-11-22-33-44-55"):
        try:
            legacy_mac_v1(bad)
            raise AssertionError(bad)
        except ValueError as error:
            assert str(error) == "credential.invalid_mac"


def test_random_password_has_all_classes():
    values = {random_password() for _ in range(50)}
    assert len(values) == 50
    for value in values:
        assert len(value) == 20 and re.search("[A-Z]", value) and re.search("[a-z]", value) and re.search("[0-9]", value)


def test_candidates_follow_script_selection():
    adapters = [
        {"name": "Ethernet", "mac": "10:00:00:00:00:01", "status": "Up", "media_type": "802.3", "description": "Intel"},
        {"name": "Wi-Fi 2", "mac": "10:00:00:00:00:02", "status": "Disconnected", "media_type": "Native 802.11", "description": "USB"},
        {"name": "Wi-Fi", "mac": "12:00:00:00:00:03", "permanent_mac": "100000000004", "status": "Up",
         "media_type": "Native 802.11", "description": "Intel Wireless"},
        {"name": "vWiFi", "mac": "10:00:00:00:00:05", "status": "Up", "media_type": "Native 802.11",
         "description": "Microsoft Wi-Fi Direct Virtual Adapter"},
    ]
    result = legacy_mac_candidates(adapters, "10:00:00:00:00:09")
    assert [c["mac"] for c in result] == ["12:00:00:00:00:03", "10:00:00:00:00:04", "10:00:00:00:00:02", "10:00:00:00:00:09"]
    assert [c["source"] for c in result] == ["current", "permanent", "current", "registered"]
    # Older agents do not report media type: every adapter is a candidate, marked unclassified.
    old = legacy_mac_candidates([{"name": "Wi-Fi", "mac": "10:00:00:00:00:02"}])
    assert old[0]["classified"] is False


def test_legacy_state_detects_boot_firewall_reset():
    inventory = {"users": [{"name": "AcademyAdmin", "enabled": True, "administrator": True}],
                 "legacy": {"startup_task": {"state": "Ready", "kursant_username": "student"},
                            "persisting_scripts": ["kursant_persisting_ru.ps1"],
                            "firewall_rule_addresses": ["192.168.0.1", "10.47.47.47"], "winre_state": "0"}}
    state = legacy_state(inventory, "https://10.0.0.5")
    assert state["kursant_username"] == "student" and state["server_allowed_after_boot"] is False
    assert {"legacy.admin_account_present", "legacy.firewall_reset_at_boot", "legacy.server_blocked_after_boot",
            "legacy.winre_disabled"} <= set(state["findings"])
    assert legacy_state(inventory, "https://10.47.47.47")["server_allowed_after_boot"] is True
    assert "legacy.server_address_unverified" in legacy_state(inventory, "https://suro.local")["findings"]
    inventory["legacy"]["startup_task"]["state"] = "Disabled"
    assert "legacy.firewall_reset_at_boot" not in legacy_state(inventory, "https://10.0.0.5")["findings"]
    assert legacy_state({}, "https://10.0.0.5")["reported"] is False


def _device(admin, app, adapters=None):
    device_id = admin.post("/api/v1/devices", json={"hostname": "PC-1", "primary_mac": "00:11:22:33:44:55"}).json()["id"]
    if adapters is not None:
        with app.state.sessions.begin() as db:
            db.get(Device, device_id).inventory = {"network_adapters": adapters}
    return device_id


def test_legacy_credential_reveal_is_authorized_and_audited(admin, app):
    device_id = _device(admin, app, [{"name": "Wi-Fi", "mac": "A4:C3:F0:85:7E:21", "status": "Up",
                                      "media_type": "Native 802.11", "description": "Intel"}])
    base = f"/api/v1/devices/{device_id}/admin-credential"
    shown = admin.get(base).json()
    assert shown["credential"] is None and shown["candidates"][0]["mac"] == "A4:C3:F0:85:7E:21"
    assert admin.post(base, json={"scheme": "LEGACY_MAC_V1", "source_mac": "nope", "reason": "legacy import"}).status_code == 422
    created = admin.post(base, json={"scheme": "LEGACY_MAC_V1", "source_mac": "a4-c3-f0-85-7e-21", "reason": "legacy import"})
    assert created.status_code == 201 and created.json()["status"] == "UNVERIFIED" and "password" not in created.text
    assert admin.post(base, json={"scheme": "LEGACY_MAC_V1", "source_mac": "A4:C3:F0:85:7E:21", "reason": "again!"}).status_code == 409
    assert admin.post(base + "/reveal", json={"reason": "x"}).status_code == 422
    revealed = admin.post(base + "/reveal", json={"reason": "local recovery at desk"})
    assert revealed.status_code == 200 and revealed.json()["password"] == "DCP83vUt*Y"
    assert revealed.headers["cache-control"] == "no-store"
    revision = created.json()["revision"]
    assert admin.post(base + "/verification", json={"result": "VERIFIED", "revision": revision + 5, "reason": "logged in"}).status_code == 409
    verified = admin.post(base + "/verification", json={"result": "VERIFIED", "revision": revision, "reason": "logged in"})
    assert verified.json()["status"] == "VERIFIED"
    with app.state.sessions.begin() as db:
        logs = db.scalars(select(AuditLog).where(AuditLog.target_id == device_id)).all()
        assert {"credential.registered", "credential.revealed", "credential.verification_recorded"} <= {a.action for a in logs}
        assert all("DCP83vUt" not in str(a.details) for a in logs)
        assert next(a for a in logs if a.action == "credential.registered").details["mac_matches_inventory"] is True


def test_random_credential_is_sealed_and_mfa_gated(admin, app):
    device_id = _device(admin, app)
    base = f"/api/v1/devices/{device_id}/admin-credential"
    created = admin.post(base, json={"scheme": "RANDOM_V1", "account": "SuroAdmin", "reason": "new machine"}).json()
    assert created["status"] == "PENDING_APPLY"
    password = admin.post(base + "/reveal", json={"reason": "set during provisioning"}).json()["password"]
    with app.state.sessions.begin() as db:
        record = db.scalar(select(AdminCredential))
        assert record.secret and password not in record.secret
        for session in db.query(__import__("app.models", fromlist=["AdminSession"]).AdminSession):
            session.mfa_at = None
    assert admin.post(base + "/reveal", json={"reason": "no recent mfa"}).status_code == 403


def test_viewer_cannot_register_or_reveal(client, admin, app):
    device_id = _device(admin, app)
    base = f"/api/v1/devices/{device_id}/admin-credential"
    admin.post(base, json={"scheme": "RANDOM_V1", "reason": "new machine"})
    client.post("/api/v1/auth/logout")
    login = client.post("/api/v1/auth/login", headers={"origin": "https://testserver"},
                        json={"username": "viewer", "password": "test-password-at-least-16"})
    client.headers.update({"x-csrf-token": login.json()["csrf"]})
    assert client.get(base).status_code == 200
    assert client.post(base + "/reveal", json={"reason": "curious viewer"}).status_code == 403
    assert client.post(base, json={"scheme": "RANDOM_V1", "replace": True, "reason": "takeover"}).status_code == 403


def test_firewall_policy_is_refused_while_kursant_task_resets_it(admin, app, enrolled):
    from test_agent_protocol import signed_request
    d, key, fp, _ = enrolled
    path = f"/api/v1/devices/{d['id']}/maintenance"
    legacy = {"startup_task": {"state": "Ready", "kursant_username": "student"}, "firewall_rule_addresses": ["10.47.47.47"]}
    with app.state.sessions.begin() as db:
        device = db.get(Device, d["id"])
        device.mode, device.inventory = "MAINTENANCE", {"legacy": legacy}
    firewall = {"operation": "firewall.apply_allowlist", "replace_legacy_rules": True, "reason": "move to Suro rules"}
    assert admin.post(path, json=firewall).json()["error"]["code"] == "maintenance.legacy_task_active"
    retire = admin.post(path, json={"operation": "legacy.retire_startup_task", "enable_winre": True, "reason": "stop boot reset"})
    assert retire.status_code == 200, retire.text
    manifest = signed_request(admin, key, fp, "GET", "/api/v1/agent/maintenance/next").json()["job"]
    payload = json.loads(base64.b64decode(manifest["payload"]))
    assert payload["operation"] == "legacy.retire_startup_task" and payload["enable_winre"] is True
    # Once the agent reports the task disabled, the reviewed firewall migration is accepted.
    with app.state.sessions.begin() as db:
        db.get(Device, d["id"]).inventory = {"legacy": {**legacy, "startup_task": {"state": "Disabled"}}}
    assert admin.post(path, json=firewall).status_code == 200
    with app.state.sessions.begin() as db:
        db.get(Device, d["id"]).inventory = {}
    assert admin.post(path, json=firewall).json()["error"]["code"] == "maintenance.legacy_state_unknown"
    assert admin.post(path, json={"operation": "legacy.retire_startup_task", "reason": "nothing there"}).json()["error"]["code"] == "maintenance.legacy_task_not_reported"
