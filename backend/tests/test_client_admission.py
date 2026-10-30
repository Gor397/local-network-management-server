"""Mandatory Suro Client admission: decisions, the per-MAC router gate, timed grants, onboarding and safety."""
import copy
import json
from datetime import timedelta
from types import SimpleNamespace
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from sqlalchemy import select
from app.db import utcnow
from app.models import AdmissionPolicy, AuditLog, Device, NetworkAdmission, Router, SoftwarePackage
from app.mikrotik.connector import snapshot_hash
from app.services import admission_gate as gate
from app.services.safety import GuardedRouter
from test_agent_protocol import enrolled, signed_request  # noqa: F401  (fixture)
from test_foundation import create_device

MAC = "00:11:22:33:44:55"  # the enrolled fixture's laptop
PEER = "AA:00:00:00:00:02"
SERVER = "192.168.88.10"


def base_snapshot():
    return {
        "system/resource": [{"version": "6.49.10 (long-term)", "board-name": "RB4011"}],
        "system/package": [{"name": "ipv6", "disabled": "false"}],
        "interface": [{"name": "bridge", "mac-address": "48:A9:8A:00:00:01"}],
        "ip/address": [{"address": "192.168.88.1/24", "interface": "bridge"}],
        "ip/arp": [{".id": "*A1", "address": "192.168.88.50", "mac-address": MAC},
                   {".id": "*A2", "address": "192.168.88.51", "mac-address": PEER}],
        "ip/dhcp-server/lease": [{".id": "*L1", "address": "192.168.88.50", "mac-address": MAC, "status": "bound"}],
        "ip/firewall/filter": [{".id": "*1", "chain": "forward", "connection-state": "established,related", "action": "accept", "comment": "defconf"},
                               {".id": "*2", "chain": "input", "action": "accept", "protocol": "icmp", "comment": "defconf"}],
        "ipv6/firewall/filter": [{".id": "*61", "chain": "forward", "action": "accept", "comment": "defconf"}],
        "ip/firewall/address-list": [{".id": "*B1", "list": "blocked", "address": "10.0.0.9", "comment": "manual"}],
    }


class FakeRouterOS:
    """Ordered RouterOS tables with add (incl. place-before), remove and print."""

    def __init__(self, snapshot):
        self.tables, self.writes, self.next = copy.deepcopy(snapshot), [], 100

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass

    async def read(self, path, **kwargs):
        return copy.deepcopy(self.tables.get(path, []))

    async def discovery(self):
        return {"snapshot": copy.deepcopy(self.tables), "capabilities": {"stacks": []}}

    async def apply(self, op):
        self.writes.append(op)
        rows = self.tables.setdefault(op["path"], [])
        if op["method"] == "DELETE":
            rows[:] = [r for r in rows if r[".id"] != op["id"]]
            return {}
        self.next += 1
        data = {k: v for k, v in op["data"].items() if k != "place-before"}
        row = {".id": f"*{self.next}", **data, **({"dynamic": "true"} if "timeout" in data else {})}
        before = next((i for i, r in enumerate(rows) if r[".id"] == op["data"].get("place-before")), len(rows))
        rows.insert(before, row)
        return {".id": row[".id"]}


@pytest.fixture
def router_env(app, monkeypatch):
    app.state.settings.operation_mode = "production"
    app.state.settings.management_address = SERVER
    fake = FakeRouterOS(base_snapshot())
    with app.state.sessions.begin() as db:
        r = Router(name="Gateway", base_url="https://192.168.88.1", username="suro", secret=app.state.vault.seal("x"),
                   transport="REST", role="ROUTER", write_enabled=True, capabilities={"stacks": []},
                   snapshot=app.state.vault.seal(json.dumps(base_snapshot())), status="ONLINE")
        db.add(r)
        db.flush()
        router_id = r.id
    import app.services.network as network
    monkeypatch.setattr(network, "connector", lambda a, router: GuardedRouter(fake, a.state.settings, router))
    return SimpleNamespace(fake=fake, router_id=router_id)


def policy(**changes):
    values = dict(mode="PILOT", require_enrollment=True, require_running_agent=True, require_compliance=False,
                  exempt_developers=True, heartbeat_timeout_seconds=300, grace_seconds=300, outage_policy="EXPIRE")
    return SimpleNamespace(**{**values, **changes})


def device(**changes):
    values = dict(device_class="STANDARD", admission_exempt=False, last_heartbeat=utcnow(), primary_mac=MAC, id="d1")
    return SimpleNamespace(**{**values, **changes})


def test_decisions_keep_enrollment_agent_and_compliance_separate():
    a = SimpleNamespace(enabled=True, override=None, override_until=None)
    now = utcnow()
    assert gate.evaluate(device(), a, policy(), True, "NONCOMPLIANT", now) == ("AUTHORIZED", "admission.agent_verified")  # case K
    assert gate.evaluate(device(), a, policy(require_compliance=True), True, "NONCOMPLIANT", now)[1] == "admission.noncompliant"
    assert gate.evaluate(device(), a, policy(), False, "COMPLIANT", now)[1] == "admission.not_enrolled"  # case A/C
    assert gate.evaluate(device(last_heartbeat=None), a, policy(), True, "", now)[1] == "admission.agent_never_connected"
    # Case D/F: a short silence stays authorized for the grace period, then access is withdrawn.
    assert gate.evaluate(device(last_heartbeat=now - timedelta(seconds=400)), a, policy(), True, "", now)[1] == "admission.grace_period"
    assert gate.evaluate(device(last_heartbeat=now - timedelta(seconds=700)), a, policy(), True, "", now)[1] == "admission.agent_offline"
    assert gate.evaluate(device(device_class="DEVELOPER"), a, policy(), False, "", now)[0] == "EXEMPT"  # case E
    assert gate.evaluate(device(device_class="DEVELOPER"), a, policy(exempt_developers=False), False, "", now)[0] == "RESTRICTED"
    assert gate.evaluate(device(admission_exempt=True), a, policy(), False, "", now)[0] == "EXEMPT"
    assert gate.evaluate(device(), a, policy(mode="DISABLED"), False, "", now)[0] == "NOT_REQUIRED"
    a.override, a.override_until = "RESTRICT", now + timedelta(minutes=5)
    assert gate.evaluate(device(), a, policy(), True, "COMPLIANT", now)[1] == "admission.override_restricted"
    assert gate.ttl_seconds(policy()) == 600 and gate.ttl_seconds(policy(outage_policy="HOLD")) == 0


def test_gate_matches_only_the_pilot_mac_and_is_idempotent():
    d, snapshot = device(), base_snapshot()
    ops = gate.gate_plan(d, SERVER, snapshot)
    assert {op["data"]["chain"] for op in ops} == {"forward", "input"} and len(ops) == 3
    for op in ops:
        assert op["data"]["action"] == "drop" and op["data"]["src-mac-address"] == MAC
    forward = next(op for op in ops if op["data"]["comment"].endswith(":forward"))
    assert forward["data"]["dst-address"] == "!" + SERVER and forward["data"]["src-address-list"] == "!suro-admitted"
    fake = FakeRouterOS(snapshot)
    import asyncio
    for op in ops:
        asyncio.run(fake.apply(op))
    assert gate.placement_verified(ops, fake.tables)
    assert gate.gate_plan(d, SERVER, fake.tables) == []
    no_ipv6 = {**snapshot, "system/package": [{"name": "ipv6", "disabled": "true"}]}
    assert len(gate.gate_plan(d, SERVER, no_ipv6)) == 2
    removal = gate.removal_plan(d, fake.tables)
    assert len(removal) == 3 and all(op["owned_comment"].startswith("lantern:d1:admission:") for op in removal)


def test_transport_refuses_firewall_writes_suro_does_not_own():
    from app.services.safety import firewall_shape
    good = {"method": "PUT", "path": "ip/firewall/filter", "data": {"chain": "forward", "action": "drop", "src-mac-address": MAC,
                                                                   "comment": "lantern:d1:admission:forward"}}
    firewall_shape(good)
    for bad in ({**good, "data": {**good["data"], "action": "accept"}},
                {**good, "data": {**good["data"], "src-mac-address": None}},
                {**good, "data": {**good["data"], "comment": "manual"}},
                {"method": "DELETE", "path": "ip/firewall/filter", "id": "*1", "owned_comment": "defconf"},
                {"method": "PATCH", "path": "ip/firewall/filter", "id": "*1", "data": {"comment": "lantern:d1:admission:x"}},
                {"method": "PUT", "path": "ip/firewall/address-list", "data": {"list": "x", "address": "1.1.1.1"}}):
        with pytest.raises(ValueError):
            firewall_shape(bad)


def test_feasibility_reports_blockers_and_layer2_limits():
    r = SimpleNamespace(transport="API", capabilities={"stacks": ["capsman"]}, role="GATEWAY", protected=True)
    report = gate.feasibility(r, base_snapshot(), device(), SERVER)
    assert "admission.router_read_only_transport" in report["blockers"]
    assert "admission.same_subnet_not_isolated" in report["warnings"] and report["facts"]["same_subnet_hosts"] == 1
    r.transport = "REST"
    assert gate.feasibility(r, base_snapshot(), device(), SERVER)["blockers"] == []
    assert "admission.infrastructure_mac" in gate.feasibility(r, base_snapshot(), device(primary_mac="48:A9:8A:00:00:01"), SERVER)["blockers"]
    elsewhere = {**base_snapshot(), "ip/address": [{"address": "10.1.1.1/24"}]}
    assert "admission.router_not_gateway_for_device" in gate.feasibility(r, elsewhere, device(), SERVER)["blockers"]


def test_snapshot_hash_ignores_counters_and_timed_entries():
    a = base_snapshot()
    b = copy.deepcopy(a)
    b["ip/firewall/filter"][0]["bytes"] = "999"
    b["ip/firewall/address-list"].append({".id": "*G", "list": "suro-admitted", "dynamic": "true", "timeout": "9m"})
    assert snapshot_hash(a) == snapshot_hash(b)


def test_policy_starts_disabled_and_network_wide_modes_are_refused(admin, client, app):
    current = admin.get("/api/v1/admission/policy").json()
    assert current["mode"] == "DISABLED"
    body = {**{k: v for k, v in current.items() if k not in ("group_ids", "updated_at")}, "reason": "enable everywhere"}
    assert admin.put("/api/v1/admission/policy", json={**body, "mode": "ALL"}).json()["error"]["code"] == "admission.mode_requires_staged_rollout"
    assert admin.put("/api/v1/admission/policy", json={**body, "mode": "PILOT", "heartbeat_timeout_seconds": 10}).status_code == 422
    assert admin.put("/api/v1/admission/policy", json={**body, "mode": "PILOT"}).json()["mode"] == "PILOT"


async def run_worker(app):
    from app.services.admission_sync import reconcile
    with app.state.sessions() as db:
        await reconcile(app, db)
        db.commit()


def admission(app):
    with app.state.sessions() as db:
        row = db.scalar(select(NetworkAdmission))
        db.expunge(row)
        return row


def enable_pilot(admin, router_env):
    admin.put("/api/v1/admission/policy", json={**{k: v for k, v in admin.get("/api/v1/admission/policy").json().items()
                                                  if k not in ("group_ids", "updated_at")}, "mode": "PILOT", "reason": "pilot laptop"})
    added = admin.post("/api/v1/admission/pilot", json={"mac": MAC.lower(), "router_id": router_env.router_id, "reason": "pilot laptop"})
    assert added.status_code == 201, added.text
    return added.json()["device_id"]


async def test_pilot_gate_grant_expiry_and_rollback(admin, app, router_env, enrolled):
    d, key, fingerprint, _ = enrolled
    device_id = enable_pilot(admin, router_env)
    assert device_id == d["id"]
    preview = admin.post(f"/api/v1/admission/devices/{device_id}/gate-preview", json={"reason": "install gate"}).json()
    assert preview["feasibility"]["blockers"] == [] and "admission.same_subnet_not_isolated" in preview["feasibility"]["warnings"]
    applied = admin.post(f"/api/v1/admission/devices/{device_id}/apply", json={"plan_id": preview["plan"]["id"], "reason": "install gate"})
    assert applied.json()["state"] == "VERIFIED", applied.text
    tables = router_env.fake.tables
    assert tables["ip/firewall/filter"][0]["comment"].endswith(":forward") and tables["ip/firewall/filter"][2]["comment"] == "defconf"
    assert applied.json()["admission"]["network"] == "RESTRICTED"
    # Case B: the enrolled agent reports through a signed heartbeat; the router confirms its IP; a timed grant follows.
    beat = {"agent_version": "0.3.0", "os_version": "10", "health": {"ip": "192.168.88.50"}}
    assert signed_request(admin, key, fingerprint, "POST", "/api/v1/agent/heartbeat", beat).status_code == 200
    await run_worker(app)
    grant = [r for r in tables["ip/firewall/address-list"] if r.get("list") == "suro-admitted"]
    assert grant == [{".id": grant[0][".id"], "list": "suro-admitted", "address": "192.168.88.50", "timeout": "600s",
                      "comment": f"lantern:{device_id}:admission:grant", "dynamic": "true"}]
    state = admission(app)
    assert state.applied == "AUTHORIZED" and state.granted_ip == "192.168.88.50" and state.error is None
    writes = len(router_env.fake.writes)
    await run_worker(app)
    assert len(router_env.fake.writes) == writes  # no router traffic while the grant is fresh
    # Case D: the agent stops; after timeout + grace the grant is revoked (and would also expire on the router).
    with app.state.sessions.begin() as db:
        db.get(Device, device_id).last_heartbeat = utcnow() - timedelta(seconds=700)
    await run_worker(app)
    assert not [r for r in tables["ip/firewall/address-list"] if r.get("list") == "suro-admitted"]
    assert admission(app).applied == "RESTRICTED" and admission(app).reason == "admission.agent_offline"
    # Switching the requirement off lets the computer through at once, permanently, until the gate is removed.
    admin.patch(f"/api/v1/admission/devices/{device_id}", json={"enabled": False, "reason": "stop pilot"})
    await run_worker(app)
    permanent = [r for r in tables["ip/firewall/address-list"] if r.get("list") == "suro-admitted"]
    assert permanent and "timeout" not in permanent[0]
    # Rollback removes only Suro's entries.
    removal = admin.post(f"/api/v1/admission/devices/{device_id}/removal-preview", json={"reason": "end pilot"}).json()
    done = admin.post(f"/api/v1/admission/devices/{device_id}/apply", json={"plan_id": removal["plan"]["id"], "reason": "end pilot"})
    assert done.json()["state"] == "VERIFIED"
    assert [r["comment"] for r in tables["ip/firewall/filter"]] == ["defconf", "defconf"]
    assert [r["comment"] for r in tables["ip/firewall/address-list"]] == ["manual"]
    assert tables["ipv6/firewall/filter"] == base_snapshot()["ipv6/firewall/filter"]


async def test_safety_modes_block_router_writes_and_state_stays_pending(admin, app, router_env, enrolled):
    d, key, fingerprint, _ = enrolled
    device_id = enable_pilot(admin, router_env)
    app.state.settings.operation_mode = "dry_run"
    preview = admin.post(f"/api/v1/admission/devices/{device_id}/gate-preview", json={"reason": "install gate"}).json()
    result = admin.post(f"/api/v1/admission/devices/{device_id}/apply", json={"plan_id": preview["plan"]["id"], "reason": "dry run"}).json()
    assert result["state"] == "DRY_RUN" and router_env.fake.writes == []
    with app.state.sessions.begin() as db:
        db.scalar(select(NetworkAdmission)).gate_state = "INSTALLED"  # as if installed earlier
    signed_request(admin, key, fingerprint, "POST", "/api/v1/agent/heartbeat",
                   {"agent_version": "0.3.0", "os_version": "10", "health": {"ip": "192.168.88.50"}})
    await run_worker(app)
    assert router_env.fake.writes == [] and admission(app).error == "safety.dry_run" and admission(app).applied == "NONE"


async def test_unconfirmed_ip_is_never_granted(admin, app, router_env, enrolled):
    d, key, fingerprint, _ = enrolled
    device_id = enable_pilot(admin, router_env)
    with app.state.sessions.begin() as db:
        db.scalar(select(NetworkAdmission)).gate_state = "INSTALLED"
    # Case G: claiming another host's address is refused because the router ties it to a different MAC.
    signed_request(admin, key, fingerprint, "POST", "/api/v1/agent/heartbeat",
                   {"agent_version": "0.3.0", "os_version": "10", "health": {"ip": "192.168.88.51"}})
    await run_worker(app)
    assert admission(app).error == "admission.ip_unconfirmed" and not router_env.fake.writes


def test_infrastructure_and_developer_devices_cannot_be_piloted(admin, router_env):
    developer = create_device(admin, mac="00:11:22:33:44:66", cls="DEVELOPER")
    blocked = admin.post("/api/v1/admission/pilot", json={"mac": developer["primary_mac"], "router_id": router_env.router_id, "reason": "try it"})
    assert blocked.json()["error"]["code"] == "admission.device_exempt"
    infra = create_device(admin, mac="00:11:22:33:44:67", cls="INFRASTRUCTURE")
    assert admin.post("/api/v1/admission/pilot", json={"mac": infra["primary_mac"], "router_id": router_env.router_id,
                                                       "reason": "try it"}).json()["error"]["code"] == "admission.device_exempt"


def csr():
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    return x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "x")])).sign(
        key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode()


def test_portal_enrollment_needs_an_open_window_and_admin_approval(admin, client, app, router_env):
    device_id = enable_pilot(admin, router_env)
    request = csr()
    body = {"csr": request, "macs": ["AA:BB:CC:00:00:01", MAC], "hostname": "LAPTOP-07"}
    closed = client.post("/api/v1/agent/onboarding-request", json=body)
    assert closed.status_code == 202 and closed.json()["token"] is None
    admin.post(f"/api/v1/admission/devices/{device_id}/onboarding-window", json={"minutes": 30, "reason": "laptop setup"})
    opened = client.post("/api/v1/agent/onboarding-request", json=body).json()
    assert opened["token"] and opened["primary_mac"] == MAC
    enroll = {"token": opened["token"], "csr": request, "primary_mac": MAC}
    assert client.post("/api/v1/agent/enroll", json=enroll).status_code == 202  # waits for approval
    pending = admin.get(f"/api/v1/devices/{device_id}/enrollments").json()
    assert admin.get(f"/api/v1/admission/devices/{device_id}").json()["client"] == "ENROLLMENT_PENDING"
    admin.post(f"/api/v1/devices/{device_id}/enrollments/{pending[-1]['id']}/approve")
    issued = client.post("/api/v1/agent/enroll", json=enroll)
    assert issued.status_code == 200 and issued.json()["device_id"] == device_id
    # An enrolled computer cannot be re-enrolled through the portal; Case H needs an explicit reset first.
    assert client.post("/api/v1/agent/onboarding-request", json={**body, "csr": csr()}).json()["token"] is None
    reset = admin.post(f"/api/v1/devices/{device_id}/reset-enrollment", json={"reason": "Windows reinstalled"})
    assert reset.json()["revoked_credentials"] == 1
    assert client.post("/api/v1/agent/onboarding-request", json={**body, "csr": csr()}).json()["token"]
    with app.state.sessions() as db:
        assert db.scalar(select(AuditLog).where(AuditLog.action == "enrollment.unsolicited_request"))


def test_developer_exemption_is_central_and_audited(admin, app, router_env):
    device_id = enable_pilot(admin, router_env)
    changed = admin.put(f"/api/v1/devices/{device_id}/admission-exemption", json={"exempt": True, "reason": "developer laptop"})
    assert changed.json() == {"exempt": True, "device_class": "STANDARD"}
    row = admin.get(f"/api/v1/admission/devices/{device_id}").json()
    assert row["desired"] == "EXEMPT" and row["exemption_reason"] == "developer laptop"
    assert any(log["action"] == "admission.exemption_changed" for log in row["logs"])
    assert admin.put(f"/api/v1/devices/{device_id}/admission-exemption",
                     json={"exempt": True, "device_class": "DEVELOPER", "reason": "move class"}).json()["error"]["code"] == "device.reenrollment_required"


def test_onboarding_page_is_local_trilingual_and_serves_the_signed_installer(client, admin, app):
    page = client.get("/onboard")
    assert page.status_code == 200 and "Միացում ցանցին" in page.text and "Տեղադրման ֆայլը դեռ պատրաստ չէ" in page.text
    assert "Подключение к сети" in client.get("/onboard?lang=ru").text and "Install the Suro program" in client.get("/onboard?lang=en").text
    assert "script-src 'self'" in page.headers["content-security-policy"] and "<script>" not in page.text
    assert client.get("/onboard/installer").status_code == 404
    content = b"MSI" * 1000
    from app.security.crypto import digest
    sha = digest(content)
    objects = app.state.settings.data_dir / "repository" / "objects"
    objects.mkdir(parents=True, exist_ok=True)
    (objects / sha).write_bytes(content)
    with app.state.sessions.begin() as db:
        owner = db.scalar(select(AuditLog.actor_id)) or None
        from app.models import Administrator
        db.add(SoftwarePackage(name="Suro", filename="Suro.msi", sha256=sha, size=len(content), kind="agent_update",
                               publisher_thumbprint="AB" * 20, approved_by=db.scalar(select(Administrator.id))))
    download = client.get("/onboard/installer")
    assert download.status_code == 200 and download.content == content and "SuroSetup.msi" in download.headers["content-disposition"]
    assert sha in client.get("/onboard").text
    assert client.get("/onboard/status").json() == {"state": "UNKNOWN"}


def test_first_and_last_name_are_stored_separately(admin, app, enrolled):
    d, key, fingerprint, _ = enrolled
    report = {"windows_sid": "S-1-5-21-1-2-3-1001", "windows_account": "PC\\user", "first_name": "Արամ", "last_name": "Պետրոսյան",
              "military_rank": "Լեյտենանտ"}
    assert signed_request(admin, key, fingerprint, "POST", "/api/v1/agent/identity", report).status_code == 200
    user = admin.get(f"/api/v1/admission/devices/{d['id']}").json()["user"]
    assert (user["first_name"], user["last_name"], user["full_name"], user["military_rank"]) == ("Արամ", "Պետրոսյան", "Արամ Պետրոսյան", "Լեյտենանտ")
    only_first = {**report, "last_name": None}
    assert signed_request(admin, key, fingerprint, "POST", "/api/v1/agent/identity", only_first).status_code == 422
