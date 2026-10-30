"""Operation modes must be enforced at execution and transport level, not only shown in the dashboard."""
import json
from types import SimpleNamespace
import pytest
from app.config import Settings
from app.models import Router, NetworkPlan
from app.services.safety import GuardedRouter, operation_mode, router_write_block, endpoint_change_block, agent_mode
from test_suro import infrastructure_factory  # noqa: F401  (fixture)


def settings(**values):
    return Settings(encryption_key="unused", **values)


class Recorder:
    def __init__(self):
        self.calls = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass

    async def read(self, path, **kwargs):
        self.calls.append(("read", path))
        return [{}]

    async def discovery(self):
        self.calls.append(("discovery",))
        return {"snapshot": {}, "capabilities": {}}

    async def command(self, path, data=None):
        self.calls.append(("command", path))
        return {}

    async def configure(self, path, record_id, data):
        self.calls.append(("configure", path))

    async def apply(self, operation):
        self.calls.append(("apply", operation["path"]))


ROUTER = SimpleNamespace(id="r-1", name="AP-Lab", base_url="https://192.168.88.2", archived=False, write_enabled=True)


def test_legacy_flag_maps_to_mode_and_explicit_mode_wins():
    assert operation_mode(settings()) == "read_only"
    assert operation_mode(settings(router_writes_enabled=True)) == "production"
    assert operation_mode(settings(router_writes_enabled=True, operation_mode="dry_run")) == "dry_run"


@pytest.mark.parametrize("mode", ["read_only", "dry_run"])
async def test_transport_refuses_every_write_but_allows_observation(mode):
    inner = Recorder()
    async with GuardedRouter(inner, settings(operation_mode=mode, router_writes_enabled=True), ROUTER) as api:
        await api.read("system/resource")
        await api.discovery()
        await api.command("ping", {"address": "192.168.88.1"})
        for call in (api.apply({"path": "ip/dhcp-server/lease", "method": "PUT"}),
                     api.configure("interface/wifi", "*1", {}), api.command("system/reboot"),
                     api.command("system/backup/load")):
            with pytest.raises(ValueError, match="safety." + mode):
                await call
    assert [c[0] for c in inner.calls] == ["read", "discovery", "command"]


def test_controlled_test_only_writes_to_listed_routers():
    lab = settings(operation_mode="controlled_test", test_routers="AP-Lab")
    assert router_write_block(lab, ROUTER) is None
    other = SimpleNamespace(**{**ROUTER.__dict__, "id": "r-2", "name": "Gateway", "base_url": "https://192.168.88.1"})
    assert router_write_block(lab, other) == "safety.not_test_router"
    by_address = settings(operation_mode="controlled_test", test_routers="192.168.88.1")
    assert router_write_block(by_address, other) is None
    # The per-router switch still applies inside the test scope.
    assert router_write_block(lab, SimpleNamespace(**{**ROUTER.__dict__, "write_enabled": False})) == "network.writes_disabled"


def test_endpoint_scope_and_signed_agent_mode():
    device = SimpleNamespace(id="d-1", hostname="PILOT-01", mode="CONTINUOUS")
    assert endpoint_change_block(settings(), device) is None  # unset mode keeps legacy endpoint behavior
    assert endpoint_change_block(settings(operation_mode="read_only"), device) == "safety.read_only"
    assert agent_mode(settings(operation_mode="dry_run"), device) == "AUDIT"
    test = settings(operation_mode="controlled_test", test_devices="pilot-01")
    assert endpoint_change_block(test, device) is None and agent_mode(test, device) == "CONTINUOUS"
    other = SimpleNamespace(id="d-2", hostname="OFFICE-07", mode="APPROVED_REMEDIATION")
    assert agent_mode(test, other) == "AUDIT"


async def test_dry_run_plan_execution_sends_nothing_and_keeps_preview(app, infrastructure_factory, monkeypatch):
    import app.services.network as service
    identifier = infrastructure_factory()
    inner = Recorder()
    monkeypatch.setattr(service, "connector", lambda *args: inner)
    app.state.settings.operation_mode = "dry_run"
    operation = {"method": "PUT", "path": "ip/dhcp-server/lease", "data": {"mac-address": "00:11:22:33:44:55"}}
    with app.state.sessions() as db:
        router = db.get(Router, identifier)
        plan = NetworkPlan(router_id=identifier, generation=router.generation, snapshot_hash="x", operations=[operation], reason="test")
        db.add(plan)
        db.commit()
        outcome = await service.execute_plan(app, db, plan, "test-admin")
        assert outcome["state"] == "DRY_RUN" and outcome["operations"] == [operation]
        db.refresh(plan)
        assert plan.state == "PREVIEW" and inner.calls == []


def test_batch_approval_refused_in_read_only(admin, app, infrastructure_factory):
    identifier = infrastructure_factory()
    app.state.settings.operation_mode = "read_only"
    preview = admin.post("/api/v1/network/operations/preview", json={
        "router_ids": [identifier], "operation": "reboot", "parameters": {}, "reason": "Read-only refusal test"}).json()
    result = admin.post(f"/api/v1/network/operations/{preview['id']}/approve", json={"confirm": True, "out_of_band_confirmed": True})
    assert result.status_code == 409 and result.json()["error"]["code"] == "safety.read_only"


def test_recovery_never_plans_outside_writing_modes(app):
    from app.services.recovery import plan_recovery
    app.state.settings.recovery_enabled = True
    app.state.settings.router_writes_enabled = True
    app.state.settings.operation_mode = "dry_run"
    with app.state.sessions() as db:
        assert plan_recovery(app, db) == []


def test_dashboard_reports_effective_mode(admin, app):
    app.state.settings.operation_mode = "controlled_test"
    body = admin.get("/api/v1/dashboard").json()
    assert body["operation_mode"] == "controlled_test" and body["operation_mode_configured"]
    assert json.dumps(body["features"])  # serializable feature summary remains


def test_safety_endpoint_is_small_and_counts_test_scope(admin, app):
    app.state.settings.operation_mode = "controlled_test"
    app.state.settings.test_routers = "AP-Lab, 192.168.88.2"
    assert admin.get("/api/v1/safety").json() == {"mode": "controlled_test", "configured": True, "test_routers": 2, "test_devices": 0}
