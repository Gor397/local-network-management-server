import base64
import json
from datetime import timedelta
from uuid import uuid4
import pytest
from sqlalchemy import select, func
from app.db import utcnow
from app.models import (
    Router,
    Device,
    NetworkBatch,
    OperationTarget,
    RouterTelemetry,
    Incident,
    MaintenanceWindow,
    UserIdentity,
    Administrator,
    ClientObservation,
    ApGroupMember,
    BackgroundJob,
)
from app.services.infrastructure import process_batches
from app.services.recovery import plan_recovery
from app.services.diagnostics import correlate
from app.mikrotik.native import NativeRouterOS, encode_length
from test_foundation import create_device, create_policy
from test_agent_protocol import enrolled, signed_request
from test_mikrotik import fixture as router_fixture


@pytest.fixture
def infrastructure_factory(app):
    def create(name="AP-01", role="ACCESS_POINT", protected=False, reachable=True):
        snapshot = router_fixture()
        snapshot["interface/wifi"] = [
            {
                ".id": "*W",
                "name": "wifi1",
                "disabled": "false",
                "configuration.ssid": "Office",
            }
        ]
        snapshot["system/identity"] = [{".id": "*0", "name": name}]
        with app.state.sessions.begin() as db:
            r = Router(
                name=name,
                base_url=f"https://192.168.88.{20 + db.scalar(select(func.count()).select_from(Router))}",
                username="reader",
                secret=app.state.vault.seal("fixture-only"),
                snapshot=app.state.vault.seal(json.dumps(snapshot)),
                capabilities={"stacks": ["wifi"], "version": "7.20"},
                role=role,
                protected=protected,
                inventory={
                    "model": "fixture",
                    "serial_number": name,
                    "version": "7.20",
                    "architecture": "arm64",
                },
                write_enabled=True,
                status="ONLINE" if reachable else "UNAVAILABLE",
                last_seen=utcnow(),
                last_health=utcnow(),
                last_inventory=utcnow(),
                health={
                    "reachable": reachable,
                    "uptime_seconds": 3000,
                    "failure_count": 0 if reachable else 4,
                    "client_count": 5,
                },
            )
            db.add(r)
            db.flush()
            return r.id

    return create


def test_suro_metadata_and_password_login_default(client, app):
    assert client.get("/api/openapi.json").json()["info"]["title"].startswith("Suro")
    assert (
        not app.state.settings.mfa_required
        and not app.state.settings.mfa_login_required
    )
    with app.state.sessions.begin() as db:
        a = db.scalar(select(Administrator).where(Administrator.username == "owner"))
        a.totp_secret = app.state.vault.seal("JBSWY3DPEHPK3PXP")
    login = client.post(
        "/api/v1/auth/login",
        headers={"origin": "https://testserver"},
        json={"username": "owner", "password": "test-password-at-least-16"},
    )
    assert (
        login.status_code == 200
        and login.json()["mfa_available"]
        and not login.json()["mfa"]
    )
    client.headers.update(
        {"origin": "https://testserver", "x-csrf-token": login.json()["csrf"]}
    )
    assert (
        client.post(
            "/api/v1/policies", json={"name": "Password-only baseline"}
        ).status_code
        == 201
    )
    assert client.get("/api/v1/administrators").status_code == 200
    app.state.settings.mfa_login_required = True
    assert (
        client.post(
            "/api/v1/auth/login",
            json={"username": "owner", "password": "test-password-at-least-16"},
        ).status_code
        == 401
    )


def test_identity_is_reported_not_automatically_owner(admin, app, enrolled):
    d, key, fp, _ = enrolled
    payload = {
        "windows_sid": "S-1-5-21-100-200-300-1001",
        "windows_account": "PC\\user",
        "full_name": "Արամ Սարգսյան",
        "military_rank": "",
        "no_military_rank": True,
    }
    result = signed_request(admin, key, fp, "POST", "/api/v1/agent/identity", payload)
    assert result.status_code == 200 and result.json()["status"] == "USER_REPORTED"
    detail = admin.get("/api/v1/devices/" + d["id"]).json()
    assert detail["owner_name"] is None and detail["last_user_account"] == "PC\\user"
    users = admin.get("/api/v1/devices/" + d["id"] + "/identities").json()
    assert (
        users[0]["full_name"] == "Արամ Սարգսյան"
        and users[0]["military_rank"] is None
        and not users[0]["verified"]
    )
    owner = {
        "full_name": "Անի Հակոբյան",
        "military_rank": "Կապիտան",
        "windows_account": "PC\\owner",
        "verified": True,
        "reason": "Assignment checked by administrator",
    }
    assert (
        admin.put("/api/v1/devices/" + d["id"] + "/owner", json=owner).status_code
        == 200
    )
    payload["full_name"] = "Другой пользователь"
    assert (
        signed_request(
            admin, key, fp, "POST", "/api/v1/agent/identity", payload
        ).status_code
        == 200
    )
    assert (
        admin.get("/api/v1/devices/" + d["id"]).json()["owner_name"] == "Անի Հակոբյան"
    )
    assert (
        admin.get(
            "/api/v1/devices", params={"q": "Անի", "owner_rank": "Կապիտան"}
        ).json()["total"]
        == 1
    )
    assert len(admin.get("/api/v1/devices/" + d["id"] + "/owner-history").json()) == 1
    assert "Անի Հակոբյան" in admin.get("/api/v1/inventory/export").text


def test_csv_export_prevents_formula_execution(admin):
    d = create_device(admin)
    admin.put(
        "/api/v1/devices/" + d["id"] + "/owner",
        json={"full_name": "=1+1", "reason": "Review export injection safety"},
    )
    assert "'=1+1" in admin.get("/api/v1/inventory/export").text


def test_groups_crud_and_explicit_policy_conflicts(admin):
    d = create_device(admin)
    p, v = create_policy(admin)
    ga = admin.post(
        "/api/v1/groups", json={"name": "A", "device_ids": [d["id"]]}
    ).json()["id"]
    gb = admin.post(
        "/api/v1/groups", json={"name": "B", "device_ids": [d["id"]]}
    ).json()["id"]
    for group, value in [(ga, False), (gb, True)]:
        response = admin.post(
            f"/api/v1/policies/{p['id']}/layers",
            json={
                "scope": "GROUP",
                "target": group,
                "controls": {"require_d": value},
                "approved_relaxation": True,
                "reason": "Explicitly approved group test",
            },
        )
        assert response.status_code == 200, response.text
    assignment = admin.post(
        f"/api/v1/policies/{p['id']}/assign",
        json={"version_id": v["id"], "device_ids": [d["id"]]},
    )
    assert (
        assignment.status_code == 409
        and assignment.json()["error"]["code"] == "policy.group_conflict"
    )
    assert (
        admin.post(
            f"/api/v1/policies/{p['id']}/layers",
            json={
                "scope": "DEVICE",
                "target": d["id"],
                "controls": {"require_d": True},
                "reason": "Explicit device resolution",
            },
        ).status_code
        == 200
    )
    assert (
        admin.post(
            f"/api/v1/groups/{ga}/operations",
            json={
                "operation": "POLICY",
                "parameters": {"policy_id": p["id"], "version_id": v["id"]},
                "reason": "Reviewed group rollout",
            },
        ).status_code
        == 200
    )
    assert (
        admin.get("/api/v1/devices/" + d["id"] + "/effective-policy").json()[
            "conflicts"
        ]
        == []
    )
    assert (
        admin.put(
            "/api/v1/groups/" + ga, json={"name": "Renamed", "device_ids": [d["id"]]}
        ).status_code
        == 200
    )
    assert admin.delete("/api/v1/groups/" + ga).status_code == 200


def test_ap_group_multiple_membership_and_preservation(
    admin, app, infrastructure_factory
):
    a = infrastructure_factory()
    b = infrastructure_factory("AP-02")
    for name in ["First floor", "Technical"]:
        response = admin.post(
            "/api/v1/mikrotik/groups",
            json={
                "name": name,
                "router_ids": [a, b],
                "template": {"ssid": "Test", "interface": "wifi1", "stack": "wifi"},
            },
        )
        assert response.status_code == 200, response.text
    groups = admin.get("/api/v1/mikrotik/groups").json()
    assert len(groups) == 2 and groups[0]["online"] == 2
    assert admin.delete("/api/v1/mikrotik/groups/" + groups[0]["id"]).status_code == 200
    with app.state.sessions() as db:
        snapshot = json.loads(app.state.vault.open(db.get(Router, a).snapshot))
        assert (
            snapshot["interface/wifi/access-list"][0]["private-passphrase"]
            == "preserve-me"
        )
        assert (
            len(
                db.scalars(
                    select(ApGroupMember).where(ApGroupMember.router_id == a)
                ).all()
            )
            == 1
        )


def batch_preview(admin, ids, operation="reboot", parameters=None):
    parameters = {
        **(parameters or {}),
        "independent_management_router_ids": [
            r["id"] for r in admin.get("/api/v1/mikrotik/routers").json()
        ],
    }
    response = admin.post(
        "/api/v1/network/operations/preview",
        json={
            "router_ids": ids,
            "operation": operation,
            "parameters": parameters,
            "reason": "Controlled lab-only operation",
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_protected_infrastructure_requires_typed_confirmation(
    admin, infrastructure_factory
):
    router_id = infrastructure_factory(role="GATEWAY", protected=True)
    preview = batch_preview(admin, [router_id])
    path = "/api/v1/network/operations/" + preview["id"] + "/approve"
    assert admin.post(path, json={"confirm": True}).status_code == 409
    assert (
        admin.post(
            path,
            json={
                "confirm": True,
                "confirmed_protected": ["AP-01"],
                "out_of_band_confirmed": True,
            },
        ).status_code
        == 200
    )


async def test_reboot_batches_wait_for_verified_return_and_stop_on_failure(
    admin, app, infrastructure_factory, monkeypatch
):
    import app.services.infrastructure as infra

    a = infrastructure_factory()
    b = infrastructure_factory("AP-02")
    app.state.settings.router_writes_enabled = True
    issued = []
    uptimes = {a: "3000s", b: "3000s"}
    unreachable = set()

    class Api:
        def __init__(self, r):
            self.r = r

        async def __aenter__(self):
            if self.r.id in unreachable:
                raise ConnectionError("fixture unavailable")
            return self

        async def __aexit__(self, *args):
            pass

        async def read(self, path):
            return [{"uptime": uptimes[self.r.id], "version": "7.20"}]

        async def command(self, path, data=None):
            issued.append((self.r.id, path))

    monkeypatch.setattr(infra, "connector", lambda app, r: Api(r))
    preview = batch_preview(admin, [a, b])
    assert preview["batch_size"] == 1
    assert (
        admin.post(
            "/api/v1/network/operations/" + preview["id"] + "/approve",
            json={"confirm": True},
        ).status_code
        == 200
    )
    await process_batches(app)
    assert len(issued) == 1
    with app.state.sessions() as db:
        targets = db.scalars(
            select(OperationTarget).where(OperationTarget.batch_id == preview["id"])
        ).all()
        first = next(t for t in targets if t.state == "WAITING_RECONNECT").router_id
    unreachable.add(first)
    await process_batches(app)
    assert len(issued) == 1
    with app.state.sessions.begin() as db:
        waiting = db.scalar(
            select(OperationTarget).where(
                OperationTarget.router_id == first,
                OperationTarget.state == "WAITING_RECONNECT",
            )
        )
        waiting.deadline = utcnow() - timedelta(seconds=1)
    await process_batches(app)
    result = admin.get("/api/v1/network/operations/" + preview["id"]).json()
    assert result["state"] == "STOPPED" and len(issued) == 1
    assert any(t["state"] == "FAILED" for t in result["targets"])


async def test_unreachable_ap_is_never_reported_rebooted(
    admin, app, infrastructure_factory, monkeypatch
):
    import app.services.infrastructure as infra

    a = infrastructure_factory()
    infrastructure_factory("AP-02")
    app.state.settings.router_writes_enabled = True

    class Failure:
        async def __aenter__(self):
            raise ConnectionError("unreachable")

        async def __aexit__(self, *args):
            pass

    monkeypatch.setattr(infra, "connector", lambda *args: Failure())
    preview = batch_preview(admin, [a])
    admin.post(
        "/api/v1/network/operations/" + preview["id"] + "/approve",
        json={"confirm": True},
    )
    await process_batches(app)
    result = admin.get("/api/v1/network/operations/" + preview["id"]).json()
    assert result["targets"][0]["state"] == "FAILED"
    assert "verified_uptime" not in result["targets"][0]["result"]


def test_auto_recovery_rejects_ping_only_upstream_protected_and_loops(
    app, infrastructure_factory
):
    a = infrastructure_factory()
    other = infrastructure_factory("AP-02")
    gateway = infrastructure_factory("Gateway", "GATEWAY", True)
    app.state.settings.recovery_enabled = True
    app.state.settings.router_writes_enabled = True
    now = utcnow()
    with app.state.sessions.begin() as db:
        r = db.get(Router, a)
        r.recovery_policy = {
            "enabled": True,
            "sustained_seconds": 180,
            "cooldown_seconds": 900,
            "max_attempts_per_day": 2,
            "independent_management_router_ids": [other],
        }
        db.add(
            MaintenanceWindow(
                name="Lab",
                starts_at=now - timedelta(hours=1),
                ends_at=now + timedelta(hours=1),
                router_ids=[a],
                device_ids=[],
                author_id=db.scalar(select(Administrator.id).limit(1)),
            )
        )
        assert plan_recovery(app, db, now) == []  # no corroborating samples
        for seconds in [240, 120, 0]:
            db.add(
                RouterTelemetry(
                    router_id=a,
                    created_at=now - timedelta(seconds=seconds),
                    metrics={
                        "reachable": True,
                        "cpu_percent": 99,
                        "memory_percent": 98,
                    },
                    clients=[],
                )
            )
        db.flush()
        db.get(Router, gateway).health = {"reachable": False}
        assert plan_recovery(app, db, now) == []
        db.get(Router, gateway).health = {"reachable": True}
        r.protected = True
        assert plan_recovery(app, db, now) == []
        r.protected = False
        created = plan_recovery(app, db, now)
        assert len(created) == 1
        assert plan_recovery(app, db, now) == []  # no parallel or repeated attempt
        db.flush()
        batch = db.get(NetworkBatch, created[0])
        batch.state = "STOPPED"
        batch.created_at = now - timedelta(hours=2)
        second = NetworkBatch(
            automatic=True,
            operation="reboot",
            state="STOPPED",
            reason="prior failed attempt",
            created_at=now - timedelta(hours=3),
        )
        db.add(second)
        db.flush()
        db.add(OperationTarget(batch_id=second.id, router_id=a, state="FAILED"))
        db.flush()
        assert plan_recovery(app, db, now) == [] and not r.recovery_policy["enabled"]


def test_network_correlation_creates_one_primary_incident(app, infrastructure_factory):
    a = infrastructure_factory("Gateway", "GATEWAY", True, False)
    b = infrastructure_factory("AP-02", reachable=False)
    with app.state.sessions.begin() as db:
        for n in range(10):
            db.add(
                Device(
                    hostname=f"PC-{n}",
                    primary_mac=f"00:11:22:33:44:{n:02X}",
                    network_evidence={"router_id": b},
                    last_heartbeat=utcnow() - timedelta(hours=1),
                )
            )
        db.flush()
        correlate(db)
        correlate(db)
        rows = db.scalars(select(Incident)).all()
        assert (
            len(rows) == 1
            and rows[0].title_key == "incident.upstream"
            and len(rows[0].device_ids) == 10
        )
        assert (
            rows[0].confidence in ("MEDIUM", "HIGH")
            and rows[0].facts[0]["source"] == "router"
        )


def test_client_diagnostics_deduplicate_and_are_not_compliance(admin, app, enrolled):
    d, key, fp, _ = enrolled
    sample = {
        "sequence": "test-sequence-123456",
        "observed_at": utcnow().isoformat(),
        "ssid": "Գրասենյակ",
        "signal_quality": 20,
        "events": [{"event_id": 8002, "password": "never store"}],
    }
    for _ in range(2):
        assert (
            signed_request(
                admin,
                key,
                fp,
                "POST",
                "/api/v1/agent/diagnostics",
                {"observations": [sample]},
            ).status_code
            == 200
        )
    with app.state.sessions() as db:
        rows = db.scalars(select(ClientObservation)).all()
        assert len(rows) == 1 and "password" not in str(rows[0].data)
    assert admin.get("/api/v1/devices/" + d["id"] + "/compliance").json()["score"] < 100


def test_topology_and_monitoring_budget(admin, infrastructure_factory):
    a = infrastructure_factory()
    topology = admin.get("/api/v1/network/topology").json()
    assert topology["unknown_links"] == ["physical_uplinks", "unobserved_vlan_paths"]
    assert all(
        e["assurance"] in ("OBSERVED", "UNKNOWN", "ADMIN_CONFIGURED")
        for e in topology["edges"]
    )
    values = {
        "low_resource_mode": True,
        "network_health_seconds": 60,
        "network_inventory_seconds": 1200,
        "network_poll_concurrency": 1,
        "telemetry_retention_days": 3,
        "recovery_enabled": False,
        "reason": "Small server resource budget",
    }
    assert (
        admin.put("/api/v1/system/monitoring-settings", json=values).status_code == 200
    )
    assert (
        admin.get("/api/v1/system/monitoring-settings").json()[
            "network_poll_concurrency"
        ]
        == 1
    )
    values["network_poll_concurrency"] = 1000
    assert (
        admin.put("/api/v1/system/monitoring-settings", json=values).status_code == 422
    )


@pytest.mark.parametrize("length", [0, 1, 127, 128, 16383, 16384, 2097151, 2097152])
async def test_native_api_word_length_contract(length):
    import asyncio

    adapter = NativeRouterOS("https://192.168.88.1:8729", "fixture", "fixture")
    adapter.reader = asyncio.StreamReader()
    adapter.reader.feed_data(encode_length(length) + b"a" * length)
    adapter.reader.feed_eof()
    assert len(await adapter.word()) == length


async def test_reboot_requires_observed_uptime_reset(
    admin, app, infrastructure_factory, monkeypatch
):
    import app.services.infrastructure as infra

    a = infrastructure_factory()
    infrastructure_factory("Alternate AP")
    app.state.settings.router_writes_enabled = True
    uptime = ["3600s"]

    class Api:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def read(self, path):
            return [{"uptime": uptime[0], "version": "7.20"}]

        async def command(self, path, data=None):
            pass

    monkeypatch.setattr(infra, "connector", lambda *args: Api())
    preview = batch_preview(admin, [a])
    admin.post(
        "/api/v1/network/operations/" + preview["id"] + "/approve",
        json={"confirm": True},
    )
    await process_batches(app)
    await process_batches(app)
    assert (
        admin.get("/api/v1/network/operations/" + preview["id"]).json()["targets"][0][
            "state"
        ]
        == "WAITING_RECONNECT"
    )
    uptime[0] = "1s"
    await process_batches(app)
    target = admin.get("/api/v1/network/operations/" + preview["id"]).json()["targets"][
        0
    ]
    assert target["state"] == "SUCCEEDED" and target["result"]["verified_uptime"] == 1


def test_client_and_ap_signals_correlate_without_overstating_cause(
    app, infrastructure_factory
):
    a = infrastructure_factory()
    infrastructure_factory("Healthy neighbor")
    now = utcnow()
    with app.state.sessions.begin() as db:
        for n in range(4):
            d = Device(
                hostname=f"Affected-{n}",
                primary_mac=f"00:11:22:77:44:{n:02X}",
                network_evidence={"router_id": a},
            )
            db.add(d)
            db.flush()
            db.add(
                ClientObservation(
                    device_id=d.id,
                    sequence=f"correlation-test-{n}",
                    observed_at=now,
                    data={
                        "management_reachable": False,
                        "events": [{"event_id": 8003}],
                    },
                )
            )
        for seconds, count in [(120, 4), (0, 0)]:
            db.add(
                RouterTelemetry(
                    router_id=a,
                    created_at=now - timedelta(seconds=seconds),
                    metrics={"reachable": True},
                    clients=[
                        {"mac-address": f"00:11:22:77:44:{n:02X}"} for n in range(count)
                    ],
                )
            )
        db.flush()
        correlate(db, now)
        result = db.scalar(
            select(Incident).where(Incident.title_key == "incident.ap_instability")
        )
        assert result.confidence == "HIGH" and len(result.device_ids) == 4
        assert {"router", "agent"} <= {fact["source"] for fact in result.facts}
        assert (
            result.cause_key == "cause.ap_instability"
        )  # Probable cause is distinct from facts.


def test_missing_router_sensors_are_unavailable():
    from app.services.telemetry import metrics

    result = metrics({"cpu-load": "2", "uptime": "2d3h4m5s"})
    assert (
        result["cpu_percent"] == 2
        and result["temperature"] is None
        and result["voltage"] is None
    )
    assert result["memory_percent"] is None and result["uptime_seconds"] == 183845


def test_new_management_routes_require_human_authentication(client):
    for path in [
        "/groups",
        "/mikrotik/groups",
        "/network/clients",
        "/network/topology",
        "/incidents",
        "/inventory/export",
        "/system/monitoring-settings",
    ]:
        assert client.get("/api/v1" + path).status_code == 401
    assert (
        client.post(
            "/api/v1/agent/identity",
            json={
                "windows_sid": "S-1-5-21-1",
                "windows_account": "PC\\user",
                "full_name": "Example",
            },
        ).status_code
        == 401
    )


def test_group_offline_deployment_reuses_repository(admin, app, enrolled):
    from test_deployments import upload_package
    from app.models import SoftwarePackage, DeploymentTask

    d, *_ = enrolled
    app.state.settings.deployment_enabled = True
    group = admin.post(
        "/api/v1/groups", json={"name": "Offline lab group", "device_ids": [d["id"]]}
    ).json()["id"]
    package = upload_package(admin).json()["package_id"]
    admin.post(
        "/api/v1/packages/" + package + "/approve",
        json={"reason": "Reviewed isolated package"},
    )
    for _ in range(2):
        rollout = admin.post(
            "/api/v1/deployments",
            json={
                "package_id": package,
                "group_ids": [group],
                "reason": "Controlled group offline rollout",
            },
        )
        assert rollout.status_code == 201, rollout.text
    with app.state.sessions() as db:
        assert db.scalar(select(func.count()).select_from(SoftwarePackage)) == 1
        assert db.scalar(select(func.count()).select_from(DeploymentTask)) == 2


async def test_wireless_change_preserves_manual_fields_and_saves_backup(
    admin, app, infrastructure_factory, monkeypatch
):
    import app.services.infrastructure as infra
    from app.models import ConfigurationBackup

    a = infrastructure_factory()
    infrastructure_factory("Alternate AP")
    app.state.settings.router_writes_enabled = True
    row = {
        ".id": "*W",
        "name": "wifi1",
        "disabled": "false",
        "configuration.ssid": "Office",
        "comment": "manually maintained",
    }

    class Api:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def read(self, path):
            return [dict(row)] if path == "interface/wifi" else [{"uptime": "3000s"}]

        async def configure(self, path, record_id, values):
            row.update(values)

    monkeypatch.setattr(infra, "connector", lambda *args: Api())
    # Add the same manually maintained field to the discovery baseline.
    with app.state.sessions.begin() as db:
        r = db.get(Router, a)
        snapshot = json.loads(app.state.vault.open(r.snapshot))
        snapshot["interface/wifi"] = [dict(row)]
        r.snapshot = app.state.vault.seal(json.dumps(snapshot))
    bad = batch_preview(
        admin,
        [a],
        "wireless",
        {"stack": "wifi", "interface": "wifi1", "ssid": "x" * 33},
    )
    assert not bad["targets"][0]["preview"]["compatible"]
    preview = batch_preview(
        admin,
        [a],
        "wireless",
        {"stack": "wifi", "interface": "wifi1", "ssid": "Հայերեն"},
    )
    admin.post(
        "/api/v1/network/operations/" + preview["id"] + "/approve",
        json={"confirm": True},
    )
    await process_batches(app)
    assert (
        row["comment"] == "manually maintained"
        and row["configuration.ssid"] == "Հայերեն"
    )
    assert (
        admin.get("/api/v1/network/operations/" + preview["id"]).json()["targets"][0][
            "state"
        ]
        == "SUCCEEDED"
    )
    with app.state.sessions() as db:
        assert db.scalar(
            select(ConfigurationBackup).where(ConfigurationBackup.router_id == a)
        ).encrypted_content


async def test_native_optional_menu_does_not_hide_authorization_errors(monkeypatch):
    native = NativeRouterOS("https://192.168.88.1:8729", "fixture", "fixture")

    async def missing(words):
        raise ValueError("no such command prefix")

    monkeypatch.setattr(native, "sentence", missing)
    assert await native.read("interface/wifi", optional=True) is None

    async def denied(words):
        raise ValueError("not enough permissions")

    monkeypatch.setattr(native, "sentence", denied)
    with pytest.raises(ValueError, match="not enough permissions"):
        await native.read("interface/wifi", optional=True)


def test_arbitrary_online_router_is_not_an_independent_management_path(
    admin, infrastructure_factory
):
    a = infrastructure_factory()
    infrastructure_factory("Unknown physical path")
    preview = admin.post(
        "/api/v1/network/operations/preview",
        json={
            "router_ids": [a],
            "operation": "reboot",
            "parameters": {},
            "reason": "Review unknown management paths",
        },
    ).json()
    result = admin.post(
        "/api/v1/network/operations/" + preview["id"] + "/approve",
        json={"confirm": True},
    )
    assert (
        result.status_code == 409
        and result.json()["error"]["code"] == "network.last_management_path"
    )


def test_viewer_cannot_assign_owners_or_manage_network(client):
    login = client.post(
        "/api/v1/auth/login",
        headers={"origin": "https://testserver"},
        json={"username": "viewer", "password": "test-password-at-least-16"},
    )
    client.headers.update(
        {"origin": "https://testserver", "x-csrf-token": login.json()["csrf"]}
    )
    for path, body in [
        ("/groups", {"name": "Denied"}),
        ("/mikrotik/groups", {"name": "Denied"}),
        (
            "/network/operations/preview",
            {"operation": "reboot", "reason": "Must be denied"},
        ),
    ]:
        assert client.post("/api/v1" + path, json=body).status_code == 403


def test_router_metadata_edit_preserves_existing_public_host_key(
    admin, app, infrastructure_factory
):
    a = infrastructure_factory()
    with app.state.sessions.begin() as db:
        db.get(Router, a).ssh_host_key = "existing-pinned-public-key"
    assert (
        admin.patch(
            "/api/v1/mikrotik/routers/" + a,
            json={"name": "Renamed AP", "role": "ACCESS_POINT", "protected": False},
        ).status_code
        == 200
    )
    with app.state.sessions() as db:
        assert db.get(Router, a).ssh_host_key == "existing-pinned-public-key"


@pytest.mark.parametrize("corrupt", [False, True])
async def test_approved_router_package_hash_and_post_reboot_version(
    admin, app, infrastructure_factory, monkeypatch, corrupt
):
    import hashlib
    import app.services.infrastructure as infra
    from app.models import SoftwarePackage

    a = infrastructure_factory()
    infrastructure_factory("Independent path")
    app.state.settings.router_writes_enabled = True
    content = b"simulated vendor package bytes"
    sha = hashlib.sha256(content).hexdigest()
    path = app.state.settings.data_dir / "repository/objects" / sha
    path.parent.mkdir(parents=True)
    path.write_bytes(b"corrupted" if corrupt else content)
    with app.state.sessions.begin() as db:
        db.get(Router, a).ssh_host_key = "fixture-pinned-key"
        package = SoftwarePackage(
            name="RouterOS lab",
            filename="routeros.npk",
            kind="routeros",
            sha256=sha,
            size=len(content),
            publisher_thumbprint="",
            metadata_={"architecture": "arm64", "release_version": "7.21"},
            approved_by=db.scalar(
                select(Administrator.id).where(Administrator.username == "owner")
            ),
        )
        db.add(package)
        db.flush()
        package_id = package.id
    actions = []
    returned = {"uptime": "3000s", "version": "7.20"}

    class Api:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def read(self, path):
            return [returned.copy()]

        async def command(self, path, data=None):
            actions.append(path)

    class Transfer:
        async def put(self, source, target):
            assert source == str(path) and target.endswith(".npk")
            actions.append("SFTP")

    async def backup(*args):
        actions.append("BACKUP")

    async def sftp(app, r, callback):
        return await callback(Transfer())

    monkeypatch.setattr(infra, "connector", lambda *args: Api())
    monkeypatch.setattr(infra, "binary_backup", backup)
    monkeypatch.setattr(infra, "sftp", sftp)
    preview = batch_preview(admin, [a], "upgrade", {"package_id": package_id})
    assert preview["targets"][0]["preview"]["compatible"]
    assert (
        admin.post(
            "/api/v1/network/operations/" + preview["id"] + "/approve",
            json={"confirm": True},
        ).status_code
        == 200
    )
    await process_batches(app)
    target = admin.get("/api/v1/network/operations/" + preview["id"]).json()["targets"][
        0
    ]
    if corrupt:
        assert (
            target["state"] == "FAILED"
            and "system/reboot" not in actions
            and "SFTP" not in actions
        )
    else:
        assert target["state"] == "WAITING_RECONNECT" and actions == [
            "BACKUP",
            "SFTP",
            "system/reboot",
        ]
        returned.update({"uptime": "1s", "version": "7.20"})
        await process_batches(app)
        assert (
            admin.get("/api/v1/network/operations/" + preview["id"]).json()["targets"][
                0
            ]["state"]
            == "WAITING_RECONNECT"
        )
        returned["version"] = "7.21"
        await process_batches(app)
        assert (
            admin.get("/api/v1/network/operations/" + preview["id"]).json()["targets"][
                0
            ]["state"]
            == "SUCCEEDED"
        )


async def test_router_sftp_checks_pinned_host_key_over_loopback(
    app, tmp_path, monkeypatch
):
    import asyncssh
    from types import SimpleNamespace
    import app.services.infrastructure as infra

    key = asyncssh.generate_private_key("ssh-ed25519")

    class Server(asyncssh.SSHServer):
        def begin_auth(self, username):
            return True

        def password_auth_supported(self):
            return True

        def validate_password(self, username, password):
            return username == "lab" and password == "test-only"

    server = await asyncssh.listen(
        "127.0.0.1",
        0,
        server_factory=Server,
        server_host_keys=[key],
        sftp_factory=lambda channel: asyncssh.SFTPServer(channel, chroot=str(tmp_path)),
    )
    original_connect = asyncssh.connect

    def connect(host, **kwargs):
        return original_connect(host, port=server.get_port(), **kwargs)

    monkeypatch.setattr(infra.asyncssh, "connect", connect)
    router = SimpleNamespace(
        id="lab",
        name="lab",
        archived=False,
        write_enabled=True,
        base_url="https://127.0.0.1",
        username="lab",
        secret=app.state.vault.seal("test-only"),
        ssh_host_key=key.export_public_key().decode(),
    )
    # Every SFTP use writes a router file, so the safety mode must permit writes.
    app.state.settings.operation_mode = "production"
    (tmp_path / "proof.txt").write_bytes(b"loopback file")

    async def read(client):
        async with client.open("proof.txt", "rb") as source:
            return await source.read()

    try:
        assert await infra.sftp(app, router, read) == b"loopback file"
        router.ssh_host_key = (
            asyncssh.generate_private_key("ssh-ed25519").export_public_key().decode()
        )
        with pytest.raises(asyncssh.HostKeyNotVerifiable):
            await infra.sftp(app, router, read)
    finally:
        server.close()
        await server.wait_closed()
