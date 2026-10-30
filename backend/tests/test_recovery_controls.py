"""Safety and readback contracts for optional AP recovery, using isolated fixtures."""

import json
from datetime import timedelta
import pytest
from sqlalchemy import select
from app.db import utcnow
from app.models import (
    Router,
    RouterTelemetry,
    MaintenanceWindow,
    Administrator,
    NetworkBatch,
    OperationTarget,
)
from app.services.recovery import plan_recovery
from app.services.infrastructure import process_batches
from test_suro import infrastructure_factory


def seed_recovery(
    app, router_id, alternate, *, radio=True, desired=True, pressure=True
):
    now = utcnow()
    app.state.settings.recovery_enabled = True
    app.state.settings.router_writes_enabled = True
    with app.state.sessions.begin() as db:
        r = db.get(Router, router_id)
        r.recovery_policy = {
            "enabled": True,
            "conditions": ["resource_pressure", "unexpected_radio_disabled"]
            if radio
            else ["resource_pressure"],
            "sustained_seconds": 180,
            "cooldown_seconds": 900,
            "max_attempts_per_day": 2,
            "independent_management_router_ids": [alternate],
        }
        r.desired_config = (
            {"wifi1": {"stack": "wifi", "interface": "wifi1", "disabled": False}}
            if desired
            else {}
        )
        snapshot = json.loads(app.state.vault.open(r.snapshot))
        snapshot["interface/wifi"][0]["disabled"] = "true"
        r.snapshot = app.state.vault.seal(json.dumps(snapshot))
        for age in (240, 120, 0):
            db.add(
                RouterTelemetry(
                    router_id=r.id,
                    created_at=now - timedelta(seconds=age),
                    metrics={
                        "reachable": True,
                        "cpu_percent": 99 if pressure else 2,
                        "interfaces": [{"name": "wifi1", "disabled": "true"}],
                    },
                    clients=[],
                )
            )
        db.add(
            MaintenanceWindow(
                name="Controlled fixture window",
                starts_at=now - timedelta(minutes=5),
                ends_at=now + timedelta(minutes=30),
                router_ids=[router_id],
                device_ids=[],
                author_id=db.scalar(select(Administrator.id).limit(1)),
            )
        )
    return now


async def test_radio_recovery_precedes_reboot_and_verifies_narrow_change(
    app, infrastructure_factory, monkeypatch
):
    import app.services.infrastructure as infra

    a = infrastructure_factory()
    other = infrastructure_factory("Independent path")
    now = seed_recovery(app, a, other)
    with app.state.sessions.begin() as db:
        created = plan_recovery(app, db, now)
        assert len(created) == 1
        batch = db.get(NetworkBatch, created[0])
        assert batch.operation == "wireless"
        target = db.scalar(
            select(OperationTarget).where(OperationTarget.batch_id == batch.id)
        )
        assert target.preview["changes"][0]["after"] == {"disabled": "false"}
    row = {
        ".id": "*W",
        "name": "wifi1",
        "disabled": "true",
        "configuration.ssid": "Office",
    }
    commands = []

    class Api:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def read(self, path):
            return [dict(row)] if path == "interface/wifi" else [{"uptime": "3000s"}]

        async def configure(self, path, record_id, values):
            commands.append(values)
            row.update(values)

        async def command(self, *args):
            raise AssertionError("The complete AP must not reboot")

    monkeypatch.setattr(infra, "connector", lambda *args: Api())
    await process_batches(app)
    with app.state.sessions() as db:
        assert (
            db.scalar(
                select(OperationTarget).where(OperationTarget.batch_id == created[0])
            ).state
            == "SUCCEEDED"
        )
    assert commands == [{"disabled": "false"}] and row["configuration.ssid"] == "Office"


@pytest.mark.parametrize("desired,enabled", [(False, True), (True, False)])
def test_unapproved_radio_and_opt_out_are_never_automatically_changed(
    app, infrastructure_factory, desired, enabled
):
    a = infrastructure_factory()
    other = infrastructure_factory("Independent path")
    now = seed_recovery(app, a, other, radio=enabled, desired=desired, pressure=False)
    with app.state.sessions.begin() as db:
        assert plan_recovery(app, db, now) == []


@pytest.mark.parametrize(
    "revocation", ["global", "device", "condition", "maintenance", "upstream"]
)
async def test_queued_recovery_rechecks_authorization_before_issuing_commands(
    app, infrastructure_factory, monkeypatch, revocation
):
    import app.services.infrastructure as infra

    a = infrastructure_factory()
    other = infrastructure_factory("Independent path")
    gateway = infrastructure_factory(
        "Management gateway", role="GATEWAY", protected=True
    )
    now = seed_recovery(app, a, other)
    with app.state.sessions.begin() as db:
        created = plan_recovery(app, db, now)
        assert len(created) == 1
        if revocation == "device":
            db.get(Router, a).recovery_policy = {
                **db.get(Router, a).recovery_policy,
                "enabled": False,
            }
        if revocation == "condition":
            db.get(Router, a).recovery_policy = {
                **db.get(Router, a).recovery_policy,
                "conditions": ["resource_pressure"],
            }
        if revocation == "maintenance":
            for window in db.scalars(select(MaintenanceWindow)):
                window.ends_at = utcnow() - timedelta(seconds=1)
        if revocation == "upstream":
            db.get(Router, gateway).health = {"reachable": False}
    if revocation == "global":
        app.state.settings.recovery_enabled = False

    def forbidden(*args):
        raise AssertionError(
            "Revoked automatic work must never open a router connection"
        )

    monkeypatch.setattr(infra, "connector", forbidden)
    await process_batches(app)
    with app.state.sessions() as db:
        target = db.scalar(
            select(OperationTarget).where(OperationTarget.batch_id == created[0])
        )
        assert target.state == "FAILED" and target.result["code"].startswith(
            "recovery."
        )


@pytest.mark.parametrize("source", ["shared", "gateway"])
def test_shared_or_gateway_resource_pressure_suppresses_ap_reboots(
    app, infrastructure_factory, source
):
    a = infrastructure_factory()
    other = infrastructure_factory("Neighbor AP")
    now = seed_recovery(app, a, other, radio=False)
    blocker = (
        other
        if source == "shared"
        else infrastructure_factory("Gateway", role="GATEWAY", protected=True)
    )
    with app.state.sessions.begin() as db:
        db.get(Router, a).health = {"reachable": True, "cpu_percent": 99}
        db.get(Router, blocker).health = {"reachable": True, "cpu_percent": 99}
        assert plan_recovery(app, db, now) == []
        db.get(Router, blocker).health = {"reachable": True, "cpu_percent": 2}
        assert len(plan_recovery(app, db, now)) == 1


def test_recovery_policy_keeps_conditions_visible_and_rejects_unknown_actions(
    admin, infrastructure_factory
):
    a = infrastructure_factory()
    other = infrastructure_factory("Independent path")
    values = {
        "enabled": True,
        "conditions": ["unexpected_radio_disabled"],
        "independent_management_router_ids": [other],
    }
    assert (
        admin.put(
            f"/api/v1/mikrotik/routers/{a}/recovery-policy", json=values
        ).status_code
        == 200
    )
    inventory = admin.get("/api/v1/mikrotik/routers").json()
    assert next(r for r in inventory if r["id"] == a)["recovery_policy"][
        "conditions"
    ] == ["unexpected_radio_disabled"]
    values["conditions"] = ["run_shell"]
    assert (
        admin.put(
            f"/api/v1/mikrotik/routers/{a}/recovery-policy", json=values
        ).status_code
        == 422
    )


def test_network_operator_cannot_remove_protection_or_replace_pinned_host_key(
    admin, app, infrastructure_factory
):
    a = infrastructure_factory(protected=True)
    with app.state.sessions.begin() as db:
        owner = db.scalar(
            select(Administrator).where(Administrator.username == "owner")
        )
        db.add(
            Administrator(
                username="network-operator",
                password_hash=owner.password_hash,
                role="operator",
            )
        )
    login = admin.post(
        "/api/v1/auth/login",
        headers={"origin": "https://testserver"},
        json={"username": "network-operator", "password": "test-password-at-least-16"},
    )
    admin.headers.update(
        {"origin": "https://testserver", "x-csrf-token": login.json()["csrf"]}
    )
    assert admin.get("/api/v1/mikrotik/routers").status_code == 200
    assert (
        admin.patch(
            f"/api/v1/mikrotik/routers/{a}",
            json={"name": "Changed", "role": "ACCESS_POINT", "protected": False},
        ).status_code
        == 403
    )
    with app.state.sessions() as db:
        assert db.get(Router, a).protected
