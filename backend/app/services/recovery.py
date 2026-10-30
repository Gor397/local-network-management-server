from datetime import timedelta
from sqlalchemy import select
from app.db import utcnow
from app.models import (
    Router,
    RouterTelemetry,
    MaintenanceWindow,
    NetworkBatch,
    OperationTarget,
)
from app.services.infrastructure import preview_router
from app.services.diagnostics import incident
from app.services.safety import operation_mode, router_write_block


def critical(metrics):
    return (metrics.get("cpu_percent") or 0) >= 95 or (
        metrics.get("memory_percent") or 0
    ) >= 95


def recovery_action(router, samples, policy, allow_resource_reboot):
    conditions = set(policy.get("conditions", ["resource_pressure"]))
    if not all(s.metrics.get("reachable") for s in samples):
        return None
    if "unexpected_radio_disabled" in conditions:
        for name, desired in sorted(router.desired_config.items()):
            if desired.get("disabled") is not False or desired.get(
                "stack"
            ) not in router.capabilities.get("stacks", []):
                continue
            disabled = lambda sample: any(
                row.get("name") == name and row.get("disabled") in (True, "true")
                for row in sample.metrics.get("interfaces", [])
            )
            if all(disabled(sample) for sample in samples):
                return (
                    "wireless",
                    {"interface": name, "stack": desired["stack"], "disabled": False},
                    "recovery.unexpected_radio_disabled",
                )
    if (
        "resource_pressure" in conditions
        and allow_resource_reboot
        and all(critical(s.metrics) for s in samples)
    ):
        return "reboot", {}, "recovery.sustained_resource_failure"
    return None


def recovery_environment(routers, now):
    fresh = lambda r: bool(
        r.last_health and (now - r.last_health).total_seconds() < 180
    )
    shared_failure = any(
        r.role == "GATEWAY" and (not fresh(r) or not r.health.get("reachable"))
        for r in routers
    ) or sum(not fresh(r) or not r.health.get("reachable") for r in routers) >= max(
        2, len(routers) / 2
    )
    aps = [r for r in routers if r.role == "ACCESS_POINT"]
    common_pressure = sum(
        bool(fresh(r) and r.health.get("reachable") and critical(r.health)) for r in aps
    ) >= max(2, len(aps) / 2)
    upstream_pressure = any(r.role == "GATEWAY" and critical(r.health) for r in routers)
    return not shared_failure, not (common_pressure or upstream_pressure)


def plan_recovery(app, db, now=None):
    now = now or utcnow()
    if (
        not app.state.settings.recovery_enabled
        or operation_mode(app.state.settings) not in ("controlled_test", "production")
    ):
        return []
    routers = db.scalars(select(Router).where(Router.archived.is_(False))).all()
    created = []
    fresh = lambda r: bool(
        r.last_health and (now - r.last_health).total_seconds() < 180
    )
    permitted, allow_resource_reboot = recovery_environment(routers, now)
    if not permitted:
        return []
    for r in routers:
        policy = r.recovery_policy
        if (
            not policy.get("enabled")
            or r.role != "ACCESS_POINT"
            or r.protected
            or router_write_block(app.state.settings, r)
        ):
            continue
        if not fresh(r) or not r.health.get("reachable"):
            # There is no independent power controller. Never pretend an unreachable API can reboot itself.
            continue
        alternatives = [
            o
            for o in routers
            if o.id in policy.get("independent_management_router_ids", [])
            and o.id != r.id
            and fresh(o)
            and o.health.get("reachable")
        ]
        if not alternatives:
            continue
        windows = db.scalars(
            select(MaintenanceWindow).where(
                MaintenanceWindow.starts_at <= now, MaintenanceWindow.ends_at >= now
            )
        ).all()
        if policy.get("require_maintenance_window", True) and not any(
            r.id in w.router_ids for w in windows
        ):
            continue
        prior = db.scalars(
            select(NetworkBatch)
            .join(OperationTarget)
            .where(
                OperationTarget.router_id == r.id,
                NetworkBatch.automatic.is_(True),
                NetworkBatch.created_at >= now - timedelta(days=1),
            )
            .order_by(NetworkBatch.created_at.desc())
        ).all()
        if any(b.state in ("APPROVED", "RUNNING") for b in prior):
            continue
        failed = sum(b.state == "STOPPED" for b in prior)
        if failed >= 2 or len(prior) >= policy.get("max_attempts_per_day", 2):
            r.recovery_policy = {
                **policy,
                "enabled": False,
                "disabled_reason": "recovery.attempt_limit",
            }
            incident(
                db,
                "recovery:limit:" + r.id,
                "incident.recovery_stopped",
                "cause.recovery_failed",
                "HIGH",
                "high",
                [r.id],
                [],
                [{"attempts": len(prior), "failed": failed}],
                ["recommend.manual_recovery"],
            )
            continue
        if prior and (now - prior[0].created_at).total_seconds() < policy.get(
            "cooldown_seconds", 3600
        ):
            continue
        samples = db.scalars(
            select(RouterTelemetry)
            .where(
                RouterTelemetry.router_id == r.id,
                RouterTelemetry.created_at
                >= now - timedelta(seconds=policy.get("sustained_seconds", 300) + 120),
            )
            .order_by(RouterTelemetry.created_at.desc())
            .limit(30)
        ).all()
        if len(samples) < 3 or (
            samples[0].created_at - samples[-1].created_at
        ).total_seconds() < policy.get("sustained_seconds", 300):
            continue
        # Prefer a narrow approved radio correction over disrupting the complete AP.
        action = recovery_action(r, samples, policy, allow_resource_reboot)
        if not action:
            continue
        operation, parameters, reason = action
        try:
            preview = preview_router(app, db, r, operation, parameters)
        except ValueError:
            continue
        batch = NetworkBatch(
            operation=operation,
            parameters={
                **parameters,
                "out_of_band_confirmed": False,
                "independent_management_router_ids": policy.get(
                    "independent_management_router_ids", []
                ),
            },
            state="APPROVED",
            batch_size=1,
            stop_on_failure=True,
            automatic=True,
            reason=reason,
            approved_at=now,
            window_end=min(
                (w.ends_at for w in windows if r.id in w.router_ids),
                default=now + timedelta(minutes=10),
            ),
        )
        db.add(batch)
        db.flush()
        db.add(OperationTarget(batch_id=batch.id, router_id=r.id, preview=preview))
        created.append(batch.id)
    return created
