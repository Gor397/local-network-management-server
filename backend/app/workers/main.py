import asyncio
import json
import logging
import signal
from datetime import timedelta
from types import SimpleNamespace
from sqlalchemy import select, delete
from app.config import Settings
from app.db import database, utcnow
from app.models import (Device, PolicyVersion, Router, NetworkPlan, Alert, HealthReport, RequestNonce,
                        AdminSession, ComplianceReport, ComplianceCheck, DeploymentTask, PolicyException)
from app.security.crypto import Vault
from app.services.network import discover, execute_plan
from app.services.devices import notify, reassess
from app.mikrotik.connector import snapshot_hash
from app.mikrotik.planner import disconnect_plan

log = logging.getLogger("lantern.worker")


def expire_evidence(db, settings, warm=True):
    now = utcnow()
    for device in db.scalars(select(Device).where(Device.enabled.is_(True), Device.device_class != "DEVELOPER")):
        policy = db.get(PolicyVersion, device.policy_version_id) if device.policy_version_id else None
        deadline = policy.document.get("heartbeat_deadline_seconds", settings.heartbeat_deadline_seconds) if policy else settings.heartbeat_deadline_seconds
        missing = device.last_heartbeat and device.last_heartbeat < now - timedelta(seconds=deadline)
        if missing:
            device.state, device.compliance_score, device.last_verified = "UNVERIFIED", 0, None
            notify(db, "agent.heartbeat_missing", device.id, connected=device.network_evidence.get("connected", "UNKNOWN"))
        elif policy and device.state not in ("PENDING_ENROLLMENT",):
            reassess(db, device)
    for task in db.scalars(select(DeploymentTask).where(DeploymentTask.state == "RUNNING", DeploymentTask.lease_until < now)):
        task.state = "UNKNOWN"
        notify(db, "deployment.lease_expired", task.device_id, task_id=task.id)
    db.execute(delete(HealthReport).where(HealthReport.created_at < now - timedelta(days=settings.health_retention_days)))
    db.execute(delete(RequestNonce).where(RequestNonce.expires_at < now))
    db.execute(delete(AdminSession).where(AdminSession.expires_at < now))
    # Security audit logs are deliberately excluded from automatic retention cleanup.
    old = select(ComplianceReport.id).where(ComplianceReport.created_at < now - timedelta(days=30))
    db.execute(delete(ComplianceCheck).where(ComplianceCheck.report_id.in_(old)))
    db.execute(delete(ComplianceReport).where(ComplianceReport.id.in_(old)))


async def automatic_enforcement(app, db, warm):
    if not warm or not app.state.settings.router_writes_enabled:
        return
    routers = db.scalars(select(Router)).all()
    # Server recovery and router outages never trigger speculative network actions.
    if not routers or any(r.status != "ONLINE" or not r.last_seen or (utcnow() - r.last_seen).total_seconds() > 120 for r in routers):
        return
    for device in db.scalars(select(Device).where(Device.enabled.is_(True), Device.device_class != "DEVELOPER")):
        if device.mode != "CONTINUOUS" or not device.policy_version_id:
            continue
        policy = db.get(PolicyVersion, device.policy_version_id).document
        deadline = policy.get("heartbeat_deadline_seconds", 300)
        missing = bool(device.last_heartbeat and (utcnow() - device.last_heartbeat).total_seconds() > deadline)
        fail = device.state == "NONCOMPLIANT" and policy.get("quarantine_on_failure", False)
        expire = missing and policy.get("quarantine_on_missing_heartbeat", False)
        if not (fail or expire):
            continue
        observation = device.network_evidence
        if not observation.get("connected") or observation.get("observed_at", "") < (utcnow() - timedelta(seconds=120)).isoformat():
            continue
        alert = db.scalar(select(Alert).where(Alert.device_id == device.id, Alert.code == ("agent.heartbeat_missing" if missing else "device.noncompliant"), Alert.resolved_at.is_(None)).order_by(Alert.created_at))
        if not alert or (utcnow() - alert.created_at).total_seconds() < policy.get("remediation_grace_seconds", 300):
            continue
        if db.scalar(select(NetworkPlan.id).where(NetworkPlan.device_id == device.id, NetworkPlan.state.in_(["APPLYING", "ERROR"]))):
            continue
        for r in routers:
            if not r.write_enabled or not r.capabilities.get("stacks"):
                continue
            snapshot = json.loads(app.state.vault.open(r.snapshot))
            try:
                operations = disconnect_plan(device, snapshot, r.capabilities)
            except ValueError:
                continue
            # Avoid rewriting an already enforced identical rejection every cycle.
            if all(op["method"] == "PATCH" for op in operations):
                continue
            plan = NetworkPlan(device_id=device.id, router_id=r.id, generation=r.generation,
                    snapshot_hash=snapshot_hash(snapshot), operations=operations, reason="automatic.policy_quarantine", author_id=None)
            db.add(plan)
            db.flush()
            await execute_plan(app, db, plan, "worker:approved-policy")


async def main():
    logging.basicConfig(level=logging.INFO)
    settings = Settings()
    engine, sessions = database(settings.database_url)
    app = SimpleNamespace(state=SimpleNamespace(settings=settings, vault=Vault(settings), sessions=sessions))
    stop = asyncio.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        asyncio.get_running_loop().add_signal_handler(sig, stop.set)
    started, router_offset = utcnow(), 0
    while not stop.is_set():
        try:
            with sessions() as db:
                routers = db.scalars(select(Router).order_by(Router.id)).all()
                # Every router must be observed within a freshness window before automation is allowed.
                for router in routers:
                    try:
                        await discover(app, db, router)
                    except Exception:
                        log.warning("router.discovery_failed router_id=%s", router.id)
                    db.commit()
                expire_evidence(db, settings)
                db.commit()
                warm = (utcnow() - started).total_seconds() >= settings.heartbeat_deadline_seconds
                await automatic_enforcement(app, db, warm)
                db.commit()
                (settings.data_dir / "worker.heartbeat").touch()
        except Exception:
            log.exception("worker.tick_failed")
        try:
            await asyncio.wait_for(stop.wait(), timeout=60 if settings.low_resource_mode else 30)
        except TimeoutError:
            pass
    engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())
