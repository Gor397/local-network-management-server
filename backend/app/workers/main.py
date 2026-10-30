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
                        AdminSession, ComplianceReport, ComplianceCheck, DeploymentTask, PolicyException, RouterTelemetry, ClientObservation, BackgroundJob, NetworkBatch, OperationTarget)
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
            upstream = db.get(Router, device.network_evidence.get("router_id")) if device.network_evidence.get("router_id") else None
            if not upstream or upstream.status != "UNAVAILABLE":
                notify(db, "agent.heartbeat_missing", device.id, connected=device.network_evidence.get("connected", "UNKNOWN"))
        elif policy and device.state not in ("PENDING_ENROLLMENT",):
            reassess(db, device)
    for task in db.scalars(select(DeploymentTask).where(DeploymentTask.state.in_(["RUNNING","AWAITING_RESTART"]), DeploymentTask.lease_until < now)):
        task.state = "UNKNOWN"
        notify(db, "deployment.lease_expired", task.device_id, task_id=task.id)
    db.execute(delete(HealthReport).where(HealthReport.created_at < now - timedelta(days=settings.health_retention_days)))
    db.execute(delete(RequestNonce).where(RequestNonce.expires_at < now))
    db.execute(delete(AdminSession).where(AdminSession.expires_at < now))
    db.execute(delete(RouterTelemetry).where(RouterTelemetry.created_at < now - timedelta(days=settings.telemetry_retention_days)))
    db.execute(delete(ClientObservation).where(ClientObservation.created_at < now - timedelta(days=settings.telemetry_retention_days)))
    from app.services.repository import clean_uploads
    clean_uploads(db,settings,now)
    for task in db.scalars(select(DeploymentTask).where(DeploymentTask.state.in_(['REBOOT_REQUIRED','AWAITING_RESTART']))):
        recorded=task.result.get('recorded_at')
        if recorded and recorded<(now-timedelta(days=7)).isoformat():
            task.state='UNKNOWN'
            notify(db,'deployment.verification_expired',task.device_id,task_id=task.id)
    for job in db.scalars(select(BackgroundJob).where(BackgroundJob.kind == 'MAINTENANCE', BackgroundJob.status == 'RUNNING', BackgroundJob.available_at < now)):
        job.status = 'UNKNOWN'
    for job in db.scalars(select(BackgroundJob).where(BackgroundJob.kind=='MAINTENANCE',BackgroundJob.status.in_(['PENDING_USER_LOGON','REBOOT_REQUIRED']))):
        recorded=job.data.get('result_recorded_at')
        if recorded and recorded<(now-timedelta(days=7)).isoformat():job.status='UNKNOWN'
    # Security audit logs are deliberately excluded from automatic retention cleanup.
    old = select(ComplianceReport.id).where(ComplianceReport.created_at < now - timedelta(days=30))
    db.execute(delete(ComplianceCheck).where(ComplianceCheck.report_id.in_(old)))
    db.execute(delete(ComplianceReport).where(ComplianceReport.id.in_(old)))


async def automatic_enforcement(app, db, warm):
    from app.services.safety import operation_mode, router_write_block
    if not warm or operation_mode(app.state.settings) not in ("controlled_test", "production"):
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
            if router_write_block(app.state.settings, r) or not r.capabilities.get("stacks"):
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
    started = utcnow()
    active_operations = None
    from app.services.telemetry import poll_all
    from app.services.diagnostics import correlate
    from app.services.recovery import plan_recovery
    from app.services.infrastructure import process_batches
    async def operations_tick():
        await process_batches(app)
        with sessions() as db:
            warm = (utcnow()-started).total_seconds() >= settings.heartbeat_deadline_seconds
            await automatic_enforcement(app, db, warm)
            db.commit()
    while not stop.is_set():
        try:
            from app.services.settings import apply_monitoring
            with sessions() as settings_db: apply_monitoring(settings_db, settings)
            if active_operations is None or active_operations.done():
                if active_operations and active_operations.exception():
                    log.error("worker.operations_failed error=%s", type(active_operations.exception()).__name__)
                active_operations = asyncio.create_task(operations_tick())
            await poll_all(app)
            with sessions() as db:
                correlate(db)
                expire_evidence(db, settings)
                plan_recovery(app, db)
                # Track per-endpoint outcomes without conflating queued work with success.
                for target in db.scalars(select(OperationTarget).join(NetworkBatch).where(NetworkBatch.kind == 'ENDPOINT', OperationTarget.state == 'QUEUED')):
                    if target.preview.get('job_id'):
                        job=db.get(BackgroundJob,target.preview['job_id'])
                        if job and job.status in ('PENDING_USER_LOGON','REBOOT_REQUIRED'):
                            target.deadline=max(target.deadline or job.created_at,job.created_at+timedelta(days=7))
                        elif job and job.status not in ('PENDING','RUNNING'):target.state=job.status;target.result=job.data.get('result',{})
                    elif target.preview.get('version_id'):
                        d=db.get(Device,target.device_id)
                        if d and d.reported_policy_id==target.preview['version_id'] and d.last_verified and d.last_verified > target.created_at:target.state='SUCCEEDED'
                    else:
                        d=db.get(Device,target.device_id)
                        if d and d.last_heartbeat and d.last_heartbeat > target.created_at:target.state='DELIVERED'
                    if target.state=='QUEUED' and target.deadline and target.deadline<utcnow():target.state='UNKNOWN'
                for batch in db.scalars(select(NetworkBatch).where(NetworkBatch.kind=='ENDPOINT',NetworkBatch.state=='APPROVED')):
                    targets=db.scalars(select(OperationTarget).where(OperationTarget.batch_id==batch.id)).all()
                    if targets and all(t.state not in ('QUEUED','RUNNING','PENDING') for t in targets):
                        batch.state='STOPPED' if any(t.state in ('FAILED','UNKNOWN') for t in targets) else 'COMPLETED'
                db.commit()
            (settings.data_dir / "worker.heartbeat").touch()
        except Exception:
            log.exception("worker.tick_failed")
        try:
            await asyncio.wait_for(stop.wait(), timeout=60 if settings.low_resource_mode else 30)
        except TimeoutError:
            pass
    if active_operations:
        try: await asyncio.wait_for(active_operations, timeout=30)
        except (TimeoutError, Exception): pass
    engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())
