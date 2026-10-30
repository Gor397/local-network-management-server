import asyncio
import json
from datetime import timedelta
from fastapi import APIRouter, Depends, Request, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy import select, func
from pydantic import BaseModel, Field
from typing import Literal
from app.auth.dependencies import db_session, require, admin_session, audit
from app.services.safety import operation_mode
from app.db import utcnow
from app.models import Device, Alert, AuditLog, Router, DeviceGroup, GroupMember, Administrator, Role
from app.services.devices import serialize_device, device_or_404

router = APIRouter(tags=["operations"])


@router.get("/dashboard")
def dashboard(request: Request, admin=Depends(require("read")), db=Depends(db_session)):
    # Inventory size is modest; SQL aggregates are used for persistent counters.
    settings = request.app.state.settings
    counts = {k: 0 for k in ("total", "online", "offline", "COMPLIANT", "NONCOMPLIANT", "QUARANTINED", "UNVERIFIED", "developer", "manual")}
    for device in db.scalars(select(Device).where(Device.enabled.is_(True))):
        d = serialize_device(device, settings)
        counts["total"] += 1
        counts[d["state"]] = counts.get(d["state"], 0) + 1
        counts["developer"] += int(device.device_class == "DEVELOPER")
        online = bool(device.last_heartbeat and device.last_heartbeat >= utcnow() - timedelta(seconds=settings.heartbeat_deadline_seconds))
        if device.device_class == "DEVELOPER":
            online = bool(device.network_evidence.get("connected") and device.network_evidence.get("observed_at", "") > (utcnow() - timedelta(seconds=300)).isoformat())
        counts["online" if online else "offline"] += 1
        counts["manual"] += int(any(v.get("status") == "FAIL" for k, v in device.inventory.get("claims", {}).items() if k.startswith("disk.")))
    alerts = db.scalars(select(Alert).where(Alert.resolved_at.is_(None)).order_by(Alert.created_at.desc()).limit(8)).all()
    return {"counts": counts, "alerts": [{"id": a.id, "code": a.code, "severity": a.severity, "device_id": a.device_id, "at": a.created_at} for a in alerts],
            "routers": db.scalar(select(func.count()).select_from(Router)),
            "low_resource_mode": settings.low_resource_mode, "poll_seconds": settings.poll_seconds,
            "deployment_concurrency": settings.deployment_concurrency,
            "operation_mode": operation_mode(settings), "operation_mode_configured": bool(settings.operation_mode), "features": {"router_writes": operation_mode(settings) in ("controlled_test", "production"), "deployments": settings.deployment_enabled, "ssh": settings.ssh_enabled}}


@router.get("/safety")
def safety(request: Request, admin=Depends(require("read"))):
    # Cheap enough for every page; the dashboard banner reads only this.
    settings = request.app.state.settings
    return {"mode": operation_mode(settings), "configured": bool(settings.operation_mode),
            "test_routers": len([n for n in settings.test_routers.split(",") if n.strip()]),
            "test_devices": len([n for n in settings.test_devices.split(",") if n.strip()])}


@router.get("/alerts")
def alerts(offset: int = 0, limit: int = 50, admin=Depends(require("read")), db=Depends(db_session)):
    rows = db.scalars(select(Alert).order_by(Alert.created_at.desc()).offset(max(0, offset)).limit(min(max(limit, 1), 200)))
    return [{"id": a.id, "code": a.code, "severity": a.severity, "device_id": a.device_id, "at": a.created_at,
             "details": a.details, "acknowledged_by": a.acknowledged_by, "resolved_at": a.resolved_at} for a in rows]


@router.post("/alerts/{alert_id}/acknowledge")
def acknowledge(alert_id: str, admin=Depends(require("manage")), db=Depends(db_session)):
    a = db.get(Alert, alert_id)
    if not a:
        raise HTTPException(404, "alert.not_found")
    a.acknowledged_by = admin.id
    audit(db, admin.id, "alert.acknowledged", a.id)
    return {"ok": True}


@router.get("/audit")
def audits(offset: int = 0, admin=Depends(require("read")), db=Depends(db_session)):
    return [{"id": a.id, "action": a.action, "actor": a.actor_id, "target": a.target_id, "at": a.created_at, "details": a.details} for a in db.scalars(select(AuditLog).order_by(AuditLog.created_at.desc()).offset(max(0, offset)).limit(100))]


@router.get("/events")
async def events(request: Request):
    # Do not retain a DB session per SSE client. Only revision metadata is streamed.
    from app.security.crypto import digest
    from app.models import AdminSession
    session_hash = digest(request.cookies.get("lantern_session", ""))
    with request.app.state.sessions() as db:
        session = db.get(AdminSession, session_hash)
        admin = db.get(Administrator, session.admin_id) if session else None
        if not session or session.expires_at <= utcnow() or not admin or not admin.enabled:
            raise HTTPException(401, "auth.required")
    async def stream():
        previous = None
        for _ in range(120):
            if await request.is_disconnected():
                break
            with request.app.state.sessions() as db:
                from app.models import AdminSession
                login = db.get(AdminSession, session_hash)
                operator = db.get(Administrator, login.admin_id) if login else None
                if not login or login.expires_at <= utcnow() or not operator or not operator.enabled:
                    break
                from app.models import Router, Incident, OperationTarget
                stamp = [str(db.scalar(select(func.max(Alert.created_at)))),
                         str(db.scalar(select(func.max(AuditLog.created_at)))),
                         db.scalar(select(func.sum(Device.revision))) or 0,
                         str(db.scalar(select(func.max(Router.last_health)))),
                         str(db.scalar(select(func.max(Incident.last_observed)))),
                         db.scalar(select(func.count()).select_from(OperationTarget).where(OperationTarget.state.in_(['SUCCEEDED','FAILED','UNKNOWN']))) or 0]
            if stamp != previous:
                yield "event: revision\ndata: " + json.dumps(stamp) + "\n\n"
                previous = stamp
            else:
                yield ": keepalive\n\n"
            await asyncio.sleep(15)
    return StreamingResponse(stream(), media_type="text/event-stream", headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})


class AdminCreate(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=16, max_length=1024)
    role: Literal["owner", "operator", "viewer", "deployer"]


@router.get("/administrators")
def administrators(admin=Depends(require("administrators", mfa=True)), db=Depends(db_session)):
    return [{"id": a.id, "username": a.username, "role": a.role, "enabled": a.enabled, "mfa_enabled": bool(a.totp_secret)} for a in db.scalars(select(Administrator).order_by(Administrator.username))]


@router.post("/administrators")
def create_administrator(body: AdminCreate, admin=Depends(require("administrators", mfa=True)), db=Depends(db_session)):
    from argon2 import PasswordHasher
    a = Administrator(username=body.username, password_hash=PasswordHasher().hash(body.password), role=body.role)
    db.add(a)
    db.flush()
    audit(db, admin.id, "admin.created", a.id, role=a.role)
    return {"id": a.id}


class AdminChange(BaseModel):
    enabled: bool
    role: Literal["owner", "operator", "viewer", "deployer"]


@router.patch("/administrators/{admin_id}")
def change_administrator(admin_id: str, body: AdminChange, admin=Depends(require("administrators", mfa=True)), db=Depends(db_session)):
    from app.models import AdminSession
    a = db.get(Administrator, admin_id)
    if not a:
        raise HTTPException(404, "auth.admin_not_found")
    if a.id == admin.id:
        raise HTTPException(409, "auth.self_lockout_prevented")
    a.enabled, a.role = body.enabled, body.role
    for session in db.scalars(select(AdminSession).where(AdminSession.admin_id == a.id)):
        db.delete(session)
    audit(db, admin.id, "admin.changed", a.id, enabled=a.enabled, role=a.role)
    return {"ok": True}


@router.get("/system/resources")
def resources(request: Request, admin=Depends(require("read")), db=Depends(db_session)):
    from pathlib import Path
    from app.models import SoftwarePackage, DeploymentTask
    import resource, shutil
    def cgroup(name):
        try:
            return (Path('/sys/fs/cgroup') / name).read_text().strip()
        except OSError:
            return None
    usage = shutil.disk_usage(request.app.state.settings.data_dir)
    return {"process_max_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
            "container_memory_bytes": cgroup('memory.current'), "container_memory_limit": cgroup('memory.max'),
            "cpu_quota": cgroup('cpu.max'), "storage_free_bytes": usage.free,
            "repository_logical_bytes": db.scalar(select(func.sum(SoftwarePackage.size))) or 0,
            "running_deployments": db.scalar(select(func.count()).select_from(DeploymentTask).where(DeploymentTask.state == 'RUNNING')),
            "low_resource_mode": request.app.state.settings.low_resource_mode}


class MonitoringSettings(BaseModel):
    low_resource_mode: bool = True
    network_health_seconds: int = Field(default=60, ge=30, le=600)
    network_inventory_seconds: int = Field(default=900, ge=300, le=86400)
    network_poll_concurrency: int = Field(default=2, ge=1, le=4)
    telemetry_retention_days: int = Field(default=7, ge=1, le=90)
    recovery_enabled: bool = False
    reason: str = Field(min_length=5,max_length=2000)


@router.get('/system/monitoring-settings')
def monitoring_settings(request: Request, admin=Depends(require('read')), db=Depends(db_session)):
    from app.services.settings import MONITORING_KEYS, apply_monitoring
    apply_monitoring(db,request.app.state.settings)
    return {key:getattr(request.app.state.settings,key) for key in MONITORING_KEYS}


@router.put('/system/monitoring-settings')
def save_monitoring(body: MonitoringSettings, request: Request, admin=Depends(require('approve',mfa=True)), db=Depends(db_session)):
    from app.models import SystemSetting
    from app.services.settings import apply_monitoring
    row=db.get(SystemSetting,'monitoring')
    if not row:row=SystemSetting(key='monitoring',value={});db.add(row)
    row.value=body.model_dump(exclude={'reason'});db.flush();apply_monitoring(db,request.app.state.settings)
    audit(db,admin.id,'monitoring.settings_changed','monitoring',values=row.value,reason=body.reason)
    return {'ok':True,'worker_refresh':'next_monitoring_tick'}
