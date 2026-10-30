import secrets
from datetime import timedelta, datetime
from typing import Literal
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select, func
from app.auth.dependencies import db_session, require, audit
from app.db import utcnow
from app.models import (Device, Enrollment, DeviceCredential, ComplianceReport, ComplianceCheck, HealthReport,
                        AuditLog, BackgroundJob, PolicyException, PolicyVersion, MigrationAssessment, DeviceGroup, GroupMember)
from app.security.crypto import digest, canonical
from app.services.devices import normalize_mac, device_or_404, serialize_device, reassess

router = APIRouter(prefix="/devices", tags=["devices"])


class DeviceCreate(BaseModel):
    hostname: str = Field(min_length=1, max_length=128)
    primary_mac: str
    device_class: Literal["STANDARD", "ADMINISTRATOR", "DEVELOPER", "INFRASTRUCTURE", "OTHER"] = "STANDARD"
    @field_validator("primary_mac")
    @classmethod
    def mac(cls, value):
        return normalize_mac(value)


@router.get("")
def list_devices(request: Request, q: str = "", device_class: str | None = None, offset: int = 0, limit: int = 50,
                 sort: str = "hostname", descending: bool = False, owner_rank: str | None = None, group_id: str | None = None,
                 admin=Depends(require("read")), db=Depends(db_session)):
    limit, offset = min(max(limit, 1), 200), max(offset, 0)
    query = select(Device)
    if q:
        query = query.where(Device.hostname.ilike(f"%{q[:128]}%") | Device.primary_mac.ilike(f"%{q[:128]}%") | Device.owner_name.ilike(f"%{q[:128]}%") | Device.last_user_account.ilike(f"%{q[:128]}%"))
    if device_class:
        query = query.where(Device.device_class == device_class)
    if owner_rank is not None:
        query = query.where(Device.owner_rank == owner_rank)
    if group_id:
        query = query.where(Device.id.in_(select(GroupMember.device_id).where(GroupMember.group_id == group_id)))
    count = db.scalar(select(func.count()).select_from(query.subquery()))
    column = {"hostname": Device.hostname, "primary_mac": Device.primary_mac, "last_heartbeat": Device.last_heartbeat,
              "device_class": Device.device_class, "compliance_score": Device.compliance_score}.get(sort)
    if column is None:
        raise HTTPException(422, "device.invalid_sort")
    devices = db.scalars(query.order_by(column.desc() if descending else column.asc(), Device.id).offset(offset).limit(limit))
    return {"items": [serialize_device(d, request.app.state.settings) for d in devices], "total": count, "offset": offset, "limit": limit}


@router.post("", status_code=201)
def create_device(body: DeviceCreate, request: Request, admin=Depends(require("manage")), db=Depends(db_session)):
    if db.scalar(select(Device.id).where(Device.primary_mac == body.primary_mac)):
        raise HTTPException(409, "device.duplicate_mac")
    device = Device(**body.model_dump(), state="UNVERIFIED" if body.device_class == "DEVELOPER" else "PENDING_ENROLLMENT")
    db.add(device)
    db.flush()
    audit(db, admin.id, "device.created", device.id, device_class=device.device_class)
    return serialize_device(device, request.app.state.settings)


@router.get("/{device_id}")
def detail(device_id: str, request: Request, admin=Depends(require("read")), db=Depends(db_session)):
    device = device_or_404(db, device_id)
    return {**serialize_device(device, request.app.state.settings), "inventory": device.inventory}


class DevicePatch(BaseModel):
    hostname: str | None = Field(default=None, min_length=1, max_length=128)
    mode: Literal["AUDIT", "PREVIEW", "APPROVED_REMEDIATION", "CONTINUOUS", "MAINTENANCE"] | None = None
    device_class: Literal["STANDARD", "ADMINISTRATOR", "INFRASTRUCTURE", "OTHER"] | None = None
    revision: int
    reason: str = Field(min_length=5, max_length=2000)


@router.patch("/{device_id}")
def patch(device_id: str, body: DevicePatch, request: Request, admin=Depends(require("approve", mfa=True)), db=Depends(db_session)):
    d = db.scalar(select(Device).where(Device.id == device_id).with_for_update())
    if not d:
        raise HTTPException(404, "device.not_found")
    if d.revision != body.revision:
        raise HTTPException(409, "device.concurrent_change")
    if d.device_class == "DEVELOPER" and body.device_class:
        raise HTTPException(409, "device.reenrollment_required")
    for key, value in body.model_dump(exclude_none=True).items():
        if key not in ("revision", "reason"):
            setattr(d, key, value)
    d.revision += 1
    d.state, d.last_verified, d.compliance_score = "UNVERIFIED", None, 0
    audit(db, admin.id, "device.updated", d.id, changes=body.model_dump())
    return serialize_device(d, request.app.state.settings)


@router.delete("/{device_id}")
def deactivate(device_id: str, admin=Depends(require("approve", mfa=True)), db=Depends(db_session)):
    d = device_or_404(db, device_id)
    d.enabled, d.state, d.compliance_score, d.last_verified = False, "UNVERIFIED", 0, None
    for c in db.scalars(select(DeviceCredential).where(DeviceCredential.device_id == d.id)):
        c.revoked = True
    audit(db, admin.id, "device.revoked", d.id)
    return {"ok": True, "network_revocation_required": True}


@router.post("/{device_id}/enrollment-token")
def token(device_id: str, admin=Depends(require("manage")), db=Depends(db_session)):
    d = device_or_404(db, device_id)
    if d.device_class == "DEVELOPER" or not d.enabled:
        raise HTTPException(409, "enrollment.invalid_device")
    value = secrets.token_urlsafe(32)
    e = Enrollment(device_id=d.id, token_hash=digest(value), expires_at=utcnow() + timedelta(minutes=15))
    db.add(e)
    audit(db, admin.id, "enrollment.token_created", d.id)
    return {"token": value, "expires_at": e.expires_at}


@router.get("/{device_id}/enrollments")
def enrollment_requests(device_id: str, admin=Depends(require("manage")), db=Depends(db_session)):
    return [{"id": e.id, "requested": bool(e.csr), "approved": e.approved, "expires_at": e.expires_at,
             "csr_sha256": digest(e.csr) if e.csr else None} for e in db.scalars(select(Enrollment).where(Enrollment.device_id == device_id))]


@router.post("/{device_id}/enrollments/{enrollment_id}/approve")
def approve_enrollment(device_id: str, enrollment_id: str, admin=Depends(require("approve", mfa=True)), db=Depends(db_session)):
    e = db.get(Enrollment, enrollment_id)
    if not e or e.device_id != device_id or not e.csr or e.expires_at <= utcnow():
        raise HTTPException(409, "enrollment.invalid_request")
    e.approved = True
    audit(db, admin.id, "enrollment.approved", device_id, csr_sha256=digest(e.csr))
    return {"ok": True}


@router.get("/{device_id}/compliance")
def compliance(device_id: str, request: Request, admin=Depends(require("read")), db=Depends(db_session)):
    d = device_or_404(db, device_id)
    # Re-evaluation at read time prevents a stopped worker from presenting stale PASS.
    v = db.get(PolicyVersion, d.policy_version_id) if d.policy_version_id else None
    if d.device_class == "DEVELOPER" or not v:
        return {"state": "UNVERIFIED", "score": None if d.device_class == "DEVELOPER" else 0, "checks": []}
    from app.compliance.engine import evaluate
    result = evaluate(v.document, v.id, d.reported_policy_id, d.inventory.get("claims", {}), d.network_evidence.get("checks", {}),
                      [c for e in db.scalars(select(PolicyException).where(PolicyException.device_id == d.id, PolicyException.revoked_at.is_(None)))
                       if e.expires_at is None or e.expires_at > utcnow() for c in e.controls])
    if not d.last_heartbeat or d.last_heartbeat < utcnow() - timedelta(seconds=request.app.state.settings.heartbeat_deadline_seconds):
        result["state"], result["score"] = "UNVERIFIED", min(result["score"], 99)
    return result


@router.get("/{device_id}/health")
def health(device_id: str, admin=Depends(require("read")), db=Depends(db_session)):
    return [{"at": h.created_at, "metrics": h.metrics} for h in db.scalars(select(HealthReport).where(HealthReport.device_id == device_id).order_by(HealthReport.created_at.desc()).limit(30))]


@router.get("/{device_id}/history")
def history(device_id: str, admin=Depends(require("read")), db=Depends(db_session)):
    return [{"at": a.created_at, "action": a.action, "actor": a.actor_id, "details": a.details} for a in db.scalars(select(AuditLog).where(AuditLog.target_id == device_id).order_by(AuditLog.created_at.desc()).limit(100))]


@router.post("/{device_id}/recheck")
def recheck(device_id: str, admin=Depends(require("manage")), db=Depends(db_session)):
    d = device_or_404(db, device_id)
    if d.device_class == "DEVELOPER":
        raise HTTPException(409, "device.unmanaged")
    d.revision += 1
    db.add(BackgroundJob(device_id=d.id, kind="SYNC"))
    audit(db, admin.id, "device.sync_requested", d.id)
    return {"status": "QUEUED"}


class ExceptionCreate(BaseModel):
    controls: list[str] = Field(min_length=1, max_length=20)
    reason: str = Field(min_length=5, max_length=2000)
    expires_at: datetime | None = None


@router.get("/{device_id}/exceptions")
def exceptions(device_id: str, admin=Depends(require("read")), db=Depends(db_session)):
    return [{"id": e.id, "controls": e.controls, "reason": e.reason, "expires_at": e.expires_at, "revoked_at": e.revoked_at} for e in db.scalars(select(PolicyException).where(PolicyException.device_id == device_id))]


@router.post("/{device_id}/exceptions")
def add_exception(device_id: str, body: ExceptionCreate, admin=Depends(require("approve", mfa=True)), db=Depends(db_session)):
    from app.policies.schema import CATALOG
    d = device_or_404(db, device_id)
    if set(body.controls) - CATALOG.keys() or any(c.startswith(("agent.", "network.")) for c in body.controls):
        raise HTTPException(422, "policy.control_not_exemptible")
    expiry = body.expires_at.replace(tzinfo=None) if body.expires_at else None
    if expiry and expiry <= utcnow():
        raise HTTPException(422, "policy.exception_expired")
    e = PolicyException(device_id=d.id, controls=body.controls, reason=body.reason, expires_at=expiry, author_id=admin.id)
    db.add(e)
    reassess(db, d)
    audit(db, admin.id, "exception.created", d.id, controls=body.controls, reason=body.reason)
    db.flush()
    return {"id": e.id}


@router.delete("/{device_id}/exceptions/{exception_id}")
def revoke_exception(device_id: str, exception_id: str, admin=Depends(require("approve", mfa=True)), db=Depends(db_session)):
    e = db.get(PolicyException, exception_id)
    if not e or e.device_id != device_id:
        raise HTTPException(404, "policy.exception_not_found")
    e.revoked_at = utcnow()
    db.flush()
    reassess(db, device_or_404(db, device_id))
    audit(db, admin.id, "exception.revoked", device_id, exception_id=e.id)
    return {"ok": True}


@router.post("/{device_id}/migration-assessment")
def migration(device_id: str, admin=Depends(require("manage")), db=Depends(db_session)):
    from app.services.migration import assess
    d = device_or_404(db, device_id)
    report = assess(d.inventory)
    assessment = MigrationAssessment(device_id=d.id, inventory_hash=digest(canonical(d.inventory)), report=report)
    db.add(assessment)
    db.flush()
    audit(db, admin.id, "migration.assessed", d.id)
    return {"id": assessment.id, **report}
