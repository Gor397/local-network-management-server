from datetime import datetime, timedelta
from typing import Literal
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from app.auth.dependencies import db_session, require, agent_identity, audit
from app.db import utcnow
from app.models import BackgroundJob, PolicyVersion
from app.services.devices import device_or_404

router = APIRouter(tags=["maintenance"])


class Maintenance(BaseModel):
    operation: Literal["windows.locale", "ssh.enable", "firewall.apply_allowlist", "system.reboot"]
    language: str | None = Field(default=None, pattern=r"^[a-z]{2,3}-[A-Za-z]{2,8}$")
    public_key: str | None = Field(default=None, max_length=4096)
    approve_disable_default_ssh_rule: bool = False
    not_before: datetime | None = None
    reason: str = Field(min_length=5, max_length=2000)


@router.post("/devices/{device_id}/maintenance")
def create(device_id: str, body: Maintenance, request: Request, admin=Depends(require("approve", mfa=True)), db=Depends(db_session)):
    d = device_or_404(db, device_id)
    if d.device_class == "DEVELOPER" or not d.enabled or not d.policy_version_id:
        raise HTTPException(409, "device.managed_policy_required")
    if d.mode not in ("MAINTENANCE", "APPROVED_REMEDIATION"):
        raise HTTPException(409, "maintenance.approved_mode_required")
    policy = db.get(PolicyVersion, d.policy_version_id)
    if body.operation == "windows.locale" and not body.language:
        raise HTTPException(422, "maintenance.language_required")
    if body.operation == "ssh.enable":
        import asyncssh
        try:
            asyncssh.import_public_key(body.public_key or "")
        except asyncssh.KeyImportError:
            raise HTTPException(422, "ssh.invalid_public_key") from None
    job = BackgroundJob(device_id=d.id, kind="MAINTENANCE", data={**body.model_dump(mode="json"),
              "policy_version_id": d.policy_version_id, "user_account": policy.document["user_account"],
              "admin_account": policy.document["admin_account"], "server": request.app.state.settings.public_origin},
              available_at=body.not_before.replace(tzinfo=None) if body.not_before else utcnow())
    db.add(job)
    db.flush()
    audit(db, admin.id, "maintenance.approved", d.id, job_id=job.id, operation=body.operation, reason=body.reason)
    return {"id": job.id, "status": "PENDING"}


@router.get("/devices/{device_id}/maintenance")
def jobs(device_id: str, admin=Depends(require("read")), db=Depends(db_session)):
    return [{"id": j.id, "operation": j.data.get("operation"), "status": j.status, "at": j.created_at,
             "result": j.data.get("result")} for j in db.scalars(select(BackgroundJob).where(BackgroundJob.device_id == device_id, BackgroundJob.kind == "MAINTENANCE").order_by(BackgroundJob.created_at.desc()).limit(100))]


@router.get("/agent/maintenance/next")
def next_job(request: Request, d=Depends(agent_identity), db=Depends(db_session)):
    if d.mode not in ("MAINTENANCE", "APPROVED_REMEDIATION") or d.network_state in ("QUARANTINE_PENDING", "ERROR"):
        return {"job": None}
    job = db.scalar(select(BackgroundJob).where(BackgroundJob.device_id == d.id, BackgroundJob.kind == "MAINTENANCE",
                    BackgroundJob.status == "PENDING", BackgroundJob.available_at <= utcnow()).order_by(BackgroundJob.created_at)
                    .with_for_update(skip_locked=True).limit(1))
    if not job:
        return {"job": None}
    if job.data["policy_version_id"] != d.policy_version_id:
        job.status = "STALE_POLICY"
        return {"job": None}
    job.status, job.attempts = "RUNNING", job.attempts + 1
    job.available_at = utcnow() + timedelta(hours=2)
    audit(db, d.id, "maintenance.claimed", d.id, job_id=job.id)
    return {"job": request.app.state.vault.signed({**job.data, "job_id": job.id, "device_id": d.id,
              "schema_version": 1, "expires_at": job.available_at.isoformat()})}


class Result(BaseModel):
    state: Literal["SUCCEEDED", "FAILED", "UNKNOWN", "REBOOT_REQUIRED", "PENDING_USER_LOGON"]
    details: dict


@router.post("/agent/maintenance/{job_id}/result")
def result(job_id: str, body: Result, d=Depends(agent_identity), db=Depends(db_session)):
    j = db.get(BackgroundJob, job_id)
    if not j or j.device_id != d.id or j.kind != "MAINTENANCE" or j.status not in ("RUNNING", body.state):
        raise HTTPException(409, "maintenance.invalid_result")
    j.status = body.state
    j.data = {**j.data, "result": body.details}
    audit(db, d.id, "maintenance.result", d.id, job_id=j.id, state=body.state)
    return {"accepted": True, "verification_required": True}
