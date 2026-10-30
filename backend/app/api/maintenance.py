from datetime import datetime, timedelta, timezone
from typing import Literal
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from app.auth.dependencies import db_session, require, agent_identity, audit
from app.db import utcnow
from app.models import BackgroundJob, PolicyVersion, DeploymentTask
from app.services.devices import device_or_404

router = APIRouter(tags=["maintenance"])


class Maintenance(BaseModel):
    operation: Literal[
        "windows.locale", "ssh.enable", "firewall.apply_allowlist", "system.reboot",
        "legacy.retire_startup_task", "legacy.restore_startup_task",
    ]
    language: str | None = Field(default=None, pattern=r"^[a-z]{2,3}-[A-Za-z]{2,8}$")
    keyboard_layouts: list[str] = Field(default_factory=list, max_length=16)
    public_key: str | None = Field(default=None, max_length=4096)
    approve_disable_default_ssh_rule: bool = False
    # Explicit approval to disable (not delete) the kursant "Allow outbound to ..." rules once Suro's verify.
    replace_legacy_rules: bool = False
    enable_winre: bool = False
    not_before: datetime | None = None
    reason: str = Field(min_length=5, max_length=2000)


@router.post("/devices/{device_id}/maintenance")
def create(
    device_id: str,
    body: Maintenance,
    request: Request,
    admin=Depends(require("approve", mfa=True)),
    db=Depends(db_session),
):
    d = device_or_404(db, device_id)
    if d.device_class == "DEVELOPER" or not d.enabled or not d.policy_version_id:
        raise HTTPException(409, "device.managed_policy_required")
    if d.mode not in ("MAINTENANCE", "APPROVED_REMEDIATION"):
        raise HTTPException(409, "maintenance.approved_mode_required")
    from app.services.safety import endpoint_change_block
    if blocked := endpoint_change_block(request.app.state.settings, d):
        raise HTTPException(409, blocked)
    policy = db.get(PolicyVersion, d.policy_version_id)
    from app.services.legacy_credentials import legacy_state
    legacy = legacy_state(d.inventory, request.app.state.settings.public_origin)
    if body.operation == "firewall.apply_allowlist":
        # The kursant startup task would erase Suro's rules at the next boot; retire it first.
        if "legacy.firewall_reset_at_boot" in legacy["findings"]:
            raise HTTPException(409, "maintenance.legacy_task_active")
        if body.replace_legacy_rules and not legacy["reported"]:
            raise HTTPException(409, "maintenance.legacy_state_unknown")
    if body.operation.startswith("legacy.") and not legacy["startup_task"]:
        raise HTTPException(409, "maintenance.legacy_task_not_reported")
    if body.operation == "windows.locale" and not body.language:
        raise HTTPException(422, "maintenance.language_required")
    import re

    if any(
        not re.fullmatch(r"[0-9A-Fa-f]{4}:[0-9A-Fa-f]{8}", layout)
        for layout in body.keyboard_layouts
    ):
        raise HTTPException(422, "maintenance.invalid_keyboard_layout")
    if body.operation == "ssh.enable":
        import asyncssh

        try:
            asyncssh.import_public_key(body.public_key or "")
        except asyncssh.KeyImportError:
            raise HTTPException(422, "ssh.invalid_public_key") from None
    if body.operation == "windows.locale":
        from app.api.deployments import scheduler_lock

        scheduler_lock(db)
        for prior in db.scalars(
            select(BackgroundJob).where(
                BackgroundJob.device_id == d.id,
                BackgroundJob.kind == "MAINTENANCE",
                BackgroundJob.status.in_(["PENDING", "PENDING_USER_LOGON"]),
            )
        ):
            if prior.data.get("operation") == "windows.locale":
                prior.status = "SUPERSEDED"
    job = BackgroundJob(
        device_id=d.id,
        kind="MAINTENANCE",
        data={
            **body.model_dump(mode="json"),
            "policy_version_id": d.policy_version_id,
            "user_account": policy.document["user_account"],
            "admin_account": policy.document["admin_account"],
            "server": request.app.state.settings.public_origin,
        },
        available_at=(
            body.not_before.astimezone(timezone.utc).replace(tzinfo=None)
            if body.not_before.tzinfo
            else body.not_before
        )
        if body.not_before
        else utcnow(),
    )
    db.add(job)
    db.flush()
    audit(
        db,
        admin.id,
        "maintenance.approved",
        d.id,
        job_id=job.id,
        operation=body.operation,
        reason=body.reason,
    )
    return {"id": job.id, "status": "PENDING"}


@router.get("/devices/{device_id}/maintenance")
def jobs(device_id: str, admin=Depends(require("read")), db=Depends(db_session)):
    return [
        {
            "id": j.id,
            "operation": j.data.get("operation"),
            "status": j.status,
            "at": j.created_at,
            "result": j.data.get("result"),
        }
        for j in db.scalars(
            select(BackgroundJob)
            .where(
                BackgroundJob.device_id == device_id,
                BackgroundJob.kind == "MAINTENANCE",
            )
            .order_by(BackgroundJob.created_at.desc())
            .limit(100)
        )
    ]


@router.get("/agent/maintenance/next")
def next_job(request: Request, d=Depends(agent_identity), db=Depends(db_session)):
    from app.services.safety import endpoint_change_block
    if endpoint_change_block(request.app.state.settings, d):
        return {"job": None}
    if d.mode not in ("MAINTENANCE", "APPROVED_REMEDIATION") or d.network_state in (
        "QUARANTINE_PENDING",
        "ERROR",
    ):
        return {"job": None}
    from app.api.deployments import scheduler_lock

    scheduler_lock(db)
    if db.scalar(
        select(DeploymentTask.id).where(
            DeploymentTask.device_id == d.id,
            DeploymentTask.state.in_(["RUNNING", "AWAITING_RESTART"]),
        )
    ) or db.scalar(
        select(BackgroundJob.id).where(
            BackgroundJob.device_id == d.id,
            BackgroundJob.kind == "MAINTENANCE",
            BackgroundJob.status == "RUNNING",
        )
    ):
        return {"job": None}
    job = db.scalar(
        select(BackgroundJob)
        .where(
            BackgroundJob.device_id == d.id,
            BackgroundJob.kind == "MAINTENANCE",
            BackgroundJob.status == "PENDING",
            BackgroundJob.available_at <= utcnow(),
        )
        .order_by(BackgroundJob.created_at)
        .with_for_update(skip_locked=True)
        .limit(1)
    )
    if not job:
        return {"job": None}
    if job.data["policy_version_id"] != d.policy_version_id:
        job.status = "STALE_POLICY"
        return {"job": None}
    job.status, job.attempts = "RUNNING", job.attempts + 1
    job.available_at = utcnow() + timedelta(hours=2)
    audit(db, d.id, "maintenance.claimed", d.id, job_id=job.id)
    return {
        "job": request.app.state.vault.signed(
            {
                **job.data,
                "job_id": job.id,
                "device_id": d.id,
                "schema_version": 1,
                "expires_at": job.available_at.isoformat() + "Z",
            }
        )
    }


class Result(BaseModel):
    state: Literal[
        "SUCCEEDED", "FAILED", "UNKNOWN", "REBOOT_REQUIRED", "PENDING_USER_LOGON"
    ]
    details: dict


@router.post("/agent/maintenance/{job_id}/result")
def result(
    job_id: str, body: Result, d=Depends(agent_identity), db=Depends(db_session)
):
    j = db.get(BackgroundJob, job_id)
    if (
        j
        and j.device_id == d.id
        and j.kind == "MAINTENANCE"
        and j.status in ("SUPERSEDED", "CANCELLED")
    ):
        audit(db, d.id, "maintenance.stale_result_ignored", j.id)
        return {"accepted": False, "superseded": True}
    if (
        not j
        or j.device_id != d.id
        or j.kind != "MAINTENANCE"
        or j.status
        not in ("RUNNING", "PENDING_USER_LOGON", "REBOOT_REQUIRED", body.state)
    ):
        raise HTTPException(409, "maintenance.invalid_result")
    if (
        j.status in ("PENDING_USER_LOGON", "REBOOT_REQUIRED")
        and body.state == "SUCCEEDED"
        and not body.details.get("verified")
    ):
        raise HTTPException(422, "maintenance.verification_required")
    j.status = body.state
    j.data = {
        **j.data,
        "result": body.details,
        "result_recorded_at": utcnow().isoformat(),
    }
    audit(db, d.id, "maintenance.result", d.id, job_id=j.id, state=body.state)
    return {"accepted": True, "verification_required": True}


@router.get("/agent/maintenance/pending-verification")
def pending_verification(
    request: Request, d=Depends(agent_identity), db=Depends(db_session)
):
    rows = db.scalars(
        select(BackgroundJob)
        .where(
            BackgroundJob.device_id == d.id,
            BackgroundJob.kind == "MAINTENANCE",
            BackgroundJob.status.in_(["PENDING_USER_LOGON", "REBOOT_REQUIRED"]),
        )
        .order_by(BackgroundJob.created_at)
        .limit(10)
    ).all()
    return {
        "jobs": [
            request.app.state.vault.signed(
                {
                    "purpose": "verify_maintenance",
                    "schema_version": 1,
                    "job_id": j.id,
                    "device_id": d.id,
                    "operation": j.data["operation"],
                    "data": j.data,
                    "state": j.status,
                    "expires_at": (utcnow() + timedelta(minutes=5)).isoformat() + "Z",
                }
            )
            for j in rows
        ]
    }
