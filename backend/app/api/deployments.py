import asyncio
import base64
import hashlib
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import StreamingResponse
from starlette.background import BackgroundTask
from pydantic import BaseModel, Field, model_validator
from sqlalchemy import select, func, text
from app.auth.dependencies import db_session, require, agent_identity, audit
from app.db import utcnow
from app.models import (
    Upload,
    SoftwarePackage,
    Deployment,
    DeploymentTask,
    Device,
    GroupMember,
    BackgroundJob,
)
from app.services.devices import device_or_404

router = APIRouter(tags=["deployments"])
KINDS = {
    "msi": {".msi"},
    "exe": {".exe"},
    "msix": {".msix", ".msixbundle"},
    "driver": {".cab"},
    "windows_update": {".msu", ".cab"},
    "language_pack": {".cab"},
    "feature": {".cab"},
    "script": {".ps1"},
    "agent_update": {".msi"},
    "routeros": {".npk"},
}


class Detection(BaseModel):
    model_config = {"extra": "forbid"}
    kind: Literal["file_sha256", "registry"]
    path: str = Field(max_length=512)
    sha256: str | None = Field(default=None, pattern=r"^[a-fA-F0-9]{64}$")
    value_name: str | None = Field(default=None, max_length=128)
    expected_value: str | None = Field(default=None, max_length=512)

    @model_validator(mode="after")
    def allowed(self):
        if self.kind == "file_sha256":
            if (
                not self.sha256
                or not re.fullmatch(
                    r"C:\\Program Files(?: \(x86\))?\\[A-Za-z0-9_ .(){}\\-]+", self.path
                )
                or ".." in self.path.split("\\")
            ):
                raise ValueError("package.invalid_detection")
        elif (
            not self.path.startswith("HKLM:\\SOFTWARE\\")
            or not self.value_name
            or self.expected_value is None
        ):
            raise ValueError("package.invalid_detection")
        return self


class Descriptor(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    filename: str = Field(min_length=1, max_length=256, pattern=r"^[A-Za-z0-9_. -]+$")
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    size: int = Field(gt=0)
    kind: str
    publisher_thumbprint: str = Field(default="", pattern=r"^(?:[A-Fa-f0-9]{40,64})?$")
    architecture: Literal[
        "x64", "arm64", "x86", "arm", "mipsbe", "mmips", "tile", "ppc", "smips"
    ] = "x64"
    release_version: str | None = Field(
        default=None, pattern=r"^[67]\.\d+(?:\.\d+)?(?:[a-z]+\d*)?$"
    )
    minimum_build: int = Field(default=22000, ge=17763)
    maximum_build: int = Field(default=99999, ge=17763)
    product_code: str | None = Field(default=None, pattern=r"^\{[0-9A-Fa-f-]{36}\}$")
    feature_name: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_.-]{1,128}$")
    language: str | None = Field(default=None, pattern=r"^[a-z]{2,3}-[A-Za-z]{2,8}$")
    expected_version: str | None = Field(default=None, pattern=r"^\d+(?:\.\d+){1,3}$")
    package_identity: str | None = Field(
        default=None, pattern=r"^[A-Za-z0-9_.~\-]{1,256}$"
    )
    msix_name: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_.\-]{1,128}$")
    driver_original_inf: str | None = Field(
        default=None, pattern=r"^[A-Za-z0-9_.-]{1,128}\.inf$"
    )
    detection: Detection | None = None

    @model_validator(mode="after")
    def validate_kind(self):
        if (
            self.kind not in KINDS
            or Path(self.filename).suffix.lower() not in KINDS[self.kind]
        ):
            raise ValueError("package.invalid_type")
        if self.kind != "routeros" and not self.publisher_thumbprint:
            raise ValueError("package.publisher_required")
        if self.kind == "routeros" and not self.release_version:
            raise ValueError("package.version_required")
        if self.kind in ("msi", "agent_update") and not self.product_code:
            raise ValueError("package.product_code_required")
        if self.kind == "feature" and not self.feature_name:
            raise ValueError("package.feature_name_required")
        if self.kind == "agent_update" and not self.expected_version:
            raise ValueError("package.expected_version_required")
        return self


def paths(request):
    root = request.app.state.settings.data_dir / "repository"
    (root / "uploads").mkdir(parents=True, exist_ok=True, mode=0o700)
    (root / "objects").mkdir(parents=True, exist_ok=True, mode=0o700)
    return root


@router.post("/packages/uploads", status_code=201)
def start_upload(
    body: Descriptor,
    request: Request,
    admin=Depends(require("deploy", mfa=True)),
    db=Depends(db_session),
):
    if body.size > request.app.state.settings.max_upload_bytes:
        raise HTTPException(413, "package.too_large")
    existing = db.scalar(
        select(SoftwarePackage).where(SoftwarePackage.sha256 == body.sha256)
    )
    if existing:
        return {"package_id": existing.id, "deduplicated": True}
    upload = Upload(
        admin_id=admin.id,
        sha256=body.sha256,
        size=body.size,
        descriptor=body.model_dump(),
    )
    db.add(upload)
    db.flush()
    path = paths(request) / "uploads" / upload.id
    path.touch(mode=0o600, exist_ok=False)
    audit(
        db,
        admin.id,
        "package.upload_started",
        upload.id,
        size=body.size,
        sha256=body.sha256,
    )
    return {
        "upload_id": upload.id,
        "offset": 0,
        "chunk_size": request.app.state.settings.upload_chunk_bytes,
    }


@router.get("/packages/uploads/{upload_id}")
def upload_status(
    upload_id: str, admin=Depends(require("deploy")), db=Depends(db_session)
):
    u = db.get(Upload, upload_id)
    if not u or u.admin_id != admin.id:
        raise HTTPException(404, "package.upload_not_found")
    return {"offset": u.offset, "size": u.size, "completed": u.completed}


@router.put("/packages/uploads/{upload_id}")
async def upload_chunk(
    upload_id: str,
    offset: int,
    request: Request,
    admin=Depends(require("deploy", mfa=True)),
    db=Depends(db_session),
):
    u = db.scalar(select(Upload).where(Upload.id == upload_id).with_for_update())
    if not u or u.admin_id != admin.id or u.completed:
        raise HTTPException(404, "package.upload_not_found")
    if u.offset != offset:
        raise HTTPException(409, "package.offset_conflict")
    chunk = await request.body()
    if (
        not chunk
        or len(chunk) > request.app.state.settings.upload_chunk_bytes
        or offset + len(chunk) > u.size
    ):
        raise HTTPException(413, "package.invalid_chunk_size")
    path = paths(request) / "uploads" / u.id
    with path.open("r+b") as output:
        output.seek(offset)
        output.write(chunk)
        output.truncate(offset + len(chunk))
        output.flush()
        os.fsync(output.fileno())
    u.offset += len(chunk)
    return {"offset": u.offset}


@router.post("/packages/uploads/{upload_id}/complete")
def finish_upload(
    upload_id: str,
    request: Request,
    admin=Depends(require("deploy", mfa=True)),
    db=Depends(db_session),
):
    u = db.scalar(select(Upload).where(Upload.id == upload_id).with_for_update())
    if not u or u.admin_id != admin.id or u.completed or u.offset != u.size:
        raise HTTPException(409, "package.upload_incomplete")
    path = paths(request) / "uploads" / u.id
    with path.open("rb") as f:
        actual = hashlib.file_digest(f, "sha256").hexdigest()
    if actual != u.sha256:
        raise HTTPException(422, "package.hash_mismatch")
    target = paths(request) / "objects" / actual
    # Hard link never overwrites an existing content-addressed object.
    try:
        os.link(path, target)
    except FileExistsError:
        pass
    package = db.scalar(select(SoftwarePackage).where(SoftwarePackage.sha256 == actual))
    if not package:
        d = u.descriptor
        package = SoftwarePackage(
            name=d["name"],
            filename=d["filename"],
            sha256=actual,
            size=u.size,
            kind=d["kind"],
            publisher_thumbprint=d["publisher_thumbprint"].upper(),
            metadata_=d,
        )
        db.add(package)
        db.flush()
    u.completed = True
    audit(db, admin.id, "package.upload_complete", package.id, sha256=actual)
    return {"package_id": package.id, "approved": False}


@router.get("/packages")
def packages(admin=Depends(require("read")), db=Depends(db_session)):
    return [
        {
            "id": p.id,
            "name": p.name,
            "filename": p.filename,
            "sha256": p.sha256,
            "size": p.size,
            "kind": p.kind,
            "approved": bool(p.approved_by),
            "metadata": p.metadata_,
        }
        for p in db.scalars(
            select(SoftwarePackage)
            .order_by(SoftwarePackage.created_at.desc())
            .limit(200)
        )
    ]


class Approval(BaseModel):
    reason: str = Field(min_length=5, max_length=2000)


@router.post("/packages/{package_id}/approve")
def approve(
    package_id: str,
    body: Approval,
    admin=Depends(require("approve", mfa=True)),
    db=Depends(db_session),
):
    package = db.get(SoftwarePackage, package_id)
    if not package:
        raise HTTPException(404, "package.not_found")
    package.approved_by = admin.id
    audit(
        db,
        admin.id,
        "package.approved",
        package.id,
        reason=body.reason,
        publisher_pin=package.publisher_thumbprint,
    )
    return {"approved": True, "endpoint_signature_validation_required": True}


class DeploymentCreate(BaseModel):
    package_id: str
    device_ids: list[str] = Field(default_factory=list, max_length=10000)
    group_ids: list[str] = Field(default_factory=list, max_length=100)
    all_devices: bool = False
    action: Literal["install", "uninstall", "update"] = "install"
    arguments: list[str] = Field(default_factory=list, max_length=30)
    not_before: datetime | None = None
    reason: str = Field(min_length=5, max_length=2000)


@router.post("/deployments", status_code=201)
def deploy(
    body: DeploymentCreate,
    request: Request,
    admin=Depends(require("deploy", mfa=True)),
    db=Depends(db_session),
):
    if not request.app.state.settings.deployment_enabled:
        raise HTTPException(409, "deployment.disabled")
    from app.services.safety import blocks_all_changes
    if blocked := blocks_all_changes(request.app.state.settings):
        raise HTTPException(409, blocked)
    package = db.get(SoftwarePackage, body.package_id)
    if not package or not package.approved_by:
        raise HTTPException(409, "package.approval_required")
    if package.kind == "routeros":
        raise HTTPException(422, "package.router_target_required")
    if any(len(a) > 1024 or "\x00" in a or "\n" in a for a in body.arguments):
        raise HTTPException(422, "deployment.invalid_arguments")
    # Arbitrary parameters are confined to explicitly approved installers; policy never receives them.
    if package.kind not in ("exe", "script") and body.arguments:
        raise HTTPException(422, "deployment.typed_package_arguments_only")
    if body.action == "uninstall" and package.kind not in ("msi", "exe", "msix"):
        raise HTTPException(422, "deployment.uninstall_unsupported")
    ids = set(body.device_ids)
    if body.group_ids:
        ids.update(
            db.scalars(
                select(GroupMember.device_id).where(
                    GroupMember.group_id.in_(body.group_ids)
                )
            )
        )
    if body.all_devices:
        ids.update(
            db.scalars(
                select(Device.id).where(
                    Device.enabled.is_(True), Device.device_class != "DEVELOPER"
                )
            )
        )
    if not ids:
        raise HTTPException(422, "deployment.no_targets")
    devices = [device_or_404(db, d) for d in sorted(ids)]
    if any(d.device_class == "DEVELOPER" or not d.enabled for d in devices):
        raise HTTPException(409, "device.unmanaged")
    # Suro's own agent updates stay possible, so a computer can always be brought back under management.
    if package.kind != "agent_update" and any(not deployment_allowed(db, d) for d in devices):
        raise HTTPException(409, "deployment.disabled_by_policy")
    deployment = Deployment(
        package_id=package.id,
        author_id=admin.id,
        action=body.action,
        arguments=body.arguments,
        not_before=(
            body.not_before.astimezone(timezone.utc).replace(tzinfo=None)
            if body.not_before.tzinfo
            else body.not_before
        )
        if body.not_before
        else utcnow(),
        reason=body.reason,
    )
    db.add(deployment)
    db.flush()
    for d in devices:
        db.add(DeploymentTask(deployment_id=deployment.id, device_id=d.id))
    audit(
        db,
        admin.id,
        "deployment.created",
        deployment.id,
        targets=sorted(ids),
        package_hash=package.sha256,
        reason=body.reason,
    )
    return {
        "id": deployment.id,
        "targets": len(ids),
        "concurrency": request.app.state.settings.deployment_concurrency,
    }


@router.get("/deployments")
def deployments(admin=Depends(require("read")), db=Depends(db_session)):
    rows = db.execute(
        select(
            DeploymentTask.deployment_id, DeploymentTask.state, func.count()
        ).group_by(DeploymentTask.deployment_id, DeploymentTask.state)
    ).all()
    counts = {}
    for deployment_id, state, count in rows:
        counts.setdefault(deployment_id, {})[state] = count
    return [
        {
            "id": d.id,
            "package_id": d.package_id,
            "action": d.action,
            "not_before": d.not_before,
            "cancelled": d.cancelled,
            "counts": counts.get(d.id, {}),
        }
        for d in db.scalars(
            select(Deployment).order_by(Deployment.created_at.desc()).limit(100)
        )
    ]


@router.get("/deployments/{deployment_id}/tasks")
def tasks(deployment_id: str, admin=Depends(require("read")), db=Depends(db_session)):
    return [
        {
            "id": t.id,
            "device_id": t.device_id,
            "state": t.state,
            "attempt": t.attempt,
            "result": t.result,
        }
        for t in db.scalars(
            select(DeploymentTask).where(DeploymentTask.deployment_id == deployment_id)
        )
    ]


@router.post("/deployments/{deployment_id}/cancel")
def cancel(
    deployment_id: str,
    admin=Depends(require("deploy", mfa=True)),
    db=Depends(db_session),
):
    d = db.get(Deployment, deployment_id)
    if not d:
        raise HTTPException(404, "deployment.not_found")
    d.cancelled = True
    for t in db.scalars(
        select(DeploymentTask).where(
            DeploymentTask.deployment_id == d.id, DeploymentTask.state == "PENDING"
        )
    ):
        t.state = "CANCELLED"
    audit(db, admin.id, "deployment.cancelled", d.id)
    return {
        "status": "CANCEL_REQUESTED",
        "running_installers": "allowed_to_finish_safely",
    }


@router.post("/deployment-tasks/{task_id}/retry")
def retry(
    task_id: str, admin=Depends(require("deploy", mfa=True)), db=Depends(db_session)
):
    t = db.get(DeploymentTask, task_id)
    if not t or t.state not in ("FAILED", "UNKNOWN", "CANCELLED"):
        raise HTTPException(409, "deployment.retry_invalid_state")
    if db.get(Deployment, t.deployment_id).cancelled:
        raise HTTPException(409, "deployment.cancelled")
    t.state, t.lease_until = "PENDING", None
    audit(db, admin.id, "deployment.retry_approved", t.id, prior_result=t.result)
    return {"status": "PENDING"}


def scheduler_lock(db):
    if db.bind.dialect.name == "postgresql":
        db.execute(text("SELECT pg_advisory_xact_lock(72819403)"))


def deployment_allowed(db, device):
    from app.models import PolicyVersion
    version = db.get(PolicyVersion, device.policy_version_id) if device.policy_version_id else None
    return not version or version.document.get("allow_software_deployment", True)


@router.get("/agent/deployments/next")
def claim(request: Request, d=Depends(agent_identity), db=Depends(db_session)):
    from app.services.safety import endpoint_change_block
    if not request.app.state.settings.deployment_enabled or d.mode in (
        "AUDIT",
        "PREVIEW",
    ) or endpoint_change_block(request.app.state.settings, d):
        return {"task": None}
    if d.network_state in (
        "QUARANTINE_PENDING",
        "ERROR",
        "RESTRICTION_APPLIED_VERIFICATION_REQUIRED",
    ):
        return {"task": None}
    scheduler_lock(db)
    if db.scalar(
        select(BackgroundJob.id).where(
            BackgroundJob.device_id == d.id,
            BackgroundJob.kind == "MAINTENANCE",
            BackgroundJob.status == "RUNNING",
        )
    ):
        return {"task": None}
    # Expired work is ambiguous, never automatically replay a privileged installer.
    for task in db.scalars(
        select(DeploymentTask).where(
            DeploymentTask.state.in_(["RUNNING", "AWAITING_RESTART"]),
            DeploymentTask.lease_until < utcnow(),
        )
    ):
        task.state = "UNKNOWN"
    db.flush()
    if (
        db.scalar(
            select(func.count())
            .select_from(DeploymentTask)
            .where(DeploymentTask.state.in_(["RUNNING", "AWAITING_RESTART"]))
        )
        >= request.app.state.settings.deployment_concurrency
    ):
        return {"task": None}
    if db.scalar(
        select(DeploymentTask.id).where(
            DeploymentTask.device_id == d.id,
            DeploymentTask.state.in_(
                ["RUNNING", "AWAITING_RESTART", "REBOOT_REQUIRED"]
            ),
        )
    ):
        return {"task": None}
    t = db.scalar(
        select(DeploymentTask)
        .join(Deployment)
        .where(
            DeploymentTask.device_id == d.id,
            DeploymentTask.state == "PENDING",
            Deployment.cancelled.is_(False),
            Deployment.not_before <= utcnow(),
        )
        .order_by(DeploymentTask.created_at)
        .with_for_update(skip_locked=True)
        .limit(1)
    )
    if not t:
        return {"task": None}
    deployment = db.get(Deployment, t.deployment_id)
    package = db.get(SoftwarePackage, deployment.package_id)
    if not package.approved_by:
        return {"task": None}
    if package.kind != "agent_update" and not deployment_allowed(db, d):
        # The policy changed after the job was created; hold it rather than install or silently drop it.
        return {"task": None}
    t.state, t.attempt, t.lease_until = (
        "RUNNING",
        t.attempt + 1,
        utcnow() + timedelta(hours=2),
    )
    manifest = {
        "schema_version": 1,
        "task_id": t.id,
        "attempt": t.attempt,
        "device_id": d.id,
        "issued_at": utcnow().isoformat(),
        "package_id": package.id,
        "sha256": package.sha256,
        "size": package.size,
        "filename": package.filename,
        "kind": package.kind,
        "publisher_thumbprint": package.publisher_thumbprint,
        "metadata": package.metadata_,
        "action": deployment.action,
        "arguments": deployment.arguments,
        "expires_at": t.lease_until.isoformat() + "Z",
    }
    t.manifest = manifest
    audit(db, d.id, "deployment.claimed", t.id, attempt=t.attempt)
    return {"task": request.app.state.vault.signed(manifest)}


@router.get("/agent/deployments/pending-verification")
def pending_verification(
    request: Request, d=Depends(agent_identity), db=Depends(db_session)
):
    from sqlalchemy import or_, and_

    eligible = or_(
        DeploymentTask.state.in_(["REBOOT_REQUIRED", "AWAITING_RESTART"]),
        and_(
            DeploymentTask.state.in_(["RUNNING", "UNKNOWN"]),
            DeploymentTask.manifest["kind"].as_string() == "agent_update",
        ),
    )
    query = (
        select(DeploymentTask)
        .where(DeploymentTask.device_id == d.id, eligible)
        .order_by(DeploymentTask.created_at)
        .limit(10)
    )
    rows = db.scalars(query).all()
    return {
        "tasks": [
            request.app.state.vault.signed(
                {
                    "purpose": "verify_deployment",
                    "schema_version": 1,
                    "device_id": d.id,
                    "task_id": t.id,
                    "attempt": t.attempt,
                    "state": t.state,
                    "manifest": t.manifest,
                    "previous_boot_time": t.result.get("details", {}).get("boot_time"),
                    "expires_at": (utcnow() + timedelta(minutes=5)).isoformat() + "Z",
                }
            )
            for t in rows
        ]
    }


@router.get("/agent/deployments/{task_id}")
def agent_task(task_id: str, d=Depends(agent_identity), db=Depends(db_session)):
    t = db.get(DeploymentTask, task_id)
    if not t or t.device_id != d.id:
        raise HTTPException(404, "deployment.not_found")
    return {
        "state": t.state,
        "cancel_requested": db.get(Deployment, t.deployment_id).cancelled,
    }


class TaskResult(BaseModel):
    attempt: int
    state: Literal[
        "SUCCEEDED",
        "FAILED",
        "REBOOT_REQUIRED",
        "SKIPPED",
        "UNKNOWN",
        "CANCELLED",
        "AWAITING_RESTART",
    ]
    exit_code: int | None = None
    verified: bool = False
    log_tail: str = Field(default="", max_length=16000)
    details: dict = Field(default_factory=dict)


@router.post("/agent/deployments/{task_id}/result")
def task_result(
    task_id: str, body: TaskResult, d=Depends(agent_identity), db=Depends(db_session)
):
    t = db.get(DeploymentTask, task_id)
    if (
        t
        and t.device_id == d.id
        and (
            1 <= body.attempt < t.attempt
            or t.state in ("SUCCEEDED", "SKIPPED", "CANCELLED")
            and body.state != t.state
        )
    ):
        audit(db, d.id, "deployment.stale_result_ignored", t.id, attempt=body.attempt)
        return {"accepted": False, "superseded": True}
    if (
        not t
        or t.device_id != d.id
        or t.attempt != body.attempt
        or (
            t.state
            not in ("RUNNING", "AWAITING_RESTART", "REBOOT_REQUIRED", body.state)
            and not (
                t.state == "UNKNOWN"
                and t.manifest.get("kind") == "agent_update"
                and body.state == "SUCCEEDED"
            )
        )
    ):
        raise HTTPException(409, "deployment.invalid_result")
    # Installer exit 0 alone is never independently verified installation success.
    if body.state == "SUCCEEDED" and not body.verified:
        raise HTTPException(422, "deployment.verification_required")
    if body.state == "AWAITING_RESTART" and t.manifest.get("kind") != "agent_update":
        raise HTTPException(422, "deployment.invalid_result")
    if (
        t.state == "REBOOT_REQUIRED"
        and body.state == "SUCCEEDED"
        and not body.details.get("reboot_observed")
    ):
        raise HTTPException(422, "deployment.reboot_verification_required")
    t.state, t.result, t.lease_until = (
        body.state,
        {**body.model_dump(), "recorded_at": utcnow().isoformat()},
        None,
    )
    if body.state == "AWAITING_RESTART":
        t.lease_until = utcnow() + timedelta(minutes=30)
    audit(
        db, d.id, "deployment.result", t.id, state=body.state, exit_code=body.exit_code
    )
    return {"accepted": True, "assurance": "endpoint_reported"}


async def download_identity(request: Request, db=Depends(db_session, scope="function")):
    return await agent_identity(request, db)


@router.get("/agent/packages/{package_id}")
async def download(
    package_id: str,
    request: Request,
    d=Depends(download_identity),
    db=Depends(db_session, scope="function"),
):
    package = db.get(SoftwarePackage, package_id)
    authorized = db.scalar(
        select(DeploymentTask.id)
        .join(Deployment)
        .where(
            Deployment.package_id == package_id,
            DeploymentTask.device_id == d.id,
            DeploymentTask.state == "RUNNING",
            DeploymentTask.lease_until > utcnow(),
        )
    )
    if not package or not package.approved_by or not authorized:
        raise HTTPException(403, "package.not_authorized")
    start, end = 0, package.size - 1
    range_header = request.headers.get("range")
    if range_header:
        match = re.fullmatch(r"bytes=(\d+)-(\d*)", range_header)
        if not match:
            raise HTTPException(416, "package.invalid_range")
        start = int(match[1])
        end = min(int(match[2]) if match[2] else end, end)
        if not 0 <= start <= end < package.size:
            raise HTTPException(416, "package.invalid_range")
    path = paths(request) / "objects" / package.sha256
    if not path.is_file() or path.stat().st_size != package.size:
        raise HTTPException(409, "package.object_unavailable")
    rate = max(65536, request.app.state.settings.transfer_bytes_per_second)
    budget = request.app.state.transfers
    token = await budget.reserve(
        d.id, max(1, request.app.state.settings.transfer_concurrency)
    )
    total_rate = max(65536, request.app.state.settings.transfer_global_bytes_per_second)

    async def stream():
        try:
            with path.open("rb") as source:
                source.seek(start)
                remaining = end - start + 1
                while remaining:
                    chunk = await asyncio.to_thread(source.read, min(65536, remaining))
                    if not chunk:
                        break
                    remaining -= len(chunk)
                    await budget.throttle(len(chunk), total_rate)
                    yield chunk
                    await asyncio.sleep(len(chunk) / rate)
        finally:
            await budget.release(token)

    headers = {
        "Accept-Ranges": "bytes",
        "Content-Length": str(end - start + 1),
        "ETag": '"' + package.sha256 + '"',
        "Content-Type": "application/octet-stream",
    }
    if range_header:
        headers["Content-Range"] = f"bytes {start}-{end}/{package.size}"
    return StreamingResponse(
        stream(),
        status_code=206 if range_header else 200,
        headers=headers,
        background=BackgroundTask(budget.release, token),
    )
