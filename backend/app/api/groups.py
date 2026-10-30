from datetime import timedelta
from typing import Literal
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select, delete
from app.auth.dependencies import db_session, require, audit
from app.db import utcnow
from app.models import (
    DeviceGroup,
    GroupMember,
    PolicyOverride,
    PolicyVersion,
    Policy,
    NetworkBatch,
    OperationTarget,
    BackgroundJob,
)
from app.policies.resolver import resolve
from app.services.devices import device_or_404

router = APIRouter(tags=["device groups"])


class GroupEdit(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    description: str = Field(default="", max_length=2000)
    device_ids: list[str] = Field(default_factory=list, max_length=10000)


def get_group(db, group_id):
    group = db.get(DeviceGroup, group_id)
    if not group:
        raise HTTPException(404, "group.not_found")
    return group


def compile_members(db, request, ids, admin):
    from app.api.policies import new_version

    for device_id in ids:
        d = device_or_404(db, device_id)
        if not d.policy_version_id:
            continue
        current = db.get(PolicyVersion, d.policy_version_id)
        p = db.scalar(
            select(Policy).where(Policy.id == current.policy_id).with_for_update()
        )
        baseline = db.get(PolicyVersion, p.active_version_id)
        effective = resolve(db, p.id, baseline.document, d)
        if effective != current.document:
            d.policy_version_id = new_version(
                db, request, p, effective, admin, "Device group membership changed"
            ).id
        d.state, d.compliance_score, d.last_verified = "UNVERIFIED", 0, None
        d.revision += 1


@router.get("/groups")
def groups(admin=Depends(require("read")), db=Depends(db_session)):
    members = {}
    for row in db.scalars(select(GroupMember)):
        members.setdefault(row.group_id, []).append(row.device_id)
    return [
        {
            "id": g.id,
            "name": g.name,
            "description": g.description,
            "device_ids": members.get(g.id, []),
        }
        for g in db.scalars(select(DeviceGroup).order_by(DeviceGroup.name))
    ]


@router.post("/groups")
def create(
    body: GroupEdit,
    request: Request,
    admin=Depends(require("approve", mfa=True)),
    db=Depends(db_session),
):
    g = DeviceGroup(name=body.name, description=body.description)
    db.add(g)
    db.flush()
    for device_id in set(body.device_ids):
        device_or_404(db, device_id)
        db.add(GroupMember(group_id=g.id, device_id=device_id))
    audit(db, admin.id, "group.created", g.id, device_ids=body.device_ids)
    return {"id": g.id}


@router.put("/groups/{group_id}")
def edit(
    group_id: str,
    body: GroupEdit,
    request: Request,
    admin=Depends(require("approve", mfa=True)),
    db=Depends(db_session),
):
    g = get_group(db, group_id)
    before = set(
        db.scalars(select(GroupMember.device_id).where(GroupMember.group_id == g.id))
    )
    for device_id in set(body.device_ids):
        device_or_404(db, device_id)
    db.execute(delete(GroupMember).where(GroupMember.group_id == g.id))
    g.name, g.description = body.name, body.description
    for device_id in set(body.device_ids):
        db.add(GroupMember(group_id=g.id, device_id=device_id))
    db.flush()
    compile_members(db, request, before | set(body.device_ids), admin)
    audit(
        db,
        admin.id,
        "group.updated",
        g.id,
        before=sorted(before),
        after=body.device_ids,
    )
    return {"ok": True}


@router.delete("/groups/{group_id}")
def remove(
    group_id: str,
    request: Request,
    admin=Depends(require("approve", mfa=True)),
    db=Depends(db_session),
):
    g = get_group(db, group_id)
    ids = set(
        db.scalars(
            select(GroupMember.device_id).where(GroupMember.group_id == group_id)
        )
    )
    db.execute(delete(GroupMember).where(GroupMember.group_id == group_id))
    db.execute(delete(PolicyOverride).where(PolicyOverride.group_id == group_id))
    db.flush()
    compile_members(db, request, ids, admin)
    audit(db, admin.id, "group.deleted", g.id, name=g.name, device_ids=sorted(ids))
    db.delete(g)
    return {"ok": True}


class GroupOperation(BaseModel):
    operation: Literal["SYNC", "POLICY", "EXCEPTION", "MAINTENANCE"]
    parameters: dict = Field(default_factory=dict)
    reason: str = Field(min_length=5, max_length=2000)


@router.post("/groups/{group_id}/operations")
def operation(
    group_id: str,
    body: GroupOperation,
    request: Request,
    admin=Depends(require("approve", mfa=True)),
    db=Depends(db_session),
):
    get_group(db, group_id)
    ids = list(
        db.scalars(
            select(GroupMember.device_id).where(GroupMember.group_id == group_id)
        )
    )
    if not ids:
        raise HTTPException(409, "group.empty")
    if body.operation == "POLICY" and not all(
        k in body.parameters for k in ("policy_id", "version_id")
    ):
        raise HTTPException(422, "policy.assignment_required")
    batch = NetworkBatch(
        kind="ENDPOINT",
        operation=body.operation,
        state="APPROVED",
        parameters=body.parameters,
        reason=body.reason,
        author_id=admin.id,
        approved_at=utcnow(),
    )
    db.add(batch)
    db.flush()
    for device_id in ids:
        d = device_or_404(db, device_id)
        target = OperationTarget(
            batch_id=batch.id,
            device_id=d.id,
            state="QUEUED",
            deadline=utcnow() + timedelta(hours=2),
        )
        db.add(target)
        if d.device_class == "DEVELOPER" or not d.enabled:
            target.state, target.result = "SKIPPED", {"code": "device.unmanaged"}
            continue
        if body.operation == "SYNC":
            d.revision += 1
            db.add(BackgroundJob(device_id=d.id, kind="SYNC"))
        elif body.operation == "POLICY":
            from app.api.policies import assign, Assignment

            assign(
                body.parameters["policy_id"],
                Assignment(device_ids=[d.id], version_id=body.parameters["version_id"]),
                request,
                admin,
                db,
            )
            target.preview = {"version_id": d.policy_version_id}
        elif body.operation == "EXCEPTION":
            from app.api.devices import add_exception, ExceptionCreate

            target.result = add_exception(
                d.id,
                ExceptionCreate(**{**body.parameters, "reason": body.reason}),
                admin,
                db,
            )
            target.state = "SUCCEEDED"
        else:
            from app.api.maintenance import create, Maintenance

            result = create(
                d.id,
                Maintenance(**{**body.parameters, "reason": body.reason}),
                request,
                admin,
                db,
            )
            target.preview = {"job_id": result["id"]}
            job=db.get(BackgroundJob,result['id'])
            target.deadline=max(target.deadline,job.available_at+timedelta(hours=2))
    audit(
        db,
        admin.id,
        "group.operation_created",
        group_id,
        batch_id=batch.id,
        operation=body.operation,
        targets=ids,
    )
    return {"id": batch.id, "targets": len(ids), "state": "APPROVED"}


@router.get("/devices/{device_id}/effective-policy")
def effective(device_id: str, admin=Depends(require("read")), db=Depends(db_session)):
    d = device_or_404(db, device_id)
    current = (
        db.get(PolicyVersion, d.policy_version_id) if d.policy_version_id else None
    )
    if not current:
        return {"assigned": None, "effective": None, "conflicts": []}
    p = db.get(Policy, current.policy_id)
    baseline = db.get(PolicyVersion, p.active_version_id)
    try:
        value, conflicts = resolve(db, p.id, baseline.document, d), []
    except ValueError as exc:
        value, conflicts = None, [str(exc)]
    from app.policies.resolver import applicable_layers
    return {
        "assigned": current.document,
        "version_id": current.id,
        "policy_id": p.id,
        "policy_name": p.name,
        # The UI explains each value: the policy sets it unless a later layer here overrides it.
        "layers": applicable_layers(db, p.id, d),
        "effective": value,
        "conflicts": conflicts,
        "group_ids": list(
            db.scalars(
                select(GroupMember.group_id).where(GroupMember.device_id == d.id)
            )
        ),
    }
