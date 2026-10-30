import csv
import io
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field, field_validator, model_validator
from sqlalchemy import select
from app.auth.dependencies import db_session, require, agent_identity, audit
from app.db import utcnow
from app.models import Device, UserIdentity, OwnerAssignment, GroupMember
from app.services.devices import device_or_404

router = APIRouter(tags=["identity"])


class UserReport(BaseModel):
    windows_sid: str = Field(pattern=r"^S-1-5-[0-9-]{1,160}$")
    windows_account: str = Field(min_length=1, max_length=256)
    # Clients from 0.3 send first and last name separately; older ones send only full_name.
    full_name: str | None = Field(default=None, min_length=2, max_length=256)
    first_name: str | None = Field(default=None, min_length=1, max_length=128)
    last_name: str | None = Field(default=None, min_length=1, max_length=128)
    military_rank: str | None = Field(default=None, max_length=128)
    no_military_rank: bool = False

    @field_validator("full_name", "first_name", "last_name", "military_rank", "windows_account")
    @classmethod
    def clean(cls, value):
        if value is not None and any(ord(c) < 32 for c in value):
            raise ValueError("identity.invalid_text")
        return value.strip() if value else value

    @model_validator(mode="after")
    def names(self):
        if bool(self.first_name) != bool(self.last_name):
            raise ValueError("identity.first_and_last_name_required")
        if self.first_name:
            self.full_name = f"{self.first_name} {self.last_name}"
        if not self.full_name or len(self.full_name) < 2:
            raise ValueError("identity.name_required")
        return self


@router.post("/agent/identity")
def report(body: UserReport, d=Depends(agent_identity), db=Depends(db_session)):
    identity = db.scalar(
        select(UserIdentity).where(
            UserIdentity.device_id == d.id, UserIdentity.windows_sid == body.windows_sid
        )
    )
    if not identity:
        identity = UserIdentity(
            device_id=d.id,
            windows_sid=body.windows_sid,
            windows_account=body.windows_account,
            full_name=body.full_name,
        )
        db.add(identity)
    changed = identity.full_name != body.full_name or identity.military_rank != (
        None if body.no_military_rank else body.military_rank
    )
    changed |= (identity.first_name, identity.last_name) != (body.first_name, body.last_name) and body.first_name is not None
    identity.windows_account, identity.full_name = body.windows_account, body.full_name
    if body.first_name:
        identity.first_name, identity.last_name = body.first_name, body.last_name
    identity.military_rank = None if body.no_military_rank else body.military_rank
    identity.updated_at = utcnow()
    if changed:
        identity.verified_by = None
    d.last_user_account, d.last_user_sid, d.last_user_seen = (
        body.windows_account,
        body.windows_sid,
        utcnow(),
    )
    # Submission is a claim from a logged-in user; it never assigns permanent ownership.
    d.identity_status = "USER_REPORTED"
    audit(db, d.id, "identity.submitted", d.id, windows_sid=body.windows_sid)
    return {"accepted": True, "status": "USER_REPORTED"}


@router.get("/agent/identity-status")
def identity_status(
    windows_sid: str, d=Depends(agent_identity), db=Depends(db_session)
):
    found = db.scalar(
        select(UserIdentity.id).where(
            UserIdentity.device_id == d.id, UserIdentity.windows_sid == windows_sid
        )
    )
    return {"submitted": bool(found), "default_language": "hy"}


@router.get("/devices/{device_id}/identities")
def identities(device_id: str, admin=Depends(require("read")), db=Depends(db_session)):
    device_or_404(db, device_id)
    return [
        {
            "id": u.id,
            "windows_sid": u.windows_sid,
            "windows_account": u.windows_account,
            "full_name": u.full_name,
            "military_rank": u.military_rank,
            "verified": bool(u.verified_by),
            "submitted_at": u.created_at,
            "updated_at": u.updated_at,
        }
        for u in db.scalars(
            select(UserIdentity).where(UserIdentity.device_id == device_id)
        )
    ]


class OwnerEdit(BaseModel):
    full_name: str | None = Field(default=None, max_length=256)
    first_name: str | None = Field(default=None, max_length=128)
    last_name: str | None = Field(default=None, max_length=128)
    military_rank: str | None = Field(default=None, max_length=128)
    windows_account: str | None = Field(default=None, max_length=256)
    verified: bool = False
    reason: str = Field(min_length=5, max_length=2000)


@router.put("/devices/{device_id}/owner")
def owner(
    device_id: str,
    body: OwnerEdit,
    admin=Depends(require("manage")),
    db=Depends(db_session),
):
    d = device_or_404(db, device_id)
    if body.verified and not body.full_name:
        raise HTTPException(422, "identity.name_required")
    d.owner_name, d.owner_rank, d.owner_account, d.owner_verified = (
        body.full_name,
        body.military_rank,
        body.windows_account,
        body.verified,
    )
    db.add(
        OwnerAssignment(
            device_id=d.id,
            full_name=body.full_name,
            military_rank=body.military_rank,
            windows_account=body.windows_account,
            verified=body.verified,
            author_id=admin.id,
            reason=body.reason,
        )
    )
    d.revision += 1
    audit(
        db, admin.id, "owner.assigned", d.id, verified=body.verified, reason=body.reason
    )
    return {"ok": True}


@router.patch("/devices/{device_id}/identities/{identity_id}")
def correct_identity(
    device_id: str,
    identity_id: str,
    body: OwnerEdit,
    admin=Depends(require("manage")),
    db=Depends(db_session),
):
    u = db.get(UserIdentity, identity_id)
    if body.first_name and body.last_name:
        body.full_name = f"{body.first_name.strip()} {body.last_name.strip()}"
    if not u or u.device_id != device_id or not body.full_name:
        raise HTTPException(404, "identity.not_found")
    u.full_name, u.military_rank = body.full_name, body.military_rank
    if body.first_name and body.last_name:
        u.first_name, u.last_name = body.first_name.strip(), body.last_name.strip()
    u.verified_by, u.updated_at = admin.id if body.verified else None, utcnow()
    audit(
        db,
        admin.id,
        "identity.corrected",
        device_id,
        identity_id=u.id,
        reason=body.reason,
        verified=body.verified,
    )
    return {"ok": True}


@router.get("/devices/{device_id}/owner-history")
def assignments(device_id: str, admin=Depends(require("read")), db=Depends(db_session)):
    return [
        {
            "id": h.id,
            "full_name": h.full_name,
            "military_rank": h.military_rank,
            "windows_account": h.windows_account,
            "verified": h.verified,
            "at": h.created_at,
            "author_id": h.author_id,
            "reason": h.reason,
        }
        for h in db.scalars(
            select(OwnerAssignment)
            .where(OwnerAssignment.device_id == device_id)
            .order_by(OwnerAssignment.created_at.desc())
            .limit(100)
        )
    ]


@router.get("/inventory/export")
def export(
    request: Request,
    group_id: str | None = None,
    admin=Depends(require("manage")),
    db=Depends(db_session),
):
    query = select(Device).order_by(Device.hostname)
    if group_id:
        query = query.where(
            Device.id.in_(
                select(GroupMember.device_id).where(GroupMember.group_id == group_id)
            )
        )

    def safe(value):
        text = str(value or "")
        return "'" + text if text.startswith(("=", "+", "-", "@", "\t", "\r")) else text

    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(
        [
            "device_uuid",
            "hostname",
            "owner_name",
            "military_rank",
            "verified",
            "last_user",
            "mac",
            "state",
        ]
    )
    for d in db.scalars(query.limit(10000)):
        writer.writerow(
            [
                safe(v)
                for v in [
                    d.id,
                    d.hostname,
                    d.owner_name,
                    d.owner_rank,
                    d.owner_verified,
                    d.last_user_account,
                    d.primary_mac,
                    d.state,
                ]
            ]
        )
    audit(db, admin.id, "inventory.exported", group_id or "all")
    return Response(
        "\ufeff" + output.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="suro-inventory.csv"'},
    )
