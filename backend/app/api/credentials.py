"""Local Windows administrator credentials: legacy MAC-derived compatibility and random escrow.

Secrets leave the server only through `/reveal`, which needs the `credentials` permission, recent MFA
and a reason, and is audited without the secret. Nothing here changes an endpoint: setting or verifying
a password on Windows is done by an administrator, who then records the outcome.
"""

from typing import Literal
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from app.auth.dependencies import db_session, require, audit
from app.db import utcnow
from app.models import AdminCredential
from app.services.devices import device_or_404, normalize_mac
from app.services.legacy_credentials import (LEGACY_ACCOUNT, legacy_mac_v1, legacy_mac_candidates, legacy_state,
                                             random_password)

router = APIRouter(prefix="/devices/{device_id}/admin-credential", tags=["credentials"])


def _record(db, device_id):
    return db.scalar(select(AdminCredential).where(AdminCredential.device_id == device_id))


def _public(record):
    if not record:
        return None
    return {"id": record.id, "account": record.account, "scheme": record.scheme, "source_mac": record.source_mac,
            "status": record.status, "verified_at": record.verified_at, "verified_by": record.verified_by,
            "revision": record.revision, "created_at": record.created_at}


@router.get("")
def show(device_id: str, request: Request, admin=Depends(require("read")), db=Depends(db_session)):
    device = device_or_404(db, device_id)
    inventory = device.inventory or {}
    return {"credential": _public(_record(db, device_id)),
            "legacy": legacy_state(inventory, request.app.state.settings.public_origin),
            "candidates": legacy_mac_candidates(inventory.get("network_adapters"), device.primary_mac)}


class CredentialCreate(BaseModel):
    scheme: Literal["LEGACY_MAC_V1", "RANDOM_V1"]
    account: str = Field(default=LEGACY_ACCOUNT, pattern=r"^[A-Za-z][A-Za-z0-9_-]{0,19}$")
    source_mac: str | None = None
    replace: bool = False
    revision: int | None = None
    reason: str = Field(min_length=5, max_length=2000)


@router.post("", status_code=201)
def register(device_id: str, body: CredentialCreate, request: Request, admin=Depends(require("credentials", mfa=True)),
             db=Depends(db_session)):
    device = device_or_404(db, device_id)
    record = _record(db, device_id)
    if record and not body.replace:
        raise HTTPException(409, "credential.exists")
    if record and body.revision != record.revision:
        raise HTTPException(409, "credential.concurrent_change")
    mac, matched = None, None
    if body.scheme == "LEGACY_MAC_V1":
        try:
            mac = normalize_mac(body.source_mac or "")
        except ValueError:
            raise HTTPException(422, "credential.invalid_mac") from None
        known = {c["mac"] for c in legacy_mac_candidates((device.inventory or {}).get("network_adapters"), device.primary_mac)}
        matched = mac in known
    record = record or AdminCredential(device_id=device.id, revision=0)
    record.account, record.scheme, record.source_mac = body.account, body.scheme, mac
    # A random password is not on the machine until an administrator sets it there.
    record.secret = request.app.state.vault.seal(random_password()) if body.scheme == "RANDOM_V1" else None
    record.status = "PENDING_APPLY" if body.scheme == "RANDOM_V1" else "UNVERIFIED"
    record.verified_at = record.verified_by = None
    record.revision += 1
    db.add(record)
    db.flush()
    audit(db, admin.id, "credential.registered", device.id, scheme=body.scheme, account=body.account,
          source_mac=mac, mac_matches_inventory=matched, replaced=body.replace, reason=body.reason)
    return _public(record)


class Reveal(BaseModel):
    reason: str = Field(min_length=5, max_length=2000)


@router.post("/reveal")
def reveal(device_id: str, body: Reveal, request: Request, response: Response, admin=Depends(require("credentials", mfa="always")),
           db=Depends(db_session)):
    record = _record(db, device_id)
    if not record or record.status == "RETIRED":
        raise HTTPException(404, "credential.not_found")
    password = legacy_mac_v1(record.source_mac) if record.scheme == "LEGACY_MAC_V1" else request.app.state.vault.open(record.secret)
    response.headers["Cache-Control"] = "no-store"
    audit(db, admin.id, "credential.revealed", device_id, scheme=record.scheme, account=record.account, reason=body.reason)
    return {"account": record.account, "scheme": record.scheme, "status": record.status, "password": password}


class Verification(BaseModel):
    result: Literal["VERIFIED", "FAILED", "RETIRED"]
    revision: int
    reason: str = Field(min_length=5, max_length=2000)


@router.post("/verification")
def verification(device_id: str, body: Verification, admin=Depends(require("credentials", mfa=True)),
                 db=Depends(db_session)):
    record = _record(db, device_id)
    if not record:
        raise HTTPException(404, "credential.not_found")
    if record.revision != body.revision:
        raise HTTPException(409, "credential.concurrent_change")
    record.status = body.result
    record.verified_at, record.verified_by = utcnow(), admin.id
    record.revision += 1
    audit(db, admin.id, "credential.verification_recorded", device_id, result=body.result, reason=body.reason)
    return _public(record)

