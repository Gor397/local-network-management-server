"""Mandatory Suro Client network admission: policy, pilot computers, gate plans, overrides and overview.

Requested changes (overrides, toggles) and router-confirmed state are reported separately; see
services/admission_gate.py for the mechanism and its limits.
"""

import json
from datetime import timedelta
from typing import Literal
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from app.auth.dependencies import audit, db_session, require
from app.db import utcnow
from app.models import (AuditLog, Device, DeviceCredential, Enrollment, NetworkAdmission, NetworkInterface, NetworkPlan,
                        Router, UserIdentity)
from app.services import admission_gate as gate
from app.services.admission_sync import credential_active, get_policy
from app.services.devices import device_or_404, effective_state, normalize_mac
from app.security.crypto import digest

router = APIRouter(tags=["admission"])


def _policy(p):
    return {k: getattr(p, k) for k in ("mode", "group_ids", "require_enrollment", "require_running_agent", "require_compliance",
                                       "exempt_developers", "heartbeat_timeout_seconds", "grace_seconds", "auto_revoke",
                                       "onboarding_enabled", "outage_policy", "revision", "updated_at")}


@router.get("/admission/policy")
def read_policy(admin=Depends(require("read")), db=Depends(db_session)):
    return _policy(get_policy(db))


class PolicyUpdate(BaseModel):
    mode: Literal["DISABLED", "PILOT", "GROUPS", "ALL"]
    require_enrollment: bool = True
    require_running_agent: bool = True
    require_compliance: bool = False
    exempt_developers: bool = True
    heartbeat_timeout_seconds: int = Field(default=300, ge=60, le=3600)
    grace_seconds: int = Field(default=300, ge=0, le=3600)
    auto_revoke: bool = True
    onboarding_enabled: bool = True
    outage_policy: Literal["EXPIRE", "HOLD"] = "EXPIRE"
    revision: int
    reason: str = Field(min_length=5, max_length=2000)


@router.put("/admission/policy")
def update_policy(body: PolicyUpdate, admin=Depends(require("approve", mfa=True)), db=Depends(db_session)):
    policy = get_policy(db)
    if body.revision != policy.revision:
        raise HTTPException(409, "admission.concurrent_change")
    if body.mode in ("GROUPS", "ALL"):
        # Network-wide gating needs subnet-level rules and a staged rollout that are not implemented yet.
        raise HTTPException(409, "admission.mode_requires_staged_rollout")
    if not body.require_enrollment and not body.require_running_agent and not body.require_compliance:
        raise HTTPException(422, "admission.no_requirement")
    for key, value in body.model_dump(exclude={"revision", "reason"}).items():
        setattr(policy, key, value)
    policy.revision += 1
    policy.updated_by, policy.updated_at = admin.id, utcnow()
    audit(db, admin.id, "admission.policy_updated", "admission-policy", **body.model_dump(exclude={"revision"}))
    return _policy(policy)


class PilotCreate(BaseModel):
    mac: str
    router_id: str
    hostname: str | None = Field(default=None, min_length=1, max_length=128)
    reason: str = Field(min_length=5, max_length=2000)


@router.post("/admission/pilot", status_code=201)
def add_pilot(body: PilotCreate, request: Request, admin=Depends(require("approve", mfa=True)), db=Depends(db_session)):
    try:
        mac = normalize_mac(body.mac)
    except ValueError:
        raise HTTPException(422, "device.invalid_mac") from None
    r = db.get(Router, body.router_id)
    if not r or r.archived:
        raise HTTPException(404, "router.not_found")
    device = db.scalar(select(Device).where(Device.primary_mac == mac))
    if not device:
        interface = db.scalar(select(NetworkInterface).where(NetworkInterface.mac == mac))
        device = db.get(Device, interface.device_id) if interface else None
    if not device:
        device = Device(hostname=body.hostname or "PILOT-" + mac.replace(":", "")[-6:], primary_mac=mac, state="PENDING_ENROLLMENT")
        db.add(device)
        db.flush()
        audit(db, admin.id, "device.created", device.id, device_class="STANDARD", source="admission_pilot")
    if device.device_class in ("DEVELOPER", "INFRASTRUCTURE") or device.admission_exempt or not device.enabled:
        raise HTTPException(409, "admission.device_exempt")
    if device.primary_mac != mac:
        raise HTTPException(409, "admission.use_primary_mac")
    admission = db.scalar(select(NetworkAdmission).where(NetworkAdmission.device_id == device.id))
    if not admission:
        admission = NetworkAdmission(device_id=device.id, source="PILOT", revision=0)
        db.add(admission)
    if admission.gate_state == "INSTALLED" and admission.router_id != r.id:
        raise HTTPException(409, "admission.remove_gate_first")
    admission.router_id, admission.enabled = r.id, True
    admission.revision += 1
    db.flush()
    audit(db, admin.id, "admission.pilot_added", device.id, mac=mac, router_id=r.id, reason=body.reason)
    return detail(device.id, request, admin, db)


async def _snapshot(request, r):
    """Read the router now: a plan must describe the current configuration, not the last discovery."""
    import asyncio
    from app.services.network import connector
    try:
        async with connector(request.app, r) as api:
            snapshot = (await asyncio.wait_for(api.discovery(), timeout=90))["snapshot"]
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from None
    except Exception:
        raise HTTPException(502, "admission.router_unreachable") from None
    r.snapshot = request.app.state.vault.seal(json.dumps(snapshot))
    return snapshot


def _admission(db, device_id):
    admission = db.scalar(select(NetworkAdmission).where(NetworkAdmission.device_id == device_id))
    if not admission:
        raise HTTPException(404, "admission.not_found")
    return admission


class Reason(BaseModel):
    reason: str = Field(min_length=5, max_length=2000)


def _plan(db, device, r, snapshot, operations, admin, reason, kind):
    from app.mikrotik.connector import snapshot_hash
    plan = NetworkPlan(device_id=device.id, router_id=r.id, generation=r.generation, snapshot_hash=snapshot_hash(snapshot),
                       operations=operations, reason=reason, author_id=admin.id, result={"admission": None, "kind": kind})
    db.add(plan)
    db.flush()
    return plan


def _readable(operations):
    return [{"action": op["method"], "path": op["path"], **({"rule": {k: v for k, v in op["data"].items() if k != "place-before"}} if "data" in op else {}),
             **({"owned_comment": op["owned_comment"]} if "owned_comment" in op else {})} for op in operations]


@router.post("/admission/devices/{device_id}/gate-preview")
async def gate_preview(device_id: str, body: Reason, request: Request, admin=Depends(require("approve", mfa=True)), db=Depends(db_session)):
    device = device_or_404(db, device_id)
    admission = _admission(db, device.id)
    r = db.get(Router, admission.router_id)
    snapshot = await _snapshot(request, r)
    server = gate.server_address(request.app.state.settings)
    report = gate.feasibility(r, snapshot, device, server)
    result = {"feasibility": report, "rollback_commands": gate.rollback_commands(device), "plan": None}
    if report["blockers"]:
        return result
    operations = gate.gate_plan(device, server, snapshot)
    if not operations:
        admission.gate_state = "INSTALLED"
        return {**result, "already_installed": True}
    plan = _plan(db, device, r, snapshot, operations, admin, body.reason, "admission_gate")
    admission.gate_state, admission.gate_plan_id = "PREVIEW", plan.id
    audit(db, admin.id, "admission.gate_previewed", device.id, plan_id=plan.id, warnings=report["warnings"])
    return {**result, "plan": {"id": plan.id, "operations": _readable(operations), "expires_in_seconds": 600}}


@router.post("/admission/devices/{device_id}/removal-preview")
async def removal_preview(device_id: str, body: Reason, request: Request, admin=Depends(require("approve", mfa=True)), db=Depends(db_session)):
    device = device_or_404(db, device_id)
    admission = _admission(db, device.id)
    r = db.get(Router, admission.router_id)
    snapshot = await _snapshot(request, r)
    operations = gate.removal_plan(device, snapshot)
    if not operations:
        admission.gate_state, admission.applied, admission.granted_ip, admission.grant_expires_at = "NOT_INSTALLED", "NONE", None, None
        return {"plan": None, "already_removed": True, "rollback_commands": gate.rollback_commands(device)}
    plan = _plan(db, device, r, snapshot, operations, admin, body.reason, "admission_removal")
    # Freeze grant refreshes so the router still matches this plan when it is applied.
    admission.gate_state = "REMOVING"
    audit(db, admin.id, "admission.removal_previewed", device.id, plan_id=plan.id)
    return {"plan": {"id": plan.id, "operations": _readable(operations), "expires_in_seconds": 600},
            "rollback_commands": gate.rollback_commands(device)}


class Apply(BaseModel):
    plan_id: str
    reason: str = Field(min_length=5, max_length=2000)


@router.post("/admission/devices/{device_id}/apply")
async def apply(device_id: str, body: Apply, request: Request, admin=Depends(require("approve", mfa=True)), db=Depends(db_session)):
    from app.services.network import execute_plan
    device = device_or_404(db, device_id)
    admission = _admission(db, device.id)
    plan = db.get(NetworkPlan, body.plan_id)
    kind = (plan.result or {}).get("kind") if plan else None
    if not plan or plan.device_id != device.id or kind not in ("admission_gate", "admission_removal"):
        raise HTTPException(404, "network.plan_not_found")
    audit(db, admin.id, "admission.apply_requested", device.id, plan_id=plan.id, kind=kind, reason=body.reason)
    result = await execute_plan(request.app, db, plan, admin.id)
    admission = _admission(db, device.id)
    if result["state"] == "VERIFIED":
        if kind == "admission_gate":
            admission.gate_state, admission.error = "INSTALLED", None
        else:
            admission.gate_state, admission.applied, admission.granted_ip, admission.grant_expires_at = "NOT_INSTALLED", "NONE", None, None
            admission.error = None
    elif result["state"] == "ERROR":
        # A failed removal keeps the gate (and its grants) managed, so access is not silently lost.
        admission.gate_state = "INSTALLED" if kind == "admission_removal" else "ERROR"
        admission.error = (result.get("result") or {}).get("error", "admission.router_error")
    admission.revision += 1
    db.commit()
    return {"state": result["state"], "kind": kind, "admission": _row(db, request, device, admission)}


class Toggle(BaseModel):
    enabled: bool
    reason: str = Field(min_length=5, max_length=2000)


@router.patch("/admission/devices/{device_id}")
def toggle(device_id: str, body: Toggle, admin=Depends(require("approve", mfa=True)), db=Depends(db_session)):
    admission = _admission(db, device_id)
    admission.enabled = body.enabled
    admission.revision += 1
    audit(db, admin.id, "admission.requirement_changed", device_id, enabled=body.enabled, reason=body.reason)
    return {"enabled": admission.enabled, "applied_by_worker": True}


class Override(BaseModel):
    action: Literal["AUTHORIZE", "RESTRICT", "CLEAR"]
    minutes: int | None = Field(default=None, ge=5, le=10080)
    reason: str = Field(min_length=5, max_length=2000)


@router.post("/admission/devices/{device_id}/override")
def override(device_id: str, body: Override, admin=Depends(require("approve", mfa=True)), db=Depends(db_session)):
    admission = _admission(db, device_id)
    admission.override = None if body.action == "CLEAR" else body.action
    admission.override_until = utcnow() + timedelta(minutes=body.minutes) if body.minutes and body.action != "CLEAR" else None
    admission.revision += 1
    audit(db, admin.id, "admission.override_requested", device_id, action=body.action, minutes=body.minutes, reason=body.reason)
    return {"requested": body.action, "applied": admission.applied, "note": "admission.applied_by_worker"}


class Window(BaseModel):
    minutes: int = Field(default=120, ge=5, le=1440)
    reason: str = Field(min_length=5, max_length=2000)


@router.post("/admission/devices/{device_id}/onboarding-window")
def onboarding_window(device_id: str, body: Window, admin=Depends(require("approve", mfa=True)), db=Depends(db_session)):
    """Lets a portal-installed client of this computer ask to enroll; an administrator still approves it."""
    if not get_policy(db).onboarding_enabled:
        raise HTTPException(409, "admission.onboarding_disabled")
    admission = _admission(db, device_id)
    admission.onboarding_until = utcnow() + timedelta(minutes=body.minutes)
    audit(db, admin.id, "admission.onboarding_opened", device_id, minutes=body.minutes, reason=body.reason)
    return {"onboarding_until": admission.onboarding_until}


@router.post("/devices/{device_id}/reset-enrollment")
def reset_enrollment(device_id: str, body: Reason, admin=Depends(require("approve", mfa=True)), db=Depends(db_session)):
    """Reinstalled Windows or a new disk: retire the old identity so it can never be reused, keep history."""
    device = device_or_404(db, device_id)
    revoked = 0
    for credential in db.scalars(select(DeviceCredential).where(DeviceCredential.device_id == device.id, DeviceCredential.revoked.is_(False))):
        credential.revoked, revoked = True, revoked + 1
    for enrollment in db.scalars(select(Enrollment).where(Enrollment.device_id == device.id, Enrollment.approved.is_(False))):
        enrollment.expires_at = utcnow()
    device.state, device.last_verified, device.compliance_score, device.agent_features = "PENDING_ENROLLMENT", None, 0, []
    device.revision += 1
    audit(db, admin.id, "enrollment.reset", device.id, revoked_credentials=revoked, reason=body.reason)
    return {"revoked_credentials": revoked, "state": device.state}


class Exemption(BaseModel):
    exempt: bool
    device_class: Literal["STANDARD", "ADMINISTRATOR", "DEVELOPER", "INFRASTRUCTURE", "OTHER"] | None = None
    reason: str = Field(min_length=5, max_length=2000)


@router.put("/devices/{device_id}/admission-exemption")
def exemption(device_id: str, body: Exemption, admin=Depends(require("approve", mfa=True)), db=Depends(db_session)):
    """Only administrators set this; a computer can never declare itself exempt."""
    device = device_or_404(db, device_id)
    if body.device_class and body.device_class != device.device_class:
        if "DEVELOPER" in (body.device_class, device.device_class):
            # Developer devices have no agent identity; moving into or out of that class re-enrolls.
            raise HTTPException(409, "device.reenrollment_required")
        device.device_class = body.device_class
    device.admission_exempt, device.exemption_reason = body.exempt, body.reason if body.exempt else None
    device.revision += 1
    audit(db, admin.id, "admission.exemption_changed", device.id, exempt=body.exempt, device_class=device.device_class, reason=body.reason)
    return {"exempt": device.admission_exempt, "device_class": device.device_class}


def _client_state(db, device):
    if device.device_class == "DEVELOPER":
        return "NOT_APPLICABLE"
    if credential_active(db, device):
        return "ENROLLED"
    pending = db.scalar(select(Enrollment.id).where(Enrollment.device_id == device.id, Enrollment.csr.is_not(None),
                                                     Enrollment.approved.is_(False), Enrollment.expires_at > utcnow()))
    return "ENROLLMENT_PENDING" if pending else "NOT_ENROLLED"


def _agent_state(device, policy):
    if not device.last_heartbeat:
        return "NEVER"
    age = (utcnow() - device.last_heartbeat).total_seconds()
    if age > policy.heartbeat_timeout_seconds:
        return "DISCONNECTED"
    claim = (device.inventory or {}).get("claims", {}).get("agent.service_running", {})
    return "UNHEALTHY" if claim.get("status") == "FAIL" else "CONNECTED"


def _identity(db, device):
    i = db.scalar(select(UserIdentity).where(UserIdentity.device_id == device.id).order_by(UserIdentity.updated_at.desc()))
    return {"first_name": i.first_name, "last_name": i.last_name, "full_name": i.full_name, "military_rank": i.military_rank,
            "verified": bool(i.verified_by), "id": i.id} if i else None


def _row(db, request, device, admission, policy=None):
    policy = policy or get_policy(db)
    desired, reason = gate.evaluate(device, admission, policy, credential_active(db, device),
                                    effective_state(device, request.app.state.settings)[0])
    credential = db.scalar(select(DeviceCredential).where(DeviceCredential.device_id == device.id, DeviceCredential.revoked.is_(False))
                           .order_by(DeviceCredential.created_at.desc()))
    evidence = device.network_evidence or {}
    return {
        "device_id": device.id, "hostname": device.hostname, "mac": device.primary_mac, "device_class": device.device_class,
        "exempt": device.admission_exempt or (device.device_class == "DEVELOPER" and policy.exempt_developers),
        "exemption_reason": device.exemption_reason, "client": _client_state(db, device), "agent": _agent_state(device, policy),
        "agent_version": device.agent_version, "last_heartbeat": device.last_heartbeat, "registered_at": device.created_at,
        "enrollment_id": credential.fingerprint[:16] if credential else None, "user": _identity(db, device),
        "required": bool(admission and admission.enabled), "desired": desired, "reason": reason,
        "network": gate.network_state(admission, desired),
        "gate_state": admission.gate_state if admission else None, "router_id": admission.router_id if admission else None,
        "applied": admission.applied if admission else None, "applied_at": admission.applied_at if admission else None,
        "granted_ip": admission.granted_ip if admission else None, "grant_expires_at": admission.grant_expires_at if admission else None,
        "reported_ip": admission.reported_ip if admission else None, "error": admission.error if admission else None,
        "override": admission.override if admission else None, "override_until": admission.override_until if admission else None,
        "onboarding_until": admission.onboarding_until if admission else None,
        "connected_ap": evidence.get("ap") if evidence.get("connected") else None,
    }


@router.get("/admission/overview")
def overview(request: Request, q: str = "", only_required: bool = False, admin=Depends(require("read")), db=Depends(db_session)):
    policy = get_policy(db)
    admissions = {a.device_id: a for a in db.scalars(select(NetworkAdmission))}
    query = select(Device).where(Device.enabled.is_(True))
    if q:
        needle = f"%{q[:128]}%"
        query = query.where(Device.hostname.ilike(needle) | Device.primary_mac.ilike(needle) | Device.owner_name.ilike(needle))
    if only_required:
        query = query.where(Device.id.in_(admissions))
    rows = [_row(db, request, d, admissions.get(d.id), policy) for d in db.scalars(query.order_by(Device.hostname).limit(500))]
    counts = {key: sum(r["client"] == key for r in rows) for key in ("ENROLLED", "ENROLLMENT_PENDING", "NOT_ENROLLED")}
    return {"policy": _policy(policy), "counts": counts, "items": rows}


@router.get("/admission/devices/{device_id}")
def detail(device_id: str, request: Request, admin=Depends(require("read")), db=Depends(db_session)):
    device = device_or_404(db, device_id)
    admission = db.scalar(select(NetworkAdmission).where(NetworkAdmission.device_id == device.id))
    logs = db.scalars(select(AuditLog).where(AuditLog.target_id == device.id,
                                             AuditLog.action.like("admission.%") | AuditLog.action.like("enrollment.%"))
                      .order_by(AuditLog.created_at.desc()).limit(50))
    return {**_row(db, request, device, admission), "rollback_commands": gate.rollback_commands(device),
            "logs": [{"at": a.created_at, "action": a.action, "actor": a.actor_id, "details": a.details} for a in logs]}


# ---- portal-installed clients -------------------------------------------------------------------

class OnboardingRequest(BaseModel):
    csr: str = Field(max_length=16000)
    macs: list[str] = Field(min_length=1, max_length=16)
    hostname: str = Field(min_length=1, max_length=128)


@router.post("/agent/onboarding-request", status_code=202)
def onboarding_request(body: OnboardingRequest, request: Request, db=Depends(db_session)):
    """Tokenless enrollment for a client installed from the onboarding page.

    Accepted only for a computer an administrator put under admission with an open onboarding window, and it
    only creates a pending request: the certificate is issued after an administrator approves it. MAC
    addresses are claims: a spoofer inside an open window learns only that its request awaits approval, and
    the administrator sees the hostname and CSR fingerprint before approving.
    """
    macs = set()
    for value in body.macs:
        try:
            macs.add(normalize_mac(value))
        except ValueError:
            continue
    now = utcnow()
    candidates = db.scalars(select(Device).where(Device.primary_mac.in_(macs), Device.enabled.is_(True),
                                                 Device.device_class.not_in(["DEVELOPER", "INFRASTRUCTURE"]))).all()
    device = next((d for d in candidates if (a := db.scalar(select(NetworkAdmission).where(NetworkAdmission.device_id == d.id)))
                   and a.onboarding_until and a.onboarding_until > now and get_policy(db).onboarding_enabled), None)
    if not device or credential_active(db, device):
        audit(db, "onboarding", "enrollment.unsolicited_request", "onboarding", macs=sorted(macs)[:4], hostname=body.hostname)
        return {"status": "PENDING_APPROVAL", "token": None}
    try:
        request.app.state.vault.issue(body.csr, device.id)
    except ValueError:
        raise HTTPException(422, "enrollment.invalid_csr") from None
    # One open request per computer: a reinstall replaces the earlier, unapproved one.
    for old in db.scalars(select(Enrollment).where(Enrollment.device_id == device.id, Enrollment.approved.is_(False))):
        old.expires_at = now
    import secrets
    token = secrets.token_urlsafe(32)
    db.add(Enrollment(device_id=device.id, token_hash=digest(token), expires_at=now + timedelta(hours=24), csr=body.csr, used_at=now))
    audit(db, "onboarding", "enrollment.requested", device.id, source="onboarding_portal", hostname=body.hostname,
          csr_sha256=digest(body.csr))
    return {"status": "PENDING_APPROVAL", "token": token, "primary_mac": device.primary_mac}
