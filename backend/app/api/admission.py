"""Mandatory Suro Client network admission: policy, pilot computers, gate plans, overrides and overview.

Requested changes (overrides, toggles) and router-confirmed state are reported separately; see
services/admission_gate.py for the mechanism and its limits.
"""

import json
from datetime import timedelta
from typing import Literal
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from app.auth.dependencies import audit, db_session, require
from app.db import utcnow
from app.models import (AdmissionSubnet, AuditLog, Device, DeviceCredential, Enrollment, NetworkAdmission, NetworkInterface,
                        NetworkPlan, Router, UserIdentity)
from app.services import admission_gate as gate
from app.services.admission_sync import credential_active, enforced, get_policy
from app.services.devices import device_or_404, effective_state, normalize_mac
from app.security.crypto import digest

router = APIRouter(tags=["admission"])


def _policy(p):
    return {k: getattr(p, k) for k in ("mode", "group_ids", "require_enrollment", "require_running_agent", "require_compliance",
                                       "exempt_developers", "heartbeat_timeout_seconds", "grace_seconds", "auto_revoke",
                                       "onboarding_enabled", "outage_policy", "revision", "updated_at")}


@router.get("/admission/site-config")
def site_config(request: Request, admin=Depends(require("read"))):
    """site.json for building a code-signed setup (scripts/build-client.py --site). Public values only."""
    from app.api.onboarding import site_settings
    try:
        return site_settings(request.app.state.settings, None)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from None


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
    if body.mode == "GROUPS":
        # Requiring by group is done by selecting the group's computers (POST /admission/selected).
        raise HTTPException(409, "admission.mode_requires_staged_rollout")
    if policy.mode == "ALL" and body.mode != "ALL" and db.scalar(
            select(AdmissionSubnet.id).where(AdmissionSubnet.state != "NOT_INSTALLED")):
        # Subnet drop rules also restrict computers Suro does not know; leaving ALL would strand them.
        raise HTTPException(409, "admission.remove_subnet_gates_first")
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
    if device.primary_mac != mac:
        raise HTTPException(409, "admission.use_primary_mac")
    code = _require_device(db, admin, device, r, body.reason)
    if code:
        raise HTTPException(409, code)
    return detail(device.id, request, admin, db)


def _require_device(db, admin, device, r, reason):
    """Put one computer under a per-MAC (selected computers) gate on router r. Returns an error code or None."""
    if device.device_class in ("DEVELOPER", "INFRASTRUCTURE") or device.admission_exempt or not device.enabled:
        return "admission.device_exempt"
    admission = db.scalar(select(NetworkAdmission).where(NetworkAdmission.device_id == device.id))
    if admission and admission.source == "ALL" and admission.gate_state == "SUBNET":
        return "admission.covered_by_subnet"
    if not admission:
        admission = NetworkAdmission(device_id=device.id, source="PILOT", revision=0)
        db.add(admission)
    if admission.gate_state == "INSTALLED" and admission.router_id != r.id:
        return "admission.remove_gate_first"
    admission.source, admission.router_id, admission.enabled = "PILOT", r.id, True
    admission.revision = (admission.revision or 0) + 1
    db.flush()
    audit(db, admin.id, "admission.pilot_added", device.id, mac=device.primary_mac, router_id=r.id, reason=reason)
    return None


def _router_or_404(db, router_id):
    r = db.get(Router, router_id)
    if not r or r.archived:
        raise HTTPException(404, "router.not_found")
    return r


class Selected(BaseModel):
    device_ids: list[str] = Field(min_length=1, max_length=200)
    router_id: str
    reason: str = Field(min_length=5, max_length=2000)


@router.post("/admission/selected")
def add_selected(body: Selected, admin=Depends(require("approve", mfa=True)), db=Depends(db_session)):
    """Require the Suro Client on one or several chosen computers. Nothing reaches the router until a gate plan
    (POST /admission/routers/{id}/gate-preview) is reviewed and applied."""
    r = _router_or_404(db, body.router_id)
    added, skipped = [], []
    for device_id in dict.fromkeys(body.device_ids):
        device = db.get(Device, device_id)
        code = "device.not_found" if not device else _require_device(db, admin, device, r, body.reason)
        (skipped.append({"device_id": device_id, "code": code}) if code else added.append(device_id))
    return {"added": added, "skipped": skipped}


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


# ---- several selected computers on one router: one reviewed plan ------------------------------------

BATCH_LIMIT = 50  # per-MAC rules on an old router; larger groups belong in a subnet gate


class BatchPreview(BaseModel):
    device_ids: list[str] | None = Field(default=None, max_length=BATCH_LIMIT)
    reason: str = Field(min_length=5, max_length=2000)


@router.post("/admission/routers/{router_id}/gate-preview")
async def batch_gate_preview(router_id: str, body: BatchPreview, request: Request, admin=Depends(require("approve", mfa=True)),
                             db=Depends(db_session)):
    """Gate rules for every selected computer on this router that has no installed gate yet, in one plan."""
    r = _router_or_404(db, router_id)
    query = select(NetworkAdmission).where(NetworkAdmission.router_id == r.id, NetworkAdmission.source == "PILOT",
                                           NetworkAdmission.enabled.is_(True), NetworkAdmission.gate_state != "INSTALLED")
    if body.device_ids:
        query = query.where(NetworkAdmission.device_id.in_(body.device_ids))
    admissions = db.scalars(query).all()
    if len(admissions) > BATCH_LIMIT:
        raise HTTPException(409, "admission.batch_too_large")
    if not admissions:
        raise HTTPException(409, "admission.nothing_to_prepare")
    snapshot = await _snapshot(request, r)
    server = gate.server_address(request.app.state.settings)
    operations, included, skipped = [], [], []
    for admission in admissions:
        device = db.get(Device, admission.device_id)
        report = gate.feasibility(r, snapshot, device, server)
        if report["blockers"]:
            skipped.append({"device_id": device.id, "hostname": device.hostname, "blockers": report["blockers"]})
            continue
        device_operations = gate.gate_plan(device, server, snapshot)
        if not device_operations:
            admission.gate_state = "INSTALLED"
            continue
        operations += device_operations
        included.append({"device_id": device.id, "hostname": device.hostname, "mac": device.primary_mac,
                         "warnings": report["warnings"]})
    result = {"included": included, "skipped": skipped, "plan": None}
    if not operations:
        return result
    from app.mikrotik.connector import snapshot_hash
    plan = NetworkPlan(device_id=None, router_id=r.id, generation=r.generation, snapshot_hash=snapshot_hash(snapshot),
                       operations=operations, reason=body.reason, author_id=admin.id,
                       result={"admission": None, "kind": "admission_batch_gate", "device_ids": [i["device_id"] for i in included],
                               "owned_prefixes": [f"lantern:{i['device_id']}:admission:" for i in included]})
    db.add(plan)
    db.flush()
    for admission in admissions:
        if admission.device_id in plan.result["device_ids"]:
            admission.gate_state, admission.gate_plan_id = "PREVIEW", plan.id
    audit(db, admin.id, "admission.batch_gate_previewed", r.id, plan_id=plan.id, devices=len(included), skipped=len(skipped))
    return {**result, "plan": {"id": plan.id, "operations": _readable(operations), "expires_in_seconds": 600}}


@router.post("/admission/routers/{router_id}/apply")
async def batch_apply(router_id: str, body: Apply, request: Request, admin=Depends(require("approve", mfa=True)), db=Depends(db_session)):
    from app.services.network import execute_plan
    plan = db.get(NetworkPlan, body.plan_id)
    if not plan or plan.router_id != router_id or (plan.result or {}).get("kind") != "admission_batch_gate":
        raise HTTPException(404, "network.plan_not_found")
    device_ids = list(plan.result["device_ids"])
    audit(db, admin.id, "admission.apply_requested", router_id, plan_id=plan.id, kind="admission_batch_gate", reason=body.reason)
    result = await execute_plan(request.app, db, plan, admin.id)
    for admission in db.scalars(select(NetworkAdmission).where(NetworkAdmission.device_id.in_(device_ids))):
        if result["state"] == "VERIFIED":
            admission.gate_state, admission.error = "INSTALLED", None
        elif result["state"] == "ERROR":
            admission.gate_state = "ERROR"
            admission.error = (result.get("result") or {}).get("error", "admission.router_error")
        admission.revision += 1
    db.commit()
    return {"state": result["state"], "devices": len(device_ids)}


# ---- all computers of a subnet except exceptions ----------------------------------------------------

def _subnet_or_404(db, subnet_id):
    subnet = db.get(AdmissionSubnet, subnet_id)
    if not subnet:
        raise HTTPException(404, "admission.subnet_not_found")
    return subnet


def _subnet_row(db, subnet):
    r = db.get(Router, subnet.router_id)
    members = db.scalars(select(NetworkAdmission).where(NetworkAdmission.source == "ALL", NetworkAdmission.router_id == subnet.router_id,
                                                        NetworkAdmission.gate_state == "SUBNET")).all()
    network = gate.subnet_network(subnet)
    inside = [a for a in members if gate._inside(a.granted_ip or a.reported_ip or "", network)]
    return {"id": subnet.id, "router_id": subnet.router_id, "router_name": r.name if r else None, "cidr": subnet.cidr,
            "state": subnet.state, "error": subnet.error, "created_at": subnet.created_at,
            "members": len(inside), "granted": sum(a.applied == "AUTHORIZED" for a in inside),
            "rollback_commands": gate.subnet_rollback_commands(subnet)}


@router.get("/admission/subnets")
def list_subnets(admin=Depends(require("read")), db=Depends(db_session)):
    return [_subnet_row(db, s) for s in db.scalars(select(AdmissionSubnet).order_by(AdmissionSubnet.created_at))]


class SubnetCreate(BaseModel):
    router_id: str
    cidr: str = Field(min_length=9, max_length=43)
    reason: str = Field(min_length=5, max_length=2000)


@router.post("/admission/subnets", status_code=201)
def add_subnet(body: SubnetCreate, admin=Depends(require("approve", mfa=True)), db=Depends(db_session)):
    """Start "all computers except exceptions" on one subnet. This only prepares grants; nothing is dropped
    until the subnet's plan is previewed, its restricted-host count confirmed and applied."""
    from ipaddress import ip_network
    if get_policy(db).mode != "ALL":
        raise HTTPException(409, "admission.mode_not_all")
    r = _router_or_404(db, body.router_id)
    try:
        network = ip_network(body.cidr.strip(), strict=False)
    except ValueError:
        raise HTTPException(422, "admission.invalid_subnet") from None
    if network.version != 4 or network.prefixlen < 16 or network.prefixlen > 30:
        raise HTTPException(422, "admission.invalid_subnet")
    for other in db.scalars(select(AdmissionSubnet).where(AdmissionSubnet.state != "NOT_INSTALLED")):
        if gate.subnet_network(other).overlaps(network):
            raise HTTPException(409, "admission.subnet_overlaps")
    subnet = AdmissionSubnet(router_id=r.id, cidr=str(network), created_by=admin.id, revision=0)
    db.add(subnet)
    db.flush()
    audit(db, admin.id, "admission.subnet_added", subnet.id, router_id=r.id, cidr=subnet.cidr, reason=body.reason)
    return _subnet_row(db, subnet)


def _subnet_plan(db, subnet, r, snapshot, operations, admin, reason, kind, **extra):
    from app.mikrotik.connector import snapshot_hash
    plan = NetworkPlan(device_id=None, router_id=r.id, generation=r.generation, snapshot_hash=snapshot_hash(snapshot),
                       operations=operations, reason=reason, author_id=admin.id,
                       result={"admission": None, "kind": kind, "subnet_id": subnet.id, **extra})
    db.add(plan)
    db.flush()
    subnet.plan_id = plan.id
    return plan


@router.post("/admission/subnets/{subnet_id}/preview")
async def subnet_preview(subnet_id: str, body: Reason, request: Request, admin=Depends(require("approve", mfa=True)), db=Depends(db_session)):
    subnet = _subnet_or_404(db, subnet_id)
    if subnet.state in ("NOT_INSTALLED", "REMOVING"):
        raise HTTPException(409, "admission.subnet_not_prepared")
    r = _router_or_404(db, subnet.router_id)
    snapshot = await _snapshot(request, r)
    server = gate.server_address(request.app.state.settings)
    from app.api.onboarding import client_ip
    report = gate.subnet_feasibility(r, subnet, snapshot, server, admin_ip=client_ip(request))
    result = {"feasibility": report, "rollback_commands": gate.subnet_rollback_commands(subnet), "plan": None}
    if report["blockers"]:
        return result
    operations = gate.subnet_plan(subnet, server, snapshot)
    if not operations:
        subnet.state = "INSTALLED"
        return {**result, "already_installed": True}
    restricted = report["facts"]["hosts_restricted"]
    plan = _subnet_plan(db, subnet, r, snapshot, operations, admin, body.reason, "admission_subnet_gate",
                        restricted=restricted, owned_prefixes=[gate.subnet_prefix(subnet)])
    subnet.state = "PREVIEW"
    audit(db, admin.id, "admission.subnet_previewed", subnet.id, plan_id=plan.id, restricted=restricted, warnings=report["warnings"])
    return {**result, "plan": {"id": plan.id, "operations": _readable(operations), "expires_in_seconds": 600, "confirm_restricted": restricted}}


@router.post("/admission/subnets/{subnet_id}/removal-preview")
async def subnet_removal_preview(subnet_id: str, body: Reason, request: Request, admin=Depends(require("approve", mfa=True)),
                                 db=Depends(db_session)):
    subnet = _subnet_or_404(db, subnet_id)
    r = _router_or_404(db, subnet.router_id)
    snapshot = await _snapshot(request, r)
    members = [db.get(Device, a.device_id) for a in db.scalars(select(NetworkAdmission).where(
        NetworkAdmission.source == "ALL", NetworkAdmission.router_id == r.id, NetworkAdmission.gate_state == "SUBNET"))]
    operations = gate.subnet_removal_plan(subnet, snapshot, members)
    if not operations:
        _subnet_removed(db, subnet)
        return {"plan": None, "already_removed": True, "rollback_commands": gate.subnet_rollback_commands(subnet)}
    plan = _subnet_plan(db, subnet, r, snapshot, operations, admin, body.reason, "admission_subnet_removal",
                        owned_prefixes=[gate.subnet_prefix(subnet)] + [f"lantern:{d.id}:admission:" for d in members])
    # Freeze grant refreshes so the router still matches this plan when it is applied.
    subnet.state = "REMOVING"
    for admission in db.scalars(select(NetworkAdmission).where(NetworkAdmission.source == "ALL", NetworkAdmission.router_id == r.id,
                                                               NetworkAdmission.gate_state == "SUBNET")):
        admission.gate_state = "REMOVING"
    audit(db, admin.id, "admission.subnet_removal_previewed", subnet.id, plan_id=plan.id)
    return {"plan": {"id": plan.id, "operations": _readable(operations), "expires_in_seconds": 600},
            "rollback_commands": gate.subnet_rollback_commands(subnet)}


def _subnet_removed(db, subnet):
    subnet.state, subnet.error = "NOT_INSTALLED", None
    for admission in db.scalars(select(NetworkAdmission).where(NetworkAdmission.source == "ALL", NetworkAdmission.router_id == subnet.router_id,
                                                               NetworkAdmission.gate_state.in_(("SUBNET", "REMOVING")))):
        admission.gate_state, admission.applied, admission.granted_ip, admission.grant_expires_at = "NOT_INSTALLED", "NONE", None, None
        admission.enabled = False
        admission.revision += 1


class SubnetApply(BaseModel):
    plan_id: str
    reason: str = Field(min_length=5, max_length=2000)
    # The administrator types how many hosts the preview said will lose routed access.
    confirm_restricted: int | None = Field(default=None, ge=0)


@router.post("/admission/subnets/{subnet_id}/apply")
async def subnet_apply(subnet_id: str, body: SubnetApply, request: Request, admin=Depends(require("approve", mfa=True)), db=Depends(db_session)):
    from app.services.network import execute_plan
    subnet = _subnet_or_404(db, subnet_id)
    plan = db.get(NetworkPlan, body.plan_id)
    kind = (plan.result or {}).get("kind") if plan else None
    if not plan or (plan.result or {}).get("subnet_id") != subnet.id or kind not in ("admission_subnet_gate", "admission_subnet_removal"):
        raise HTTPException(404, "network.plan_not_found")
    if kind == "admission_subnet_gate" and body.confirm_restricted != plan.result.get("restricted"):
        raise HTTPException(409, "admission.confirm_restricted_mismatch")
    audit(db, admin.id, "admission.apply_requested", subnet.id, plan_id=plan.id, kind=kind, reason=body.reason,
          confirmed_restricted=body.confirm_restricted)
    result = await execute_plan(request.app, db, plan, admin.id)
    subnet = _subnet_or_404(db, subnet_id)
    if result["state"] == "VERIFIED":
        if kind == "admission_subnet_gate":
            subnet.state, subnet.error = "INSTALLED", None
        else:
            _subnet_removed(db, subnet)
    elif result["state"] == "ERROR":
        error = (result.get("result") or {}).get("error", "admission.router_error")
        # A failed removal keeps the subnet managed, so grants are not silently lost.
        subnet.state, subnet.error = ("INSTALLED" if kind == "admission_subnet_removal" else "ERROR"), error
        if kind == "admission_subnet_removal":
            for admission in db.scalars(select(NetworkAdmission).where(NetworkAdmission.source == "ALL",
                                                                       NetworkAdmission.router_id == subnet.router_id,
                                                                       NetworkAdmission.gate_state == "REMOVING")):
                admission.gate_state = "SUBNET"
    subnet.revision += 1
    db.commit()
    return {"state": result["state"], "kind": kind, "subnet": _subnet_row(db, subnet)}


@router.delete("/admission/subnets/{subnet_id}")
def delete_subnet(subnet_id: str, body: Reason, admin=Depends(require("approve", mfa=True)), db=Depends(db_session)):
    subnet = _subnet_or_404(db, subnet_id)
    if subnet.state != "NOT_INSTALLED":
        raise HTTPException(409, "admission.subnet_remove_first")
    audit(db, admin.id, "admission.subnet_deleted", subnet.id, cidr=subnet.cidr, reason=body.reason)
    db.delete(subnet)
    return {"deleted": True}


class ExceptionCreate(BaseModel):
    mac: str
    name: str = Field(min_length=1, max_length=128)
    device_class: Literal["INFRASTRUCTURE", "OTHER"] = "OTHER"
    reason: str = Field(min_length=5, max_length=2000)


@router.post("/admission/exceptions", status_code=201)
def add_exception(body: ExceptionCreate, admin=Depends(require("approve", mfa=True)), db=Depends(db_session)):
    """A device that keeps network access without the Suro Client (printer, camera, phone, server, a developer's
    machine). Only administrators set this; its router-confirmed address gets a permanent grant."""
    try:
        mac = normalize_mac(body.mac)
    except ValueError:
        raise HTTPException(422, "device.invalid_mac") from None
    device = db.scalar(select(Device).where(Device.primary_mac == mac))
    if not device:
        device = Device(hostname=body.name, primary_mac=mac, state="UNVERIFIED", device_class=body.device_class)
        db.add(device)
        db.flush()
        audit(db, admin.id, "device.created", device.id, device_class=body.device_class, source="admission_exception")
    device.admission_exempt, device.exemption_reason = True, body.reason
    device.revision = (device.revision or 0) + 1
    audit(db, admin.id, "admission.exemption_changed", device.id, exempt=True, device_class=device.device_class, reason=body.reason)
    return {"device_id": device.id, "hostname": device.hostname, "mac": device.primary_mac, "exempt": True}


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
        "network": gate.network_state(admission, desired, enforced=enforced(db, admission)),
        "source": admission.source if admission else None,
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
    subnets = [_subnet_row(db, s) for s in db.scalars(select(AdmissionSubnet).order_by(AdmissionSubnet.created_at))]
    exceptions = [{"device_id": d.id, "hostname": d.hostname, "mac": d.primary_mac, "device_class": d.device_class,
                   "reason": d.exemption_reason}
                  for d in db.scalars(select(Device).where(Device.enabled.is_(True), Device.admission_exempt.is_(True) |
                                                           Device.device_class.in_(("INFRASTRUCTURE", "DEVELOPER")))
                                      .order_by(Device.hostname).limit(500))]
    return {"policy": _policy(policy), "counts": counts, "items": rows, "subnets": subnets, "exceptions": exceptions}


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
    policy = get_policy(db)
    candidates = db.scalars(select(Device).where(Device.primary_mac.in_(macs), Device.enabled.is_(True),
                                                 Device.device_class.not_in(["DEVELOPER", "INFRASTRUCTURE"]))).all()
    device = next((d for d in candidates if (a := db.scalar(select(NetworkAdmission).where(NetworkAdmission.device_id == d.id)))
                   and a.onboarding_until and a.onboarding_until > now and policy.onboarding_enabled), None)
    if not device and policy.mode == "ALL" and policy.onboarding_enabled:
        device = _subnet_newcomer(request, db, macs, candidates, body.hostname, now)
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


NEWCOMER_LIMIT = 100  # pending portal requests per hour in "all computers" mode; each still needs approval


def _subnet_newcomer(request, db, macs, candidates, hostname, now):
    """"All computers except exceptions": a computer behind a gated subnet may ask to enroll without a per-computer
    window. The MAC must be one the gate router itself sees inside a gated subnet; the request only waits for an
    administrator's approval, exactly like a windowed one."""
    from app.services.admission_sync import router_addresses
    subnets = db.scalars(select(AdmissionSubnet).where(AdmissionSubnet.state.in_(("PREPARING", "PREVIEW", "INSTALLED")))).all()
    seen = None
    for subnet in subnets:
        addresses = router_addresses(request.app, db.get(Router, subnet.router_id))
        seen = next((m for m in sorted(macs) if gate._inside(addresses.get(m, ""), gate.subnet_network(subnet))), None)
        if seen:
            break
    if not seen:
        return None
    existing = next((d for d in candidates if d.primary_mac == seen), None)
    if existing:
        admission = db.scalar(select(NetworkAdmission).where(NetworkAdmission.device_id == existing.id))
        return existing if not admission or admission.source == "ALL" else None
    recent = db.scalar(select(func.count(Enrollment.id)).where(Enrollment.created_at > now - timedelta(hours=1),
                                                               Enrollment.approved.is_(False), Enrollment.csr.is_not(None)))
    if recent >= NEWCOMER_LIMIT or db.scalar(select(Device.id).where(Device.primary_mac == seen)):
        return None
    device = Device(hostname=hostname[:128], primary_mac=seen, state="PENDING_ENROLLMENT")
    db.add(device)
    db.flush()
    audit(db, "onboarding", "device.created", device.id, device_class="STANDARD", source="admission_subnet_portal")
    return device
