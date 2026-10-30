import base64
from datetime import datetime, timedelta
from typing import Literal
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select, func
from app.auth.dependencies import db_session, require, audit
from app.db import utcnow
from app.models import Policy, PolicyVersion, PolicyAssignment, Device, PolicyOverride
from app.policies.schema import PolicyDocument, merge_layers
from app.security.crypto import canonical, digest
from app.services.devices import device_or_404
from app.policies.resolver import resolve

router = APIRouter(prefix="/policies", tags=["policies"])


class PolicyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    description: str = Field(default="", max_length=2000)
    template: Literal["standard", "restricted", "maintenance", "custom"] | None = None
    from_policy_id: str | None = None
    is_template: bool = False


class Publish(BaseModel):
    # Omitted: publish the saved draft. The visual editor always publishes what was saved and previewed.
    document: dict | None = None
    reason: str = Field(min_length=5, max_length=2000)
    expected_version_id: str | None = None


def checked(document, request):
    """Schema plus server-side checks; raises with field-level error codes the dashboard translates."""
    from pydantic import ValidationError
    from app.policies.catalog import server_checks, validation_errors
    try:
        value = PolicyDocument.model_validate(document or {}).model_dump()
    except ValidationError as exc:
        raise HTTPException(422, {"code": "policy.invalid", "fields": validation_errors(exc)}) from None
    errors, warnings = server_checks(value, request.app.state.settings.public_origin)
    if errors:
        raise HTTPException(422, {"code": "policy.invalid", "fields": errors})
    return value, warnings


def policy_or_404(db, policy_id, lock=False):
    query = select(Policy).where(Policy.id == policy_id)
    p = db.scalar(query.with_for_update() if lock else query)
    if not p:
        raise HTTPException(404, "policy.not_found")
    return p


def active_document(db, p):
    return db.get(PolicyVersion, p.active_version_id).document if p.active_version_id else None


def policy_devices(db, policy_id):
    versions = select(PolicyVersion.id).where(PolicyVersion.policy_id == policy_id)
    return db.scalars(select(Device).where(Device.policy_version_id.in_(versions), Device.enabled.is_(True))).all()


def new_version(db, request, policy, document, admin, reason):
    sequence = (db.scalar(select(func.max(PolicyVersion.sequence)).where(PolicyVersion.policy_id == policy.id)) or 0) + 1
    envelope = request.app.state.vault.signed(document)
    version = PolicyVersion(policy_id=policy.id, sequence=sequence, document=document,
                            content_hash=digest(canonical(document)), payload=envelope["payload"], signature=envelope["signature"],
                            author_id=admin.id, reason=reason)
    db.add(version)
    db.flush()
    return version


@router.get("")
def policies(admin=Depends(require("read")), db=Depends(db_session)):
    counts = dict(db.execute(select(PolicyVersion.policy_id, func.count(Device.id))
                             .join(Device, Device.policy_version_id == PolicyVersion.id)
                             .where(Device.enabled.is_(True)).group_by(PolicyVersion.policy_id)).all())
    sequences = dict(db.execute(select(PolicyVersion.id, PolicyVersion.sequence)
                                .where(PolicyVersion.id.in_(select(Policy.active_version_id)))).all())
    return [{"id": p.id, "name": p.name, "description": p.description, "active_version_id": p.active_version_id,
             "active_sequence": sequences.get(p.active_version_id), "has_draft": p.draft is not None,
             "draft_updated_at": p.draft_updated_at, "is_template": p.is_template, "devices": counts.get(p.id, 0)}
            for p in db.scalars(select(Policy).order_by(Policy.name))]


@router.post("", status_code=201)
def create(body: PolicyCreate, request: Request, admin=Depends(require("policy")), db=Depends(db_session)):
    from app.policies.catalog import templates
    if body.from_policy_id:
        source = policy_or_404(db, body.from_policy_id)
        document = source.draft or active_document(db, source) or PolicyDocument().model_dump()
    else:
        document = templates(request.app.state.settings.public_origin)[body.template or "custom"]
    p = Policy(name=body.name, description=body.description, is_template=body.is_template,
               draft=PolicyDocument.model_validate(document).model_dump(), draft_updated_at=utcnow(), draft_author_id=admin.id)
    db.add(p)
    db.flush()
    audit(db, admin.id, "policy.created", p.id, template=body.template, copied_from=body.from_policy_id)
    return {"id": p.id, "name": p.name}


class PolicyPatch(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    description: str | None = Field(default=None, max_length=2000)
    is_template: bool | None = None


@router.patch("/{policy_id}")
def rename(policy_id: str, body: PolicyPatch, admin=Depends(require("policy")), db=Depends(db_session)):
    p = policy_or_404(db, policy_id, lock=True)
    changes = body.model_dump(exclude_none=True)
    for key, value in changes.items():
        setattr(p, key, value)
    audit(db, admin.id, "policy.renamed", p.id, **changes)
    return {"id": p.id, "name": p.name, "description": p.description, "is_template": p.is_template}


@router.get("/schema")
def schema(admin=Depends(require("read"))):
    return {"schema": PolicyDocument.model_json_schema(), "default": PolicyDocument().model_dump()}


@router.get("/catalog")
def catalog(request: Request, admin=Depends(require("read"))):
    from app.policies.catalog import AGENT_FEATURES, CATEGORIES, SETTINGS, management_allowance, templates
    from app.policies.schema import CATALOG
    origin = request.app.state.settings.public_origin
    return {"categories": CATEGORIES, "settings": SETTINGS, "templates": templates(origin),
            "checks": {k: {"source": v[0], "severity": v[1]} for k, v in CATALOG.items()},
            "default": PolicyDocument().model_dump(), "agent_features": AGENT_FEATURES,
            "management": management_allowance(origin)}


class DocumentBody(BaseModel):
    document: dict


@router.post("/validate")
def validate(body: DocumentBody, request: Request, admin=Depends(require("read"))):
    try:
        value, warnings = checked(body.document, request)
    except HTTPException as exc:
        return {"valid": False, "errors": exc.detail["fields"], "warnings": []}
    return {"valid": True, "errors": [], "warnings": warnings, "document": value}


class Simulation(BaseModel):
    document: PolicyDocument
    layers: list[dict] = Field(default_factory=list, max_length=20)


@router.post("/simulate")
def simulate(body: Simulation, admin=Depends(require("policy"))):
    try:
        # Simulation can describe a relaxation; publishing it still needs MFA approval.
        return {"effective": merge_layers(body.document.model_dump(), body.layers)}
    except (ValueError, KeyError, TypeError) as exc:
        raise HTTPException(422, str(exc)) from None


@router.get("/{policy_id}")
def detail(policy_id: str, admin=Depends(require("read")), db=Depends(db_session)):
    p = db.get(Policy, policy_id)
    if not p:
        raise HTTPException(404, "policy.not_found")
    from app.models import Administrator
    names = dict(db.execute(select(Administrator.id, Administrator.username)).all())
    return {"id": p.id, "name": p.name, "description": p.description, "active_version_id": p.active_version_id,
            "is_template": p.is_template, "draft": p.draft, "draft_updated_at": p.draft_updated_at,
            "draft_author": names.get(p.draft_author_id),
            "versions": [{"id": v.id, "sequence": v.sequence, "hash": v.content_hash, "document": v.document,
                           "created_at": v.created_at, "reason": v.reason, "author": names.get(v.author_id),
                           # Versions compiled for one computer's scope layers are not separate policy releases.
                           "compiled": v.reason.startswith("Compiled ")}
                          for v in db.scalars(select(PolicyVersion).where(PolicyVersion.policy_id == p.id).order_by(PolicyVersion.sequence.desc()))]}


class DraftBody(BaseModel):
    document: dict
    expected_draft_at: datetime | None = None


@router.put("/{policy_id}/draft")
def save_draft(policy_id: str, body: DraftBody, request: Request, admin=Depends(require("policy")), db=Depends(db_session)):
    from app.policies.catalog import diff
    p = policy_or_404(db, policy_id, lock=True)
    expected = body.expected_draft_at.replace(tzinfo=None) if body.expected_draft_at and body.expected_draft_at.tzinfo else body.expected_draft_at
    if p.draft_updated_at and expected and abs((p.draft_updated_at - expected).total_seconds()) > 0.001:
        raise HTTPException(409, "policy.draft_changed")
    value, warnings = checked(body.document, request)
    changed = [c["key"] for c in diff(p.draft or active_document(db, p), value)]
    p.draft, p.draft_updated_at, p.draft_author_id = value, utcnow(), admin.id
    audit(db, admin.id, "policy.draft_saved", p.id, changed=changed)
    return {"draft_updated_at": p.draft_updated_at, "warnings": warnings, "document": value}


@router.delete("/{policy_id}/draft")
def discard_draft(policy_id: str, admin=Depends(require("policy")), db=Depends(db_session)):
    p = policy_or_404(db, policy_id, lock=True)
    if not p.active_version_id:
        raise HTTPException(409, "policy.draft_is_only_copy")
    p.draft, p.draft_updated_at, p.draft_author_id = None, None, None
    audit(db, admin.id, "policy.draft_discarded", p.id)
    return {"ok": True}


class Restore(BaseModel):
    version_id: str


@router.post("/{policy_id}/restore")
def restore(policy_id: str, body: Restore, admin=Depends(require("policy")), db=Depends(db_session)):
    """Load an earlier version into the draft; it reaches computers only after review and publication."""
    p = policy_or_404(db, policy_id, lock=True)
    v = db.get(PolicyVersion, body.version_id)
    if not v or v.policy_id != p.id:
        raise HTTPException(404, "policy.version_not_found")
    p.draft, p.draft_updated_at, p.draft_author_id = PolicyDocument.model_validate(v.document).model_dump(), utcnow(), admin.id
    audit(db, admin.id, "policy.version_restored_to_draft", p.id, version_id=v.id, sequence=v.sequence)
    return {"draft_updated_at": p.draft_updated_at}


@router.get("/{policy_id}/diff")
def compare(policy_id: str, base: str, target: str = "draft", admin=Depends(require("read")), db=Depends(db_session)):
    from app.policies.catalog import diff
    p = policy_or_404(db, policy_id)

    def document(ref):
        if ref == "draft":
            return p.draft
        if ref == "active":
            return active_document(db, p)
        v = db.get(PolicyVersion, ref)
        if not v or v.policy_id != p.id:
            raise HTTPException(404, "policy.version_not_found")
        return v.document
    return {"changes": diff(document(base), document(target))}


class Preview(BaseModel):
    document: dict | None = None


@router.post("/{policy_id}/preview")
def preview(policy_id: str, body: Preview, request: Request, admin=Depends(require("read")), db=Depends(db_session)):
    from app.policies.catalog import diff
    p = policy_or_404(db, policy_id)
    value, warnings = checked(body.document if body.document is not None else p.draft or active_document(db, p), request)
    devices = policy_devices(db, p.id)
    deadline = utcnow() - timedelta(seconds=request.app.state.settings.heartbeat_deadline_seconds)
    online = sum(bool(d.last_heartbeat and d.last_heartbeat >= deadline) for d in devices)
    return {"changes": diff(active_document(db, p), value), "warnings": warnings, "first_version": not p.active_version_id,
            "affected": {"devices": len(devices), "online": online, "offline": len(devices) - online}}



def compiled(db, policy_id, document, device):
    """A computer's document with its scope layers; a layer the new version no longer allows names the computer."""
    from app.policies.resolver import PolicyConflict
    try:
        return resolve(db, policy_id, document, device)
    except PolicyConflict:
        raise
    except ValueError as exc:
        from pydantic import ValidationError
        code = str(exc) if not isinstance(exc, ValidationError) else (
            next(iter(e["msg"].split(", ", 1)[-1] for e in exc.errors()), "policy.invalid_value"))
        raise HTTPException(409, {"code": "policy.layer_incompatible", "device": device.hostname, "reason": code}) from None


@router.post("/{policy_id}/publish")
def publish(policy_id: str, body: Publish, request: Request, admin=Depends(require("approve", mfa=True)), db=Depends(db_session)):
    from app.policies.catalog import diff
    p = policy_or_404(db, policy_id, lock=True)
    if p.active_version_id != body.expected_version_id:
        raise HTTPException(409, "policy.concurrent_change")
    source = body.document if body.document is not None else p.draft
    if source is None:
        raise HTTPException(409, "policy.nothing_to_publish")
    document, _ = checked(source, request)
    changed = [c["key"] for c in diff(active_document(db, p), document)]
    previous_ids = list(db.scalars(select(PolicyVersion.id).where(PolicyVersion.policy_id == p.id)))
    version = new_version(db, request, p, document, admin, body.reason)
    if body.document is None:
        p.draft, p.draft_updated_at, p.draft_author_id = None, None, None
    p.active_version_id = version.id
    for device in db.scalars(select(Device).where(Device.policy_version_id.in_(previous_ids))):
        effective = compiled(db, p.id, version.document, device)
        assigned = version if effective == version.document else new_version(db, request, p, effective, admin, "Compiled scopes: " + body.reason)
        device.policy_version_id = assigned.id
        device.state, device.compliance_score, device.last_verified = "UNVERIFIED", 0, None
        device.revision += 1
        db.add(PolicyAssignment(device_id=device.id, version_id=assigned.id, author_id=admin.id))
    audit(db, admin.id, "policy.published", p.id, version_id=version.id, reason=body.reason, changed=changed)
    return {"id": version.id, "hash": version.content_hash, "sequence": version.sequence}


class Assignment(BaseModel):
    device_ids: list[str] = Field(min_length=1, max_length=10000)
    version_id: str


@router.post("/{policy_id}/assign")
def assign(policy_id: str, body: Assignment, request: Request, admin=Depends(require("approve", mfa=True)), db=Depends(db_session)):
    policy = db.scalar(select(Policy).where(Policy.id == policy_id).with_for_update())
    version = db.get(PolicyVersion, body.version_id)
    if not version or version.policy_id != policy_id:
        raise HTTPException(404, "policy.version_not_found")
    for device_id in set(body.device_ids):
        d = device_or_404(db, device_id)
        if d.device_class == "DEVELOPER":
            raise HTTPException(409, "device.unmanaged")
        effective = compiled(db, policy_id, version.document, d)
        assigned = version if effective == version.document else new_version(db, request, policy, effective, admin, "Compiled assignment scopes")
        d.policy_version_id, d.state, d.compliance_score, d.last_verified = assigned.id, "UNVERIFIED", 0, None
        d.revision += 1
        db.add(PolicyAssignment(device_id=d.id, version_id=assigned.id, author_id=admin.id))
        audit(db, admin.id, "policy.assigned", d.id, version_id=assigned.id)
    return {"assigned": len(set(body.device_ids))}


class Targets(BaseModel):
    device_ids: list[str] = Field(default_factory=list, max_length=5000)
    # Windows computer groups only; access point groups never carry endpoint policy.
    group_ids: list[str] = Field(default_factory=list, max_length=100)
    all_devices: bool = False


def resolve_targets(db, body: Targets):
    from app.models import GroupMember
    ids = set(body.device_ids)
    if body.group_ids:
        ids |= set(db.scalars(select(GroupMember.device_id).where(GroupMember.group_id.in_(body.group_ids))))
    query = select(Device).where(Device.enabled.is_(True), Device.device_class != "DEVELOPER")
    devices = db.scalars(query if body.all_devices else query.where(Device.id.in_(ids))).all()
    skipped = len(ids - {d.id for d in devices}) if not body.all_devices else 0
    return devices, skipped


@router.post("/{policy_id}/assignment-preview")
def assignment_preview(policy_id: str, body: Targets, request: Request, admin=Depends(require("read")), db=Depends(db_session)):
    p = policy_or_404(db, policy_id)
    devices, skipped = resolve_targets(db, body)
    deadline = utcnow() - timedelta(seconds=request.app.state.settings.heartbeat_deadline_seconds)
    current = dict(db.execute(select(PolicyVersion.id, Policy.name).join(Policy, Policy.id == PolicyVersion.policy_id)
                              .where(PolicyVersion.id.in_({d.policy_version_id for d in devices if d.policy_version_id}))).all())
    mine = set(db.scalars(select(PolicyVersion.id).where(PolicyVersion.policy_id == p.id)))
    rows = [{"id": d.id, "hostname": d.hostname, "online": bool(d.last_heartbeat and d.last_heartbeat >= deadline),
             "never_seen": d.last_heartbeat is None, "current_policy": current.get(d.policy_version_id),
             "already": d.policy_version_id in mine} for d in devices]
    replacing = {}
    for row in rows:
        if row["current_policy"] and not row["already"]:
            replacing[row["current_policy"]] = replacing.get(row["current_policy"], 0) + 1
    return {"total": len(rows), "online": sum(r["online"] for r in rows), "offline": sum(not r["online"] for r in rows),
            "never_seen": sum(r["never_seen"] for r in rows), "already": sum(r["already"] for r in rows),
            "skipped_unmanaged": skipped, "replacing": replacing, "published": bool(p.active_version_id),
            "devices": sorted(rows, key=lambda r: r["hostname"].lower())[:300]}


class TargetAssignment(Targets):
    reason: str = Field(min_length=5, max_length=2000)


@router.post("/{policy_id}/assign-targets")
def assign_targets(policy_id: str, body: TargetAssignment, request: Request, admin=Depends(require("approve", mfa=True)),
                   db=Depends(db_session)):
    p = policy_or_404(db, policy_id)
    if not p.active_version_id:
        raise HTTPException(409, "policy.not_published")
    devices, _ = resolve_targets(db, body)
    if not devices:
        raise HTTPException(422, "policy.no_targets")
    result = assign(policy_id, Assignment(device_ids=[d.id for d in devices], version_id=p.active_version_id), request, admin, db)
    audit(db, admin.id, "policy.assigned_targets", p.id, devices=len(devices), groups=body.group_ids,
          all_devices=body.all_devices, reason=body.reason)
    return result


@router.get("/{policy_id}/compliance")
def policy_compliance(policy_id: str, request: Request, admin=Depends(require("read")), db=Depends(db_session)):
    """What computers actually reported, never what was sent: an assigned version is not an enforced one."""
    from app.models import BackgroundJob, ComplianceCheck, ComplianceReport, DeploymentTask, RemediationResult
    from app.services.devices import effective_state
    p = policy_or_404(db, policy_id)
    settings = request.app.state.settings
    devices = policy_devices(db, p.id)
    ids = [d.id for d in devices]
    sequences = dict(db.execute(select(PolicyVersion.id, PolicyVersion.sequence).where(PolicyVersion.policy_id == p.id)).all())
    ranked = select(ComplianceReport.id, ComplianceReport.device_id,
                    func.row_number().over(partition_by=ComplianceReport.device_id,
                                           order_by=ComplianceReport.created_at.desc()).label("n")).where(ComplianceReport.device_id.in_(ids)).subquery()
    latest = dict(db.execute(select(ranked.c.device_id, ranked.c.id).where(ranked.c.n == 1)).all())
    failing = {}
    for check in db.scalars(select(ComplianceCheck).where(ComplianceCheck.report_id.in_(latest.values()), ComplianceCheck.status != "PASS")):
        failing.setdefault(check.report_id, []).append({"check_id": check.check_id, "status": check.status,
                                                        "error": (check.details or {}).get("error")})
    reboot = set(db.scalars(select(BackgroundJob.device_id).where(BackgroundJob.device_id.in_(ids), BackgroundJob.status == "REBOOT_REQUIRED")))
    reboot |= set(db.scalars(select(DeploymentTask.device_id).where(DeploymentTask.device_id.in_(ids),
                                                                     DeploymentTask.state.in_(["AWAITING_RESTART", "REBOOT_REQUIRED"]))))
    failed = set(db.scalars(select(BackgroundJob.device_id).where(BackgroundJob.device_id.in_(ids), BackgroundJob.kind == "MAINTENANCE",
                                                                  BackgroundJob.status == "FAILED")))
    for r in db.scalars(select(RemediationResult).where(RemediationResult.device_id.in_(ids))):
        if (r.result or {}).get("exit_code") not in (0, None):
            failed.add(r.device_id)
    deadline = utcnow() - timedelta(seconds=settings.heartbeat_deadline_seconds)
    rows = []
    for d in devices:
        state, score = effective_state(d, settings)
        online = bool(d.last_heartbeat and d.last_heartbeat >= deadline)
        evaluated = d.reported_policy_id == d.policy_version_id
        rows.append({"id": d.id, "hostname": d.hostname, "state": state, "score": score, "online": online,
                     "last_heartbeat": d.last_heartbeat, "last_verified": d.last_verified,
                     "assigned_sequence": sequences.get(d.policy_version_id),
                     "evaluated_sequence": sequences.get(d.reported_policy_id),
                     "applying": online and not evaluated, "not_reported": d.last_heartbeat is None or (not online and not evaluated),
                     "awaiting_approval": state == "NONCOMPLIANT" and d.mode in ("AUDIT", "PREVIEW"),
                     "reboot_required": d.id in reboot, "failed": d.id in failed,
                     "failing": failing.get(latest.get(d.id), []), "agent_features": d.agent_features or []})
    counts = {"total": len(rows), "compliant": sum(r["state"] == "COMPLIANT" for r in rows),
              "noncompliant": sum(r["state"] == "NONCOMPLIANT" for r in rows),
              "applying": sum(r["applying"] for r in rows), "awaiting_approval": sum(r["awaiting_approval"] for r in rows),
              "reboot_required": sum(r["reboot_required"] for r in rows), "failed": sum(r["failed"] for r in rows),
              "offline": sum(not r["online"] for r in rows), "not_reported": sum(r["not_reported"] for r in rows)}
    return {"counts": counts, "devices": sorted(rows, key=lambda r: (r["state"] == "COMPLIANT", r["hostname"].lower()))}


class LayerCreate(BaseModel):
    scope: str = Field(pattern=r"^(GLOBAL|CLASS|GROUP|DEVICE)$")
    target: str | None = None
    controls: dict
    approved_relaxation: bool = False
    reason: str = Field(min_length=5, max_length=2000)


@router.get("/{policy_id}/layers")
def layers(policy_id: str, admin=Depends(require("read")), db=Depends(db_session)):
    return [{"id": layer.id, "scope": layer.scope, "target": layer.device_id or layer.group_id or layer.device_class,
             "priority": layer.priority, "controls": layer.controls, "approved_relaxation": layer.approved_relaxation,
             "reason": layer.reason} for layer in db.scalars(select(PolicyOverride).where(PolicyOverride.policy_id == policy_id).order_by(PolicyOverride.priority, PolicyOverride.id))]


@router.post("/{policy_id}/layers")
def create_layer(policy_id: str, body: LayerCreate, admin=Depends(require("approve", mfa=True)), db=Depends(db_session)):
    from app.models import DeviceGroup
    p = db.get(Policy, policy_id)
    if not p:
        raise HTTPException(404, "policy.not_found")
    values = {"policy_id": p.id, "scope": body.scope, "priority": {"GLOBAL": 0, "CLASS": 10, "GROUP": 20, "DEVICE": 30}[body.scope],
              "controls": body.controls, "author_id": admin.id, "approved_relaxation": body.approved_relaxation, "reason": body.reason}
    if body.scope == "DEVICE":
        device_or_404(db, body.target)
        values["device_id"] = body.target
    elif body.scope == "GROUP":
        if not db.get(DeviceGroup, body.target):
            raise HTTPException(404, "group.not_found")
        values["group_id"] = body.target
    elif body.scope == "CLASS":
        if body.target not in ("STANDARD", "ADMINISTRATOR"):
            raise HTTPException(422, "device.invalid_class")
        values["device_class"] = body.target
    elif body.target:
        raise HTTPException(422, "policy.global_has_no_target")
    if "static_ip_address" in body.controls:
        if body.scope != "DEVICE":
            raise HTTPException(422, "policy.static_address_device_only")
        duplicate_static_address(db, body.controls["static_ip_address"], body.target)
    baseline = db.get(PolicyVersion, p.active_version_id).document if p.active_version_id else PolicyDocument().model_dump()
    try:
        merge_layers(baseline, [{"id": "preview", **values}])
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None
    layer = PolicyOverride(**values)
    db.add(layer)
    db.flush()
    audit(db, admin.id, "policy.layer_created", p.id, layer_id=layer.id, scope=body.scope, relaxation=body.approved_relaxation, reason=body.reason)
    return {"id": layer.id, "status": "PENDING_PUBLICATION"}


def duplicate_static_address(db, address, device_id):
    """One address, one computer: across every policy's computer layers and every DHCP reservation."""
    from app.models import DhcpReservation
    if not address:
        return
    for layer in db.scalars(select(PolicyOverride).where(PolicyOverride.scope == "DEVICE")):
        if layer.controls.get("static_ip_address") == address and layer.device_id != device_id:
            raise HTTPException(409, "policy.duplicate_static_address")
    reservation = db.scalar(select(DhcpReservation).where(DhcpReservation.address == address))
    if reservation and reservation.device_id != device_id:
        raise HTTPException(409, "policy.duplicate_static_address")


@router.delete("/{policy_id}/layers/{layer_id}")
def revoke_layer(policy_id: str, layer_id: str, admin=Depends(require("approve", mfa=True)), db=Depends(db_session)):
    layer = db.get(PolicyOverride, layer_id)
    if not layer or layer.policy_id != policy_id:
        raise HTTPException(404, "policy.layer_not_found")
    audit(db, admin.id, "policy.layer_revoked", policy_id, layer_id=layer.id, controls=layer.controls, reason=layer.reason)
    db.delete(layer)
    return {"status": "PENDING_PUBLICATION"}


class Rollback(BaseModel):
    version_id: str
    expected_version_id: str
    reason: str = Field(min_length=5, max_length=2000)


@router.post("/{policy_id}/rollback")
def rollback(policy_id: str, body: Rollback, request: Request, admin=Depends(require("approve", mfa=True)), db=Depends(db_session)):
    v = db.get(PolicyVersion, body.version_id)
    if not v or v.policy_id != policy_id:
        raise HTTPException(404, "policy.version_not_found")
    return publish(policy_id, Publish(document=v.document, reason=body.reason,
                                      expected_version_id=body.expected_version_id), request, admin, db)
