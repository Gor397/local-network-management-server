import base64
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


class Publish(BaseModel):
    document: PolicyDocument
    reason: str = Field(min_length=5, max_length=2000)
    expected_version_id: str | None = None


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
    return [{"id": p.id, "name": p.name, "active_version_id": p.active_version_id} for p in db.scalars(select(Policy).order_by(Policy.name))]


@router.post("", status_code=201)
def create(body: PolicyCreate, admin=Depends(require("policy")), db=Depends(db_session)):
    p = Policy(name=body.name)
    db.add(p)
    db.flush()
    audit(db, admin.id, "policy.created", p.id)
    return {"id": p.id, "name": p.name}


@router.get("/schema")
def schema(admin=Depends(require("read"))):
    return {"schema": PolicyDocument.model_json_schema(), "default": PolicyDocument().model_dump()}


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
    return {"id": p.id, "name": p.name, "active_version_id": p.active_version_id,
            "versions": [{"id": v.id, "sequence": v.sequence, "hash": v.content_hash, "document": v.document,
                           "created_at": v.created_at, "reason": v.reason} for v in db.scalars(select(PolicyVersion).where(PolicyVersion.policy_id == p.id).order_by(PolicyVersion.sequence.desc()))]}


@router.post("/{policy_id}/publish")
def publish(policy_id: str, body: Publish, request: Request, admin=Depends(require("approve", mfa=True)), db=Depends(db_session)):
    p = db.scalar(select(Policy).where(Policy.id == policy_id).with_for_update())
    if not p:
        raise HTTPException(404, "policy.not_found")
    if p.active_version_id != body.expected_version_id:
        raise HTTPException(409, "policy.concurrent_change")
    previous_ids = list(db.scalars(select(PolicyVersion.id).where(PolicyVersion.policy_id == p.id)))
    version = new_version(db, request, p, body.document.model_dump(), admin, body.reason)
    p.active_version_id = version.id
    for device in db.scalars(select(Device).where(Device.policy_version_id.in_(previous_ids))):
        effective = resolve(db, p.id, version.document, device)
        assigned = version if effective == version.document else new_version(db, request, p, effective, admin, "Compiled scopes: " + body.reason)
        device.policy_version_id = assigned.id
        device.state, device.compliance_score, device.last_verified = "UNVERIFIED", 0, None
        device.revision += 1
        db.add(PolicyAssignment(device_id=device.id, version_id=assigned.id, author_id=admin.id))
    audit(db, admin.id, "policy.published", p.id, version_id=version.id, reason=body.reason)
    return {"id": version.id, "hash": version.content_hash, "sequence": version.sequence}


class Assignment(BaseModel):
    device_ids: list[str] = Field(min_length=1, max_length=1000)
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
        effective = resolve(db, policy_id, version.document, d)
        assigned = version if effective == version.document else new_version(db, request, policy, effective, admin, "Compiled assignment scopes")
        d.policy_version_id, d.state, d.compliance_score, d.last_verified = assigned.id, "UNVERIFIED", 0, None
        d.revision += 1
        db.add(PolicyAssignment(device_id=d.id, version_id=assigned.id, author_id=admin.id))
        audit(db, admin.id, "policy.assigned", d.id, version_id=assigned.id)
    return {"assigned": len(set(body.device_ids))}


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
    return publish(policy_id, Publish(document=PolicyDocument.model_validate(v.document), reason=body.reason,
                                      expected_version_id=body.expected_version_id), request, admin, db)
