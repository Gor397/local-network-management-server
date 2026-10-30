"""Reviewed admission to existing infrastructure; profile creation never provisions or replaces a VLAN."""

import json
from datetime import timedelta
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from app.auth.dependencies import db_session, require, audit
from app.db import utcnow
from app.models import (
    NetworkProfile,
    Subnet,
    ApGroup,
    ApGroupMember,
    Router,
    Device,
    NetworkPlan,
    DhcpReservation,
)
from app.services.devices import device_or_404
from app.services.admission import admission_plan, radio_bindings
from app.mikrotik.connector import snapshot_hash
from app.mikrotik.planner import reservation_plan

router = APIRouter(prefix="/mikrotik", tags=["network admission profiles"])


class ProfileCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    subnet_id: str
    ap_group_id: str
    ssid: str = Field(min_length=1, max_length=32)
    vlan_id: int | None = Field(default=None, ge=1, le=4094)


def profile_targets(db, app, profile):
    ids = list(
        db.scalars(
            select(ApGroupMember.router_id).where(
                ApGroupMember.group_id == profile.ap_group_id
            )
        )
    )
    if not ids:
        raise HTTPException(409, "network.profile_group_empty")
    targets = []
    for identifier in sorted(ids):
        r = db.get(Router, identifier)
        if (
            r.archived
            or not r.snapshot
            or not r.last_seen
            or r.last_seen < utcnow() - timedelta(seconds=120)
        ):
            raise HTTPException(409, "router.fresh_discovery_required")
        snapshot = json.loads(app.state.vault.open(r.snapshot))
        try:
            radio_bindings(snapshot, r.capabilities, profile.ssid, profile.vlan_id)
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from None
        targets.append((r, snapshot))
    return targets


@router.get("/network-profiles")
def profiles(admin=Depends(require("read")), db=Depends(db_session)):
    return [
        {
            "id": p.id,
            "name": p.name,
            "subnet_id": p.subnet_id,
            "ap_group_id": p.ap_group_id,
            "ssid": p.ssid,
            "vlan_id": p.vlan_id,
            "enabled": p.enabled,
            "assurance": "MAC_ADMISSION_ONLY",
        }
        for p in db.scalars(select(NetworkProfile).order_by(NetworkProfile.name))
    ]


@router.post("/network-profiles", status_code=201)
def create(
    body: ProfileCreate,
    request: Request,
    admin=Depends(require("approve", mfa=True)),
    db=Depends(db_session),
):
    subnet = db.get(Subnet, body.subnet_id)
    if not subnet or not db.get(ApGroup, body.ap_group_id):
        raise HTTPException(404, "network.profile_dependencies_missing")
    if len(body.ssid.encode()) > 32 or any(ord(c) < 32 for c in body.ssid):
        raise HTTPException(422, "network.invalid_ssid")
    p = NetworkProfile(**body.model_dump())
    profile_targets(db, request.app, p)
    if body.vlan_id:
        gateway = db.get(Router, subnet.router_id)
        snapshot = (
            json.loads(request.app.state.vault.open(gateway.snapshot))
            if gateway and gateway.snapshot
            else {}
        )
        server = next(
            (
                s
                for s in snapshot.get("ip/dhcp-server", [])
                if s.get("name") == subnet.dhcp_server
            ),
            {},
        )
        if not any(
            v.get("name") == server.get("interface")
            and str(v.get("vlan-id")) == str(body.vlan_id)
            for v in snapshot.get("interface/vlan", [])
        ):
            raise HTTPException(409, "network.profile_vlan_unverified")
    db.add(p)
    db.flush()
    audit(
        db,
        admin.id,
        "network.profile_created",
        p.id,
        ssid=p.ssid,
        ap_group_id=p.ap_group_id,
        vlan_id=p.vlan_id,
    )
    return {
        "id": p.id,
        "scope": "existing_ssid_admission",
        "endpoint_trust": "UNMANAGED",
    }


def create_registration_plans(db, app, device, profile, admin):
    if not profile.enabled:
        raise HTTPException(409, "network.profile_disabled")
    if device.device_class != "DEVELOPER":
        raise HTTPException(409, "network.developer_profile_only")
    targets = profile_targets(db, app, profile)
    reservation = db.scalar(
        select(DhcpReservation).where(
            DhcpReservation.device_id == device.id,
            DhcpReservation.subnet_id == profile.subnet_id,
        )
    )
    subnet = db.get(Subnet, profile.subnet_id)
    gateway = db.get(Router, subnet.router_id)
    if (
        not gateway
        or not gateway.snapshot
        or not gateway.last_seen
        or gateway.last_seen < utcnow() - timedelta(seconds=120)
    ):
        raise HTTPException(409, "router.fresh_discovery_required")
    if not reservation:
        from app.api.mikrotik import create_lease_preview

        lease = create_lease_preview(db, app, device, profile.subnet_id, admin)
        lease_plan = db.get(NetworkPlan, lease["plan_id"])
        address = lease["address"]
        # This plan is still inside its creation transaction; no administrator has reviewed it yet.
        if lease_plan.state == "VERIFIED":
            lease_plan.state = "PREVIEW"
    else:
        address = reservation.address
        snapshot = json.loads(app.state.vault.open(gateway.snapshot))
        try:
            operations = reservation_plan(device, subnet, address, snapshot)
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from None
        lease_plan = NetworkPlan(
            device_id=device.id,
            router_id=gateway.id,
            generation=gateway.generation,
            snapshot_hash=snapshot_hash(snapshot),
            operations=operations,
            reason="network.developer_admission",
            author_id=admin.id,
        )
        db.add(lease_plan)
        db.flush()
    result = [lease_plan.id]
    for r, snapshot in targets:
        try:
            operations, requirements = admission_plan(
                device, profile, snapshot, r.capabilities
            )
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from None
        if r.id == gateway.id:
            lease_plan.operations = [*lease_plan.operations, *operations]
            lease_plan.result = {"admission": requirements}
        else:
            p = NetworkPlan(
                device_id=device.id,
                router_id=r.id,
                generation=r.generation,
                snapshot_hash=snapshot_hash(snapshot),
                operations=operations,
                reason="network.developer_admission",
                author_id=admin.id,
                result={"admission": requirements},
            )
            db.add(p)
            db.flush()
            result.append(p.id)
    device.network_profile_id = profile.id
    device.network_state = "ADMISSION_PENDING"
    audit(
        db,
        admin.id,
        "network.admission_preview",
        device.id,
        profile_id=profile.id,
        plan_ids=result,
    )
    return {
        "plan_ids": result,
        "address": address,
        "state": "PREVIEW",
        "endpoint_compliance": "UNMANAGED",
        "scope": "wireless_admission_and_dhcp",
    }


class Authorization(BaseModel):
    profile_id: str
    reason: str = Field(min_length=5, max_length=2000)


@router.post("/developer-devices/{device_id}/authorization-preview")
def authorize(
    device_id: str,
    body: Authorization,
    request: Request,
    admin=Depends(require("approve", mfa=True)),
    db=Depends(db_session),
):
    d = device_or_404(db, device_id)
    p = db.get(NetworkProfile, body.profile_id)
    if not p:
        raise HTTPException(404, "network.profile_not_found")
    return create_registration_plans(db, request.app, d, p, admin)
