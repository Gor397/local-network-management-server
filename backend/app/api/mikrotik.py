import ipaddress
import json
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from typing import Literal
from sqlalchemy import select
from app.auth.dependencies import db_session, require, audit
from app.db import utcnow
from app.models import Router, AccessPoint, Subnet, DhcpReservation, NetworkPlan, Device, QuarantineState
from app.services.network import discover, execute_plan
from app.services.devices import device_or_404, normalize_mac, serialize_device
from app.mikrotik.connector import validate_host, redact, snapshot_hash
from app.mikrotik.planner import allocate_address, reservation_plan, disconnect_plan, release_plan

router = APIRouter(prefix="/mikrotik", tags=["mikrotik"])


class RouterCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    base_url: str = Field(max_length=256)
    username: str = Field(max_length=128)
    password: str = Field(min_length=1, max_length=1024)
    ca_file: str | None = None
    transport: Literal["REST", "API_SSL", "API"] = "REST"
    role: Literal["ACCESS_POINT", "ROUTER", "GATEWAY", "CONTROLLER"] = "ACCESS_POINT"
    protected: bool = False

    @field_validator("name", "base_url", "username")
    @classmethod
    def trimmed(cls, value):
        # Pasted values often carry spaces; passwords are deliberately left untouched.
        return value.strip()


@router.get("/routers")
def routers(admin=Depends(require("read")), db=Depends(db_session)):
    rows = db.scalars(select(Router).where(Router.archived.is_(False)).order_by(Router.controller_id.is_not(None), Router.name)).all()
    names = {r.id: r.name for r in rows}
    return [{"id": r.id, "name": r.name, "base_url": r.base_url, "status": r.status,
             "capabilities": r.capabilities, "last_seen": r.last_seen, "write_enabled": r.write_enabled,
             "role": r.role, "protected": r.protected, "transport": r.transport, "inventory": r.inventory,
             "health": r.health, "last_health": r.last_health, "last_inventory": r.last_inventory,
             "last_reboot": r.last_reboot, "desired_config": r.desired_config, "recovery_policy":r.recovery_policy,
             "backup_available": bool(r.snapshot), "controller_id": r.controller_id,
             "controller_name": names.get(r.controller_id)} for r in rows]


@router.post("/routers", status_code=201)
def create_router(body: RouterCreate, request: Request, admin=Depends(require("network")), db=Depends(db_session)):
    try:
        validate_host(body.base_url, request.app.state.settings.router_allowed_networks)
    except (ValueError, OSError):
        raise HTTPException(422, "network.invalid_router_address") from None
    # Literal addresses prevent DNS rebinding between validation and connection.
    from urllib.parse import urlparse
    try:
        address = ipaddress.ip_address(urlparse(body.base_url).hostname)
    except ValueError:
        raise HTTPException(422, "network.literal_ip_required") from None
    for network in request.app.state.settings.router_allowed_networks.split(","):
        network = ipaddress.ip_network(network.strip())
        if network.prefixlen < network.max_prefixlen - 1 and address in (network.network_address, network.broadcast_address):
            raise HTTPException(422, "network.network_address")
    if body.transport == "API" and not request.app.state.settings.router_plaintext_api_allowed:
        raise HTTPException(409, "network.plaintext_api_disabled")
    if db.scalar(select(Router.id).where(Router.archived.is_(True),
                                          (Router.name == body.name) | (Router.base_url == body.base_url.rstrip("/")))):
        raise HTTPException(409, "router.archived_duplicate")
    if body.ca_file:
        from pathlib import Path
        allowed = (request.app.state.settings.data_dir / "trust").resolve()
        path = Path(body.ca_file).resolve()
        if not path.is_relative_to(allowed) or not path.is_file():
            raise HTTPException(422, "network.invalid_ca_file")
    r = Router(name=body.name, base_url=body.base_url.rstrip("/"), username=body.username,
               secret=request.app.state.vault.seal(body.password), ca_file=body.ca_file,
               transport=body.transport, role=body.role, protected=body.protected or body.role == "GATEWAY")
    db.add(r)
    db.flush()
    audit(db, admin.id, "router.registered", r.id)
    return {"id": r.id}


@router.post("/routers/{router_id}/discover")
async def discovery(router_id: str, request: Request, admin=Depends(require("network")), db=Depends(db_session)):
    r = db.get(Router, router_id)
    if not r:
        raise HTTPException(404, "router.not_found")
    if r.transport == "CAPSMAN":
        raise HTTPException(409, "router.managed_by_controller")
    try:
        result = await discover(request.app, db, r)
    except Exception:
        db.commit()
        raise HTTPException(502, "router.discovery_failed") from None
    audit(db, admin.id, "router.discovered", r.id)
    return {"capabilities": result["capabilities"], "snapshot": redact(result["snapshot"])}


@router.get("/routers/{router_id}/inventory")
def inventory(router_id: str, request: Request, admin=Depends(require("read")), db=Depends(db_session)):
    r = db.get(Router, router_id)
    if not r or not r.snapshot:
        raise HTTPException(404, "router.inventory_unavailable")
    return redact(json.loads(request.app.state.vault.open(r.snapshot)))


@router.post("/routers/{router_id}/enable-writes")
def enable_writes(router_id: str, admin=Depends(require("approve", mfa=True)), db=Depends(db_session)):
    r = db.get(Router, router_id)
    if not r or not r.snapshot:
        raise HTTPException(409, "router.discovery_required")
    r.write_enabled = True
    audit(db, admin.id, "router.writes_enabled", r.id)
    return {"enabled": True, "global_gate_also_required": True}


@router.get("/access-points")
def access_points(admin=Depends(require("read")), db=Depends(db_session)):
    return [{"id": a.id, "router_id": a.router_id, "interface": a.interface_name, "stack": a.stack, "details": a.details} for a in db.scalars(select(AccessPoint))]


class SubnetCreate(BaseModel):
    router_id: str
    cidr: str
    dhcp_server: str = Field(max_length=128)
    allocation_start: str
    allocation_end: str
    exclusions: list[str] = Field(default_factory=list)
    profile: str = Field(default="developer", pattern=r"^[a-z][a-z0-9_-]{0,31}$")
    confirm_range_exclusively_managed: bool


@router.get("/subnets")
def subnets(admin=Depends(require("read")), db=Depends(db_session)):
    return [{"id": s.id, "router_id": s.router_id, "cidr": s.cidr, "dhcp_server": s.dhcp_server,
             "allocation_start": s.allocation_start, "allocation_end": s.allocation_end, "profile": s.profile} for s in db.scalars(select(Subnet))]


@router.post("/subnets")
def create_subnet(body: SubnetCreate, request: Request, admin=Depends(require("approve", mfa=True)), db=Depends(db_session)):
    r = db.get(Router, body.router_id)
    if not r or not r.snapshot or not body.confirm_range_exclusively_managed:
        raise HTTPException(409, "network.owned_range_and_discovery_required")
    snapshot = json.loads(request.app.state.vault.open(r.snapshot))
    try:
        network = ipaddress.ip_network(body.cidr, strict=True)
        if network.version != 4 or network.num_addresses > 65536:
            raise ValueError()
        if not any(s.get("name") == body.dhcp_server for s in snapshot["ip/dhcp-server"]):
            raise ValueError()
        if not any(ipaddress.ip_network(n.get("address")) == network for n in snapshot["ip/dhcp-server/network"]):
            raise ValueError()
        for e in body.exclusions:
            ipaddress.ip_network(e, strict=False)
        start, end = ipaddress.ip_address(body.allocation_start), ipaddress.ip_address(body.allocation_end)
        if start not in network or end not in network or start > end:
            raise ValueError()
    except ValueError:
        raise HTTPException(422, "network.invalid_subnet") from None
    s = Subnet(**body.model_dump(exclude={"confirm_range_exclusively_managed"}))
    db.add(s)
    db.flush()
    audit(db, admin.id, "network.subnet_registered", s.id, owned_range=True)
    return {"id": s.id}


@router.get("/dhcp-leases")
def leases(admin=Depends(require("read")), db=Depends(db_session)):
    return [{"id": r.id, "device_id": r.device_id, "subnet_id": r.subnet_id, "address": r.address, "mac": r.mac, "verified_at": r.verified_at} for r in db.scalars(select(DhcpReservation))]


class Reserve(BaseModel):
    subnet_id: str


def create_lease_preview(db, app, d, subnet_id, admin):
    subnet = db.scalar(select(Subnet).where(Subnet.id == subnet_id).with_for_update())
    if not subnet:
        raise HTTPException(404, "network.subnet_not_found")
    r = db.get(Router, subnet.router_id)
    if not r.snapshot or not r.last_seen or (utcnow() - r.last_seen).total_seconds() > 120:
        raise HTTPException(409, "router.fresh_discovery_required")
    snapshot = json.loads(app.state.vault.open(r.snapshot))
    existing = db.scalar(select(DhcpReservation).where(DhcpReservation.device_id == d.id, DhcpReservation.subnet_id == subnet.id))
    if existing:
        raise HTTPException(409, "network.reservation_exists")
    old_lease = next((v for v in snapshot.get("ip/dhcp-server/lease", []) if v.get("mac-address", "").upper() == d.primary_mac and v.get("server") == subnet.dhcp_server), None)
    try:
        if old_lease and old_lease.get("dynamic") == "false":
            address = old_lease["address"]
            if ipaddress.ip_address(address) not in ipaddress.ip_network(subnet.cidr):
                raise ValueError("network.existing_lease_wrong_subnet")
            operations = []
        else:
            occupied = list(db.scalars(select(DhcpReservation.address)))
            address = allocate_address(subnet, snapshot, occupied)
            operations = reservation_plan(d, subnet, address, snapshot)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from None
    reservation = DhcpReservation(device_id=d.id, subnet_id=subnet.id, address=address, mac=d.primary_mac,
                                  verified_at=utcnow() if not operations else None)
    db.add(reservation)
    plan = NetworkPlan(device_id=d.id, router_id=r.id, generation=r.generation, snapshot_hash=snapshot_hash(snapshot),
                       operations=operations, reason="network.dhcp_reservation", author_id=admin.id,
                       state="PREVIEW" if operations else "VERIFIED")
    db.add(plan)
    db.flush()
    audit(db, admin.id, "network.reservation_planned", d.id, plan_id=plan.id, address=address)
    return {"plan_id": plan.id, "address": address, "operations": operations, "authorization": "NOT_GRANTED"}


@router.post("/devices/{device_id}/reservation-preview")
def reserve(device_id: str, body: Reserve, request: Request, admin=Depends(require("network")), db=Depends(db_session)):
    return create_lease_preview(db, request.app, device_or_404(db, device_id), body.subnet_id, admin)


class Developer(BaseModel):
    mac: str
    subnet_id: str|None=None
    profile_id:str|None=None
    hostname: str = Field(default="Developer device", min_length=1, max_length=128)


@router.post("/developer-devices")
def developer(body: Developer, request: Request, admin=Depends(require("network")), db=Depends(db_session)):
    try:
        mac = normalize_mac(body.mac)
    except ValueError:
        raise HTTPException(422, "device.invalid_mac") from None
    if db.scalar(select(Device.id).where(Device.primary_mac == mac)):
        raise HTTPException(409, "device.duplicate_mac")
    d = Device(hostname=body.hostname, primary_mac=mac, device_class="DEVELOPER", state="UNVERIFIED")
    db.add(d)
    db.flush()
    if body.profile_id:
        from app.models import NetworkProfile
        from app.api.profiles import create_registration_plans
        p=db.get(NetworkProfile,body.profile_id)
        if not p:raise HTTPException(404,'network.profile_not_found')
        result=create_registration_plans(db,request.app,d,p,admin)
    elif body.subnet_id:result = create_lease_preview(db, request.app, d, body.subnet_id, admin)
    else:raise HTTPException(422,'network.profile_or_subnet_required')
    audit(db, admin.id, "developer.registered", d.id, endpoint_compliance="UNMANAGED")
    return {"device": serialize_device(d, request.app.state.settings), **result}


@router.get("/plans")
def plans(admin=Depends(require("read")), db=Depends(db_session)):
    return [{"id": p.id, "router_id": p.router_id, "device_id": p.device_id, "state": p.state,
             "operations": redact(p.operations), "reason": p.reason, "result": redact(p.result), "created_at": p.created_at} for p in db.scalars(select(NetworkPlan).order_by(NetworkPlan.created_at.desc()).limit(100))]


@router.post("/plans/{plan_id}/apply")
async def apply_plan(plan_id: str, request: Request, admin=Depends(require("approve", mfa=True)), db=Depends(db_session)):
    p = db.get(NetworkPlan, plan_id)
    if not p:
        raise HTTPException(404, "network.plan_not_found")
    return await execute_plan(request.app, db, p, admin.id)


class NetworkAction(BaseModel):
    reason: str = Field(min_length=5, max_length=2000)


@router.post("/devices/{device_id}/quarantine-preview")
def quarantine(device_id: str, body: NetworkAction, request: Request, admin=Depends(require("network")), db=Depends(db_session)):
    d = device_or_404(db, device_id)
    ids = []
    routers = db.scalars(select(Router)).all()
    if not routers:
        raise HTTPException(409, "network.no_routers")
    for r in routers:
        if not r.snapshot or not r.last_seen or (utcnow() - r.last_seen).total_seconds() > 120:
            raise HTTPException(409, "router.fresh_discovery_required")
        if not r.capabilities.get("stacks"):
            continue
        snapshot = json.loads(request.app.state.vault.open(r.snapshot))
        try:
            operations = disconnect_plan(d, snapshot, r.capabilities)
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from None
        plan = NetworkPlan(device_id=d.id, router_id=r.id, generation=r.generation, snapshot_hash=snapshot_hash(snapshot), operations=operations, reason=body.reason, author_id=admin.id)
        db.add(plan)
        db.flush()
        ids.append(plan.id)
    if not ids:
        raise HTTPException(409, "network.no_supported_wireless_enforcement")
    d.network_state = "QUARANTINE_PENDING"
    db.add(QuarantineState(device_id=d.id, requested=True, reason=body.reason, plan_ids=ids))
    audit(db, admin.id, "network.quarantine_preview", d.id, plan_ids=ids)
    return {"plan_ids": ids, "state": "PREVIEW", "scope": "wireless_rejection", "limitations": ["wired_paths_not_blocked", "remediation_connectivity_not_retained", "all_ap_readback_required"]}


@router.post("/devices/{device_id}/release-preview")
def release(device_id: str, body: NetworkAction, request: Request, admin=Depends(require("approve", mfa=True)), db=Depends(db_session)):
    from app.services.devices import effective_state
    d = device_or_404(db, device_id)
    state, _ = effective_state(d, request.app.state.settings)
    if state != "COMPLIANT":
        raise HTTPException(409, "network.current_compliance_required")
    plans = []
    for r in db.scalars(select(Router)):
        if r.snapshot:
            snapshot = json.loads(request.app.state.vault.open(r.snapshot))
            ops = release_plan(d, snapshot)
            if ops:
                p = NetworkPlan(device_id=d.id, router_id=r.id, generation=r.generation, snapshot_hash=snapshot_hash(snapshot), operations=ops, reason=body.reason, author_id=admin.id)
                db.add(p)
                db.flush()
                plans.append(p.id)
    audit(db, admin.id, "network.release_preview", d.id, plan_ids=plans)
    return {"plan_ids": plans, "state": "PREVIEW"}
