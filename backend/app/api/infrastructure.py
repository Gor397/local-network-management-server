from datetime import datetime, timedelta, timezone
from typing import Literal
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select, delete, func
from app.auth.dependencies import db_session, require, audit
from app.db import utcnow
from app.models import (
    Router,
    ApGroup,
    ApGroupMember,
    NetworkBatch,
    OperationTarget,
    ConfigurationBackup,
    RouterTelemetry,
    MaintenanceWindow,
    Incident,
    Device,
    Subnet,
    GroupMember,
)
from app.services.infrastructure import preview_router, DISRUPTIVE
from app.mikrotik.connector import redact

router = APIRouter(tags=["infrastructure"])


def as_utc(value):
    return (
        value.astimezone(timezone.utc).replace(tzinfo=None) if value.tzinfo else value
    )


def get_router(db, router_id):
    r = db.get(Router, router_id)
    if not r:
        raise HTTPException(404, "router.not_found")
    return r


class RouterEdit(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    role: Literal["ACCESS_POINT", "ROUTER", "GATEWAY", "CONTROLLER"] = "ACCESS_POINT"
    protected: bool = False
    ssh_host_key: str | None = Field(default=None, max_length=4096)


@router.patch("/mikrotik/routers/{router_id}")
def edit_router(
    router_id: str,
    body: RouterEdit,
    admin=Depends(require("approve", mfa=True)),
    db=Depends(db_session),
):
    r = get_router(db, router_id)
    if body.ssh_host_key:
        import asyncssh

        try:
            asyncssh.import_public_key(body.ssh_host_key)
        except asyncssh.KeyImportError:
            raise HTTPException(422, "ssh.invalid_public_key") from None
    r.name, r.role, r.protected = (
        body.name,
        body.role,
        body.protected or body.role == "GATEWAY",
    )
    if "ssh_host_key" in body.model_fields_set:
        r.ssh_host_key = body.ssh_host_key
    audit(db, admin.id, "router.updated", r.id, role=r.role, protected=r.protected)
    return {"ok": True}


@router.delete("/mikrotik/routers/{router_id}")
def archive(
    router_id: str, admin=Depends(require("approve", mfa=True)), db=Depends(db_session)
):
    r = get_router(db, router_id)
    r.archived = True
    r.write_enabled = False
    # A controller's CAPsMAN access points are only known through it.
    for cap in db.scalars(select(Router).where(Router.controller_id == r.id)):
        cap.archived = True
    audit(db, admin.id, "router.archived", r.id)
    return {"archived": True, "configuration_unchanged": True}


@router.get("/mikrotik/routers/archived")
def archived_routers(admin=Depends(require("read")), db=Depends(db_session)):
    rows = db.scalars(select(Router).where(Router.archived.is_(True)).order_by(Router.name)).all()
    archived = {r.id for r in rows}
    # CAPs archived together with their controller are listed (and deleted) through the controller.
    return [{"id": r.id, "name": r.name, "base_url": r.base_url, "role": r.role, "transport": r.transport}
            for r in rows if r.controller_id not in archived]


@router.delete("/mikrotik/routers/{router_id}/permanent")
def purge(router_id: str, confirm_name: str, admin=Depends(require("approve", mfa=True)), db=Depends(db_session)):
    """Remove Suro's records for a router. Never contacts the router; its configuration is unchanged."""
    from app.models import (AccessPoint, Subnet, NetworkAccessRule, NetworkPlan, ApGroupMember,
                            RouterTelemetry, OperationTarget, ConfigurationBackup)
    r = get_router(db, router_id)
    if confirm_name != r.name:
        raise HTTPException(409, "router.confirm_name_mismatch")
    # Records of changes Suro made on the router are its only ownership/rollback trail; keep them.
    if (db.scalar(select(NetworkAccessRule.id).where(NetworkAccessRule.router_id == r.id).limit(1))
            or db.scalar(select(Subnet.id).where(Subnet.router_id == r.id).limit(1))
            or db.scalar(select(NetworkPlan.id).where(NetworkPlan.router_id == r.id, NetworkPlan.state != "PREVIEW").limit(1))
            or db.scalar(select(OperationTarget.id).where(OperationTarget.router_id == r.id,
                                                          OperationTarget.state.in_(["RUNNING", "WAITING_RECONNECT"])).limit(1))):
        raise HTTPException(409, "router.has_managed_changes")
    caps = db.scalars(select(Router.id).where(Router.controller_id == r.id)).all()
    for identifier in [*caps, r.id]:
        for model in (AccessPoint, ApGroupMember, RouterTelemetry, ConfigurationBackup, NetworkPlan):
            db.execute(delete(model).where(model.router_id == identifier))
        # Batch history keeps its rows without the router reference.
        db.query(OperationTarget).filter(OperationTarget.router_id == identifier).update({"router_id": None})
    db.execute(delete(Router).where(Router.controller_id == r.id))
    name = r.name
    db.delete(r)
    audit(db, admin.id, "router.deleted_permanently", router_id, name=name)
    return {"deleted": True, "configuration_unchanged": True}


@router.get("/mikrotik/routers/{router_id}/telemetry")
def telemetry(router_id: str, admin=Depends(require("read")), db=Depends(db_session)):
    get_router(db, router_id)
    return [
        {
            "at": t.created_at,
            "metrics": t.metrics,
            "clients": t.clients,
            "facts": t.facts,
        }
        for t in db.scalars(
            select(RouterTelemetry)
            .where(RouterTelemetry.router_id == router_id)
            .order_by(RouterTelemetry.created_at.desc())
            .limit(60)
        )
    ]


@router.get("/mikrotik/routers/{router_id}/backups")
def backups(router_id: str, admin=Depends(require("network")), db=Depends(db_session)):
    return [
        {
            "id": b.id,
            "kind": b.kind,
            "at": b.created_at,
            "hash": b.content_hash,
            "metadata": redact(b.metadata_),
        }
        for b in db.scalars(
            select(ConfigurationBackup)
            .where(ConfigurationBackup.router_id == router_id)
            .order_by(ConfigurationBackup.created_at.desc())
            .limit(100)
        )
    ]


class ApGroupEdit(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    description: str = Field(default="", max_length=2000)
    router_ids: list[str] = Field(default_factory=list, max_length=1000)
    template: dict = Field(default_factory=dict)


def save_group(db, group, body, admin):
    for router_id in set(body.router_ids):
        get_router(db, router_id)
    group.name, group.description, group.template = (
        body.name,
        body.description,
        body.template,
    )
    group.revision = (group.revision or 0) + 1
    db.flush()
    db.execute(delete(ApGroupMember).where(ApGroupMember.group_id == group.id))
    for router_id in set(body.router_ids):
        db.add(ApGroupMember(group_id=group.id, router_id=router_id))
    audit(
        db,
        admin.id,
        "ap_group.saved",
        group.id,
        routers=body.router_ids,
        revision=group.revision,
    )
    return {"id": group.id, "revision": group.revision}


@router.get("/mikrotik/groups")
def ap_groups(admin=Depends(require("read")), db=Depends(db_session)):
    members = {}
    routers = {
        r.id: r for r in db.scalars(select(Router).where(Router.archived.is_(False)))
    }
    for m in db.scalars(select(ApGroupMember)):
        members.setdefault(m.group_id, []).append(m.router_id)
    result = []
    for g in db.scalars(select(ApGroup).order_by(ApGroup.name)):
        ids = [i for i in members.get(g.id, []) if i in routers]
        result.append(
            {
                "id": g.id,
                "name": g.name,
                "description": g.description,
                "template": g.template,
                "revision": g.revision,
                "router_ids": ids,
                "online": sum(routers[i].status == "ONLINE" for i in ids),
                "offline": sum(routers[i].status == "UNAVAILABLE" for i in ids),
                "connected_clients": sum(
                    routers[i].health.get("client_count", 0) for i in ids
                ),
            }
        )
    return result


@router.post("/mikrotik/groups")
def create_group(
    body: ApGroupEdit, admin=Depends(require("network")), db=Depends(db_session)
):
    group = ApGroup(name=body.name)
    db.add(group)
    return save_group(db, group, body, admin)


@router.put("/mikrotik/groups/{group_id}")
def update_group(
    group_id: str,
    body: ApGroupEdit,
    admin=Depends(require("network")),
    db=Depends(db_session),
):
    g = db.get(ApGroup, group_id)
    if not g:
        raise HTTPException(404, "group.not_found")
    return save_group(db, g, body, admin)


@router.delete("/mikrotik/groups/{group_id}")
def delete_group(
    group_id: str, admin=Depends(require("network")), db=Depends(db_session)
):
    g = db.get(ApGroup, group_id)
    if not g:
        raise HTTPException(404, "group.not_found")
    db.execute(delete(ApGroupMember).where(ApGroupMember.group_id == g.id))
    db.delete(g)
    audit(db, admin.id, "ap_group.deleted", group_id)
    return {"ok": True}


class BatchCreate(BaseModel):
    router_ids: list[str] = Field(default_factory=list, max_length=1000)
    group_id: str | None = None
    operation: Literal[
        "reboot",
        "wireless",
        "identity",
        "snapshot",
        "restore_fields",
        "binary_backup",
        "binary_restore",
        "upgrade",
        "diagnostics",
        "template",
    ]
    parameters: dict = Field(default_factory=dict)
    batch_size: int = Field(default=1, ge=1, le=5)
    stop_on_failure: bool = True
    not_before: datetime | None = None
    window_end: datetime | None = None
    reason: str = Field(min_length=5, max_length=2000)


@router.post("/network/operations/preview")
def preview(
    body: BatchCreate,
    request: Request,
    admin=Depends(require("network")),
    db=Depends(db_session),
):
    ids = set(body.router_ids)
    if body.group_id:
        ids.update(
            db.scalars(
                select(ApGroupMember.router_id).where(
                    ApGroupMember.group_id == body.group_id
                )
            )
        )
    if not ids:
        raise HTTPException(422, "network.no_targets")
    values = dict(body.parameters)
    if body.operation == "template" and body.group_id:
        g = db.get(ApGroup, body.group_id)
        if not g:
            raise HTTPException(404, "group.not_found")
        values = dict(g.template)
        # A shared physical AP must not silently choose one conflicting group template.
        for i in ids:
            others = db.scalars(
                select(ApGroup)
                .join(ApGroupMember)
                .where(ApGroupMember.router_id == i, ApGroup.id != g.id)
            ).all()
            if any(other.template and other.template != g.template for other in others):
                raise HTTPException(409, "network.group_template_conflict")
    start = as_utc(body.not_before) if body.not_before else utcnow()
    end = as_utc(body.window_end) if body.window_end else None
    if end and end <= start:
        raise HTTPException(422, "maintenance.invalid_window")
    b = NetworkBatch(
        operation=body.operation,
        parameters=values,
        batch_size=body.batch_size,
        stop_on_failure=body.stop_on_failure,
        not_before=start,
        window_end=end,
        reason=body.reason,
        author_id=admin.id,
    )
    db.add(b)
    db.flush()
    for i in sorted(ids):
        r = get_router(db, i)
        try:
            result = preview_router(request.app, db, r, body.operation, values)
        except ValueError as exc:
            result = {"compatible": False, "code": str(exc)}
        result.update(
            {"router_name": r.name, "protected": r.protected or r.role == "GATEWAY"}
        )
        db.add(OperationTarget(batch_id=b.id, router_id=i, preview=result))
    audit(
        db,
        admin.id,
        "network.batch_preview",
        b.id,
        targets=sorted(ids),
        operation=b.operation,
    )
    db.flush()
    return batch_detail(b.id, admin, db)


class Approval(BaseModel):
    confirm: bool
    confirmed_protected: list[str] = Field(default_factory=list)
    out_of_band_confirmed: bool = False


@router.post("/network/operations/{batch_id}/approve")
def approve(
    batch_id: str,
    body: Approval,
    request: Request,
    admin=Depends(require("approve", mfa=True)),
    db=Depends(db_session),
):
    b = db.scalar(
        select(NetworkBatch).where(NetworkBatch.id == batch_id).with_for_update()
    )
    if not b or b.state != "PREVIEW" or b.created_at < utcnow() - timedelta(minutes=10):
        raise HTTPException(409, "network.preview_expired")
    from app.services.safety import blocks_all_changes
    blocked = blocks_all_changes(request.app.state.settings)
    if b.operation not in ("snapshot", "diagnostics") and blocked:
        # The preview already is the dry run; approving it would only queue targets that must fail.
        raise HTTPException(409, blocked)
    targets = db.scalars(
        select(OperationTarget).where(OperationTarget.batch_id == b.id)
    ).all()
    if not body.confirm or any(not t.preview.get("compatible") for t in targets):
        raise HTTPException(409, "network.incompatible_targets")
    for t in targets:
        r = get_router(db, t.router_id)
        if r.archived:
            raise HTTPException(409, "router.archived")
        if b.operation in DISRUPTIVE and (r.protected or r.role == "GATEWAY"):
            if r.name not in body.confirmed_protected or not body.out_of_band_confirmed:
                raise HTTPException(409, "network.protected_confirmation_required")
    if (
        b.operation in DISRUPTIVE
        and not body.out_of_band_confirmed
        and not b.parameters.get("independent_management_router_ids")
    ):
        raise HTTPException(409, "network.last_management_path")
    b.parameters = {
        **b.parameters,
        "out_of_band_confirmed": body.out_of_band_confirmed,
        "confirmed_protected": body.confirmed_protected,
    }
    b.state, b.approved_at = "APPROVED", utcnow()
    audit(
        db,
        admin.id,
        "network.batch_approved",
        b.id,
        protected=body.confirmed_protected,
        out_of_band=body.out_of_band_confirmed,
    )
    return {"state": b.state}


@router.get("/network/operations")
def batches(
    kind: str | None = None, admin=Depends(require("read")), db=Depends(db_session)
):
    query = select(NetworkBatch)
    if kind:
        query = query.where(NetworkBatch.kind == kind)
    return [
        {
            "id": b.id,
            "operation": b.operation,
            "kind": b.kind,
            "state": b.state,
            "at": b.created_at,
            "not_before": b.not_before,
            "batch_size": b.batch_size,
            "reason": b.reason,
        }
        for b in db.scalars(query.order_by(NetworkBatch.created_at.desc()).limit(100))
    ]


@router.get("/network/operations/{batch_id}")
def batch_detail(batch_id: str, admin=Depends(require("read")), db=Depends(db_session)):
    b = db.get(NetworkBatch, batch_id)
    if not b:
        raise HTTPException(404, "network.operation_not_found")
    return {
        "id": b.id,
        "operation": b.operation,
        "state": b.state,
        "batch_size": b.batch_size,
        "stop_on_failure": b.stop_on_failure,
        "targets": [
            {
                "id": t.id,
                "router_id": t.router_id,
                "device_id": t.device_id,
                "state": t.state,
                "preview": redact(t.preview),
                "result": redact(t.result),
            }
            for t in db.scalars(
                select(OperationTarget).where(OperationTarget.batch_id == b.id)
            )
        ],
    }


@router.post("/network/operations/{batch_id}/cancel")
def cancel(
    batch_id: str, admin=Depends(require("approve", mfa=True)), db=Depends(db_session)
):
    b = db.get(NetworkBatch, batch_id)
    if not b:
        raise HTTPException(404, "network.operation_not_found")
    b.state = "CANCELLED"
    audit(db, admin.id, "network.batch_cancelled", b.id)
    return {"state": b.state, "running_actions": "verification_must_continue"}


@router.get("/network/overview")
def overview(admin=Depends(require("read")), db=Depends(db_session)):
    rows = db.scalars(select(Router).where(Router.archived.is_(False))).all()
    return {
        "total": len(rows),
        "online": sum(r.status == "ONLINE" for r in rows),
        "offline": sum(r.status == "UNAVAILABLE" for r in rows),
        "unhealthy": sum(
            (r.health.get("cpu_percent") or 0) >= 90
            or (r.health.get("memory_percent") or 0) >= 90
            for r in rows
        ),
        "connected_clients": sum(r.health.get("client_count", 0) for r in rows),
        "incidents": db.scalar(
            select(func.count())
            .select_from(Incident)
            .where(Incident.state != "RESOLVED")
        ),
        "groups": ap_groups(admin, db),
    }


@router.get("/network/clients")
def clients(
    request: Request,
    group_id: str | None = None,
    q: str = "",
    offset: int = 0,
    limit: int = 50,
    admin=Depends(require("read")),
    db=Depends(db_session),
):
    import json
    from app.services.explorer import latest_associations
    routers = db.scalars(select(Router).where(Router.archived.is_(False))).all()
    selected = None
    if group_id:
        selected = set(db.scalars(select(ApGroupMember.router_id).where(ApGroupMember.group_id == group_id)))
    # Clients are reported by directly managed routers (a CAPsMAN controller reports all its CAPs).
    associations, _ = latest_associations(db, routers)
    devices = {d.primary_mac: d for d in db.scalars(select(Device).where(Device.enabled.is_(True)))}
    hostnames = {}
    rows = []
    for ap, r, client, observed_at, fresh in associations:
        if r.id not in hostnames:
            hostnames[r.id] = {}
            if r.snapshot:
                try:
                    for lease in json.loads(request.app.state.vault.open(r.snapshot)).get("ip/dhcp-server/lease", []):
                        if lease.get("host-name"):
                            hostnames[r.id][(lease.get("mac-address") or "").upper()] = lease["host-name"]
                except Exception:
                    pass
        mac = client.get("mac-address", "").upper()
        if selected is not None and r.id not in selected and ap.id not in selected:
            continue
        d = devices.get(mac)
        rows.append({
            "router_id": r.id,
            "router_name": r.name,
            "access_point_id": ap.id,
            "access_point": ap.name,
            "device_id": d.id if d else None,
            "hostname": d.hostname if d else hostnames[r.id].get(mac),
            "registered": bool(d),
            # The access-list comment: an administrator label, not verified identity.
            "label": client.get("comment") or "",
            "observation": redact(client),
            "observed_at": observed_at,
            "fresh": fresh,
        })
    if q:
        needle = q.lower()
        rows = [x for x in rows if needle in " ".join(str(v) for v in (x["hostname"], x["label"], x["access_point"],
                                                                      x["observation"].get("mac-address"))).lower()]
    rows.sort(key=lambda item: (item["access_point"], item["hostname"] or "~", item["observation"].get("mac-address", "")))
    return {
        "total": len(rows),
        "items": rows[max(0, offset) : max(0, offset) + min(100, max(1, limit))],
    }


@router.get("/network/explorer")
def explorer(request: Request, admin=Depends(require("read")), db=Depends(db_session)):
    from app.services.explorer import build
    return build(db, request.app.state.settings)


@router.get("/network/topology")
def topology(
    group_id: str | None = None,
    device_group_id: str | None = None,
    subnet: str | None = None,
    health: str | None = None,
    admin=Depends(require("read")),
    db=Depends(db_session),
):
    routers = db.scalars(select(Router).where(Router.archived.is_(False))).all()
    if group_id:
        ids = set(
            db.scalars(
                select(ApGroupMember.router_id).where(
                    ApGroupMember.group_id == group_id
                )
            )
        )
        routers = [r for r in routers if r.id in ids]
    if health:
        routers = [r for r in routers if r.status == health]
    nodes = [{"id": "server", "kind": "server", "name": "Suro", "state": "ONLINE"}] + [
        {
            "id": r.id,
            "kind": "router",
            "name": r.name,
            "role": r.role,
            "state": r.status,
        }
        for r in routers
    ]
    edges = [
        {
            "source": "server",
            "target": r.id,
            "kind": "management",
            "assurance": "OBSERVED"
            if r.last_seen and (utcnow() - r.last_seen).total_seconds() < 180
            else "UNKNOWN",
            "observed_at": r.last_seen,
        }
        for r in routers
    ]
    allowed = {r.id for r in routers}
    devices = db.scalars(select(Device).where(Device.enabled.is_(True))).all()
    if device_group_id:
        ids = set(
            db.scalars(
                select(GroupMember.device_id).where(
                    GroupMember.group_id == device_group_id
                )
            )
        )
        devices = [d for d in devices if d.id in ids]
    import ipaddress

    for d in devices:
        r_id = d.network_evidence.get("router_id")
        if r_id not in allowed:
            continue
        if subnet:
            try:
                if ipaddress.ip_address(
                    d.network_evidence.get("ip")
                ) not in ipaddress.ip_network(subnet):
                    continue
            except (ValueError, TypeError):
                continue
        fresh = (
            d.network_evidence.get("connected")
            and d.network_evidence.get("observed_at", "")
            > (utcnow() - timedelta(seconds=180)).isoformat()
        )
        nodes.append(
            {
                "id": d.id,
                "kind": "device",
                "name": d.hostname,
                "state": d.state,
                "owner": d.owner_name,
            }
        )
        edges.append(
            {
                "source": r_id,
                "target": d.id,
                "kind": "association",
                "assurance": "OBSERVED" if fresh else "UNKNOWN",
                "observed_at": d.network_evidence.get("observed_at"),
            }
        )
    for s in db.scalars(select(Subnet).where(Subnet.router_id.in_(allowed))):
        nodes.append(
            {
                "id": s.id,
                "kind": "subnet",
                "name": s.cidr,
                "vlan": None,
                "state": "CONFIGURED",
            }
        )
        edges.append(
            {
                "source": s.router_id,
                "target": s.id,
                "kind": "configured_subnet",
                "assurance": "ADMIN_CONFIGURED",
            }
        )
    ap_members = {}
    for membership in db.scalars(
        select(ApGroupMember).where(ApGroupMember.router_id.in_(allowed))
    ):
        ap_members.setdefault(membership.group_id, []).append(membership.router_id)
    for g in db.scalars(select(ApGroup).where(ApGroup.id.in_(ap_members))):
        members = ap_members[g.id]
        if members:
            group_node = "ap-group:" + g.id
            nodes.append(
                {
                    "id": group_node,
                    "kind": "ap_group",
                    "name": g.name,
                    "state": "CONFIGURED",
                }
            )
            edges.extend(
                {
                    "source": group_node,
                    "target": i,
                    "kind": "group_membership",
                    "assurance": "ADMIN_CONFIGURED",
                }
                for i in members
            )
    visible_devices = {n["id"] for n in nodes if n["kind"] == "device"}
    from app.models import DeviceGroup

    device_members = {}
    for membership in db.scalars(
        select(GroupMember).where(GroupMember.device_id.in_(visible_devices))
    ):
        device_members.setdefault(membership.group_id, []).append(membership.device_id)
    for g in db.scalars(select(DeviceGroup).where(DeviceGroup.id.in_(device_members))):
        members = device_members[g.id]
        if members:
            group_node = "device-group:" + g.id
            nodes.append(
                {
                    "id": group_node,
                    "kind": "device_group",
                    "name": g.name,
                    "state": "CONFIGURED",
                }
            )
            edges.extend(
                {
                    "source": group_node,
                    "target": i,
                    "kind": "group_membership",
                    "assurance": "ADMIN_CONFIGURED",
                }
                for i in members
            )
    for r in routers:
        for vlan in r.inventory.get("vlans", []):
            if not vlan.get("vlan-ids"):
                continue
            node_id = r.id + ":vlan:" + str(vlan.get(".id", vlan["vlan-ids"]))
            nodes.append(
                {
                    "id": node_id,
                    "kind": "vlan",
                    "name": "VLAN " + vlan["vlan-ids"],
                    "state": "OBSERVED",
                }
            )
            edges.append(
                {
                    "source": r.id,
                    "target": node_id,
                    "kind": "observed_vlan_configuration",
                    "assurance": "OBSERVED",
                }
            )
    # Upstream physical links are not inferred from shared IP prefixes.
    return {
        "nodes": nodes,
        "edges": edges,
        "unknown_links": ["physical_uplinks", "unobserved_vlan_paths"],
    }


class WindowCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    starts_at: datetime
    ends_at: datetime
    router_ids: list[str] = Field(default_factory=list)
    device_ids: list[str] = Field(default_factory=list)


@router.post("/maintenance-windows")
def create_window(
    body: WindowCreate,
    admin=Depends(require("approve", mfa=True)),
    db=Depends(db_session),
):
    if body.ends_at <= body.starts_at:
        raise HTTPException(422, "maintenance.invalid_window")
    values = body.model_dump()
    values["starts_at"] = as_utc(body.starts_at)
    values["ends_at"] = as_utc(body.ends_at)
    w = MaintenanceWindow(**values, author_id=admin.id)
    db.add(w)
    db.flush()
    audit(db, admin.id, "maintenance.window_created", w.id)
    return {"id": w.id}


@router.get("/maintenance-windows")
def windows(admin=Depends(require("read")), db=Depends(db_session)):
    return [
        {
            "id": w.id,
            "name": w.name,
            "starts_at": w.starts_at,
            "ends_at": w.ends_at,
            "router_ids": w.router_ids,
            "device_ids": w.device_ids,
        }
        for w in db.scalars(
            select(MaintenanceWindow)
            .order_by(MaintenanceWindow.starts_at.desc())
            .limit(100)
        )
    ]
