"""Read-only network inventory and descriptive endpoint labels. Never contacts routers or endpoints."""
import json
from typing import Literal
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from app.auth.dependencies import db_session, require, audit
from app.db import utcnow
from app.models import Router, Device, DeviceCredential, NetworkEndpointLabel
from app.services.devices import normalize_mac
from app.services.inventory import build, access_points, CATEGORIES

router = APIRouter(tags=["network inventory"])


@router.get("/network/inventory")
def inventory(request: Request, q: str = "", enrollment: str = "", offset: int = 0, limit: int = 50,
              admin=Depends(require("read")), db=Depends(db_session)):
    vault, now = request.app.state.vault, utcnow()
    routers = []
    for r in db.scalars(select(Router).where(Router.archived.is_(False), Router.snapshot.is_not(None))):
        try:
            routers.append((r, json.loads(vault.open(r.snapshot))))
        except Exception:
            continue  # An unreadable snapshot is reported by router health, not here.
    devices = {d.primary_mac: d for d in db.scalars(select(Device).where(Device.enabled.is_(True)))}
    enrolled = set(db.scalars(select(DeviceCredential.device_id).where(DeviceCredential.revoked.is_(False))))
    labels = {label.mac: label for label in db.scalars(select(NetworkEndpointLabel))}
    items = build(routers, devices, enrolled, labels, now, request.app.state.settings.heartbeat_deadline_seconds)
    if q:
        needle = q.lower()
        items = [i for i in items if needle in " ".join([i["mac"], *i["addresses"], *i["hostnames"], i["label"], i["device_hostname"] or ""]).lower()]
    if enrollment:
        items = [i for i in items if i["enrollment"] == enrollment]
    summary = {}
    for i in items:
        summary[i["enrollment"]] = summary.get(i["enrollment"], 0) + 1
    limit = min(100, max(1, limit))
    return {"total": len(items), "summary": summary, "routers": len(routers), "categories": CATEGORIES,
            "access_points": access_points(routers) if offset == 0 else [],
            "items": items[max(0, offset):max(0, offset) + limit]}


class Label(BaseModel):
    category: Literal[CATEGORIES] = "UNKNOWN"
    label: str = Field(default="", max_length=128)
    note: str = Field(default="", max_length=2000)


@router.put("/network/inventory/{mac}/label")
def set_label(mac: str, body: Label, admin=Depends(require("manage")), db=Depends(db_session)):
    try:
        mac = normalize_mac(mac)
    except ValueError:
        raise HTTPException(422, "device.invalid_mac") from None
    record = db.scalar(select(NetworkEndpointLabel).where(NetworkEndpointLabel.mac == mac))
    if not record:
        record = NetworkEndpointLabel(mac=mac)
        db.add(record)
    record.category, record.label, record.note = body.category, body.label, body.note
    record.updated_by, record.updated_at = admin.id, utcnow()
    audit(db, admin.id, "network.endpoint_labelled", mac, category=body.category)
    return {"mac": mac, "category": record.category, "label": record.label, "note": record.note}
