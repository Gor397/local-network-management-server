from datetime import datetime, timedelta, timezone
from typing import Literal
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from app.auth.dependencies import db_session, require, agent_identity, audit
from app.db import utcnow
from app.models import (
    ClientObservation,
    Incident,
    IncidentHistory,
    Administrator,
    Router,
)

router = APIRouter(tags=["diagnostics"])


class Observation(BaseModel):
    sequence: str = Field(min_length=16, max_length=64)
    observed_at: datetime
    ssid: str | None = Field(default=None, max_length=128)
    bssid: str | None = Field(default=None, max_length=17)
    signal_quality: int | None = Field(default=None, ge=0, le=100)
    ip_addresses: list[str] = Field(default_factory=list, max_length=16)
    gateways: list[str] = Field(default_factory=list, max_length=8)
    dns: list[str] = Field(default_factory=list, max_length=8)
    connection_state: str = Field(default="UNKNOWN", max_length=32)
    management_reachable: bool | None = None
    events: list[dict] = Field(default_factory=list, max_length=20)


class Observations(BaseModel):
    observations: list[Observation] = Field(max_length=100)


@router.post("/agent/diagnostics")
def observations(body: Observations, d=Depends(agent_identity), db=Depends(db_session)):
    now = utcnow()
    accepted = []
    for observation in body.observations:
        at = (
            observation.observed_at.astimezone(timezone.utc).replace(tzinfo=None)
            if observation.observed_at.tzinfo
            else observation.observed_at
        )
        if not now - timedelta(days=3) <= at <= now + timedelta(seconds=60):
            continue
        existing = db.scalar(
            select(ClientObservation.id).where(
                ClientObservation.device_id == d.id,
                ClientObservation.sequence == observation.sequence,
            )
        )
        if not existing:
            data = observation.model_dump(
                mode="json", exclude={"sequence", "observed_at"}
            )
            data["events"] = [
                {
                    k: v
                    for k, v in event.items()
                    if k in ("event_id", "record_id", "at", "reason", "ssid", "bssid")
                }
                for event in observation.events
            ]
            db.add(
                ClientObservation(
                    device_id=d.id,
                    sequence=observation.sequence,
                    observed_at=at,
                    data=data,
                )
            )
        accepted.append(observation.sequence)
    return {"accepted": accepted}


@router.get("/devices/{device_id}/diagnostics")
def client_diagnostics(
    device_id: str, admin=Depends(require("read")), db=Depends(db_session)
):
    return [
        {"at": o.observed_at, "data": o.data}
        for o in db.scalars(
            select(ClientObservation)
            .where(ClientObservation.device_id == device_id)
            .order_by(ClientObservation.observed_at.desc())
            .limit(100)
        )
    ]


@router.get("/incidents")
def incidents(
    router_id: str | None = None,
    group_id: str | None = None,
    state: str | None = None,
    offset: int = 0,
    limit: int = 50,
    admin=Depends(require("read")),
    db=Depends(db_session),
):
    query = select(Incident)
    if state:
        query = query.where(Incident.state == state)
    rows = db.scalars(query.order_by(Incident.last_observed.desc()).limit(1000)).all()
    if group_id:
        from app.models import ApGroupMember

        ids = set(
            db.scalars(
                select(ApGroupMember.router_id).where(
                    ApGroupMember.group_id == group_id
                )
            )
        )
        rows = [i for i in rows if ids.intersection(i.router_ids)]
    if router_id:
        rows = [i for i in rows if router_id in i.router_ids]
    return {
        "total": len(rows),
        "items": [
            {
                "id": i.id,
                "title_key": i.title_key,
                "cause_key": i.cause_key,
                "confidence": i.confidence,
                "severity": i.severity,
                "router_ids": i.router_ids,
                "device_ids": i.device_ids,
                "facts": i.facts,
                "recommendations": i.recommendations,
                "state": i.state,
                "first_detected": i.created_at,
                "last_observed": i.last_observed,
                "assigned_to": i.assigned_to,
                "acknowledged_by": i.acknowledged_by,
            }
            for i in rows[max(0, offset) : max(0, offset) + min(100, max(1, limit))]
        ],
    }


class IncidentUpdate(BaseModel):
    state: Literal["OPEN", "ACKNOWLEDGED", "INVESTIGATING", "RESOLVED"]
    assigned_to: str | None = None
    reason: str = Field(min_length=5, max_length=2000)


@router.patch("/incidents/{incident_id}")
def update_incident(
    incident_id: str,
    body: IncidentUpdate,
    admin=Depends(require("manage")),
    db=Depends(db_session),
):
    i = db.get(Incident, incident_id)
    if not i:
        raise HTTPException(404, "incident.not_found")
    if body.assigned_to and not db.get(Administrator, body.assigned_to):
        raise HTTPException(422, "auth.admin_not_found")
    i.state, i.assigned_to = body.state, body.assigned_to
    if body.state == "ACKNOWLEDGED":
        i.acknowledged_by = admin.id
    i.resolved_at = utcnow() if body.state == "RESOLVED" else None
    db.add(
        IncidentHistory(
            incident_id=i.id,
            actor_id=admin.id,
            action=body.state,
            details={"reason": body.reason},
        )
    )
    audit(db, admin.id, "incident.updated", i.id, state=i.state, reason=body.reason)
    return {"ok": True}


@router.get("/incidents/{incident_id}/history")
def history(incident_id: str, admin=Depends(require("read")), db=Depends(db_session)):
    return [
        {
            "at": h.created_at,
            "actor_id": h.actor_id,
            "action": h.action,
            "details": h.details,
        }
        for h in db.scalars(
            select(IncidentHistory)
            .where(IncidentHistory.incident_id == incident_id)
            .order_by(IncidentHistory.created_at.desc())
            .limit(100)
        )
    ]


class RecoveryPolicy(BaseModel):
    enabled: bool = False
    conditions: list[Literal["resource_pressure", "unexpected_radio_disabled"]] = Field(
        default_factory=lambda: ["resource_pressure"], min_length=1, max_length=2
    )
    sustained_seconds: int = Field(default=300, ge=180, le=3600)
    cooldown_seconds: int = Field(default=3600, ge=900, le=86400)
    max_attempts_per_day: int = Field(default=2, ge=1, le=3)
    independent_management_router_ids: list[str] = Field(
        default_factory=list, max_length=16
    )
    require_maintenance_window: bool = True


@router.put("/mikrotik/routers/{router_id}/recovery-policy")
def recovery_policy(
    router_id: str,
    body: RecoveryPolicy,
    request: Request,
    admin=Depends(require("approve", mfa=True)),
    db=Depends(db_session),
):
    r = db.get(Router, router_id)
    if not r:
        raise HTTPException(404, "router.not_found")
    if body.enabled and (r.role != "ACCESS_POINT" or r.protected):
        raise HTTPException(409, "recovery.protected_infrastructure")
    if body.enabled and (
        not body.independent_management_router_ids
        or router_id in body.independent_management_router_ids
    ):
        raise HTTPException(409, "recovery.independent_path_required")
    for i in body.independent_management_router_ids:
        if not db.get(Router, i):
            raise HTTPException(422, "router.not_found")
    r.recovery_policy = {**body.model_dump(), "failures": 0}
    audit(db, admin.id, "recovery.policy_saved", r.id, enabled=body.enabled)
    return {"ok": True, "global_enabled": request.app.state.settings.recovery_enabled}
