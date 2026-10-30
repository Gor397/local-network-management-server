"""Network Explorer: registered, seen on Wi-Fi, reporting through the agent and compliant, kept separate.

Each status comes from its own evidence source and none is inferred from another. Wi-Fi association
lists cover only clients of polled access points, so a computer absent from them (wired, behind another
device, or on an AP Suro does not poll) is "not observed", never "offline".
"""

from datetime import timedelta
from sqlalchemy import func, select
from app.db import utcnow
from app.models import (ApGroup, ApGroupMember, DeploymentTask, Device, DeviceGroup, GroupMember, Router,
                        RouterTelemetry)
from app.services.devices import effective_state

FRESH_SECONDS = 180


class ApResolver:
    """Maps a reporting router plus radio interface to the access point the client is on.

    A CAPsMAN controller reports the clients of all its CAPs; `cap_radios` maps each radio to its CAP.
    """

    def __init__(self, routers):
        self.by_id = {r.id: r for r in routers}
        self.caps = {(r.controller_id, (r.inventory or {}).get("base_mac")): r for r in routers if r.controller_id}

    def resolve(self, router_id, interface):
        reporter = self.by_id.get(router_id)
        if not reporter:
            return None
        cap = self.caps.get((reporter.id, reporter.capabilities.get("cap_radios", {}).get(interface)))
        return cap or reporter


def latest_associations(db, routers, now=None):
    """(access point, reporter, client, observed_at, fresh) from each directly polled router's newest sample."""
    now = now or utcnow()
    resolver = ApResolver(routers)
    reporters = {r.id: r for r in routers if not r.controller_id}
    ranked = select(
        RouterTelemetry.id,
        func.row_number().over(partition_by=RouterTelemetry.router_id, order_by=RouterTelemetry.created_at.desc()).label("position"),
    ).subquery()
    samples = db.scalars(select(RouterTelemetry).join(ranked, ranked.c.id == RouterTelemetry.id)
                         .where(ranked.c.position == 1, RouterTelemetry.router_id.in_(reporters))).all()
    rows = []
    for sample in samples:
        reporter = reporters[sample.router_id]
        fresh = bool(reporter.status == "ONLINE" and (now - sample.created_at).total_seconds() < FRESH_SECONDS)
        for client in sample.clients:
            rows.append((resolver.resolve(reporter.id, client.get("interface")), reporter, client, sample.created_at, fresh))
    return rows, resolver


def _iso(value):
    return value.isoformat() if value else None


def build(db, settings, now=None):
    now = now or utcnow()
    routers = db.scalars(select(Router).where(Router.archived.is_(False))).all()
    associations, resolver = latest_associations(db, routers, now)
    devices = db.scalars(select(Device).where(Device.enabled.is_(True), Device.device_class != "DEVELOPER")).all()
    by_mac = {d.primary_mac: d for d in devices}
    device_groups = {}
    for member in db.scalars(select(GroupMember)):
        device_groups.setdefault(member.device_id, []).append(member.group_id)
    failures = dict(db.execute(select(DeploymentTask.device_id, func.count())
                               .where(DeploymentTask.state.in_(("FAILED", "UNKNOWN"))).group_by(DeploymentTask.device_id)).all())

    access_points = {}
    for r in routers:
        # A router reporting CAP radios is a CAPsMAN controller whatever role an administrator gave it.
        kind = ("controller" if r.capabilities.get("cap_radios") and not r.controller_id
                else "access_point" if r.role == "ACCESS_POINT" or r.controller_id else r.role.lower())
        access_points[r.id] = {"id": r.id, "name": r.name, "kind": kind, "status": r.status, "last_seen": _iso(r.last_seen),
                               "controller_id": r.controller_id, "groups": [], "fresh": False, "clients_total": 0,
                               "registered_now": [], "unregistered_now": 0, "previously_seen": [],
                               "model": (r.inventory or {}).get("model"), "version": (r.inventory or {}).get("version")}
    current = {}
    for ap, reporter, client, observed_at, fresh in associations:
        if not ap or ap.id not in access_points:
            continue
        entry = access_points[ap.id]
        entry["fresh"] = entry["fresh"] or fresh
        if not fresh:
            continue
        entry["clients_total"] += 1
        device = by_mac.get((client.get("mac-address") or "").upper())
        if device:
            entry["registered_now"].append(device.id)
            current[device.id] = (ap.id, client, observed_at)
        else:
            entry["unregistered_now"] += 1
    for member in db.scalars(select(ApGroupMember)):
        if member.router_id in access_points:
            access_points[member.router_id]["groups"].append(member.group_id)

    deadline = now - timedelta(seconds=settings.heartbeat_deadline_seconds)
    rows = {}
    for d in devices:
        evidence = d.network_evidence or {}
        last_ap = resolver.resolve(evidence.get("router_id"), evidence.get("ap"))
        live = current.get(d.id)
        if live:
            wifi = "ASSOCIATED"
        else:
            # A fresh poll of the last-known AP that no longer lists this MAC is evidence of absence there only.
            seen = evidence.get("observed_at") or ""
            wifi = "NOT_ASSOCIATED" if last_ap and seen > (now - timedelta(seconds=FRESH_SECONDS)).isoformat() else "UNKNOWN"
        agent = "NEVER" if not d.last_heartbeat else "ONLINE" if d.last_heartbeat >= deadline else "STALE"
        state, score = effective_state(d, settings, now)
        if last_ap and not live and last_ap.id in access_points:
            access_points[last_ap.id]["previously_seen"].append(d.id)
        rows[d.id] = {
            "id": d.id, "hostname": d.hostname, "mac": d.primary_mac, "owner": d.owner_name, "rank": d.owner_rank,
            "groups": device_groups.get(d.id, []), "enrolled": d.state != "PENDING_ENROLLMENT",
            "wifi": wifi, "ap_id": live[0] if live else None, "last_ap_id": last_ap.id if last_ap else None,
            "signal": (live[1].get("signal") or live[1].get("signal-strength")) if live else None,
            "wifi_observed_at": _iso(live[2]) if live else evidence.get("observed_at"),
            "agent": agent, "last_heartbeat": _iso(d.last_heartbeat),
            "compliance": state, "score": score,
            "awaiting_enforcement": state == "NONCOMPLIANT" and d.mode in ("AUDIT", "PREVIEW"),
            "failed_operations": failures.get(d.id, 0),
            # Never observed by any source: no heartbeat and never matched in a Wi-Fi association list.
            "never_seen": not d.last_heartbeat and not evidence.get("router_id"),
        }
    values = list(rows.values())
    counts = {
        "registered": len(values),
        "wifi_associated": sum(v["wifi"] == "ASSOCIATED" for v in values),
        "agent_online": sum(v["agent"] == "ONLINE" for v in values),
        "agent_offline": sum(v["agent"] != "ONLINE" for v in values),
        "compliant": sum(v["compliance"] == "COMPLIANT" for v in values),
        "noncompliant": sum(v["compliance"] == "NONCOMPLIANT" for v in values),
        "awaiting_enforcement": sum(v["awaiting_enforcement"] for v in values),
        "failed_operations": sum(bool(v["failed_operations"]) for v in values),
        "offline": sum(not v["never_seen"] and v["agent"] != "ONLINE" and v["wifi"] != "ASSOCIATED" for v in values),
        "never_seen": sum(v["never_seen"] for v in values),
        "ungrouped": sum(not v["groups"] for v in values),
        "unregistered_clients": sum(a["unregistered_now"] for a in access_points.values()),
    }
    return {
        "generated_at": _iso(now), "fresh_seconds": FRESH_SECONDS,
        "heartbeat_deadline_seconds": settings.heartbeat_deadline_seconds,
        "ap_groups": [{"id": g.id, "name": g.name} for g in db.scalars(select(ApGroup).order_by(ApGroup.name))],
        "device_groups": [{"id": g.id, "name": g.name} for g in db.scalars(select(DeviceGroup).order_by(DeviceGroup.name))],
        "access_points": sorted(access_points.values(), key=lambda a: a["name"].lower()),
        "devices": sorted(values, key=lambda v: v["hostname"].lower()),
        "counts": counts,
    }
