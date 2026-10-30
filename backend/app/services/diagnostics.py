from collections import defaultdict
from datetime import timedelta
from sqlalchemy import select
from app.db import utcnow
from app.models import (
    Router,
    RouterTelemetry,
    Device,
    ClientObservation,
    Incident,
    IncidentHistory,
    MaintenanceWindow,
    OperationTarget,
)


def incident(
    db,
    key,
    title,
    cause,
    confidence,
    severity,
    router_ids,
    device_ids,
    facts,
    recommendations,
):
    row = db.scalar(select(Incident).where(Incident.dedup_key == key))
    if not row:
        row = Incident(
            dedup_key=key,
            title_key=title,
            cause_key=cause,
            confidence=confidence,
            severity=severity,
            router_ids=router_ids,
            device_ids=device_ids,
            facts=facts,
            recommendations=recommendations,
        )
        db.add(row)
        db.flush()
        db.add(
            IncidentHistory(
                incident_id=row.id,
                actor_id="correlation-engine",
                action="DETECTED",
                details={"facts": facts},
            )
        )
    else:
        if row.state == "RESOLVED":
            row.state = "OPEN"
            row.resolved_at = None
            db.add(
                IncidentHistory(
                    incident_id=row.id,
                    actor_id="correlation-engine",
                    action="REOPENED",
                    details={},
                )
            )
        row.last_observed = utcnow()
        row.router_ids = router_ids
        row.device_ids = device_ids
        row.facts = facts
        row.cause_key, row.confidence, row.severity = cause, confidence, severity
    return row


def correlate(db, now=None):
    now = now or utcnow()
    routers = db.scalars(select(Router).where(Router.archived.is_(False))).all()
    devices = db.scalars(select(Device).where(Device.enabled.is_(True))).all()
    related = defaultdict(list)
    for d in devices:
        related[d.network_evidence.get("router_id")].append(d.id)
    active_windows = db.scalars(
        select(MaintenanceWindow).where(
            MaintenanceWindow.starts_at <= now, MaintenanceWindow.ends_at >= now
        )
    ).all()
    maintenance = {i for w in active_windows for i in w.router_ids}
    maintenance.update(
        db.scalars(
            select(OperationTarget.router_id).where(
                OperationTarget.state.in_(["WAITING_RECONNECT", "RUNNING"]),
                OperationTarget.router_id.is_not(None),
            )
        )
    )
    fresh = lambda r: bool(
        r.last_health and (now - r.last_health).total_seconds() < 300
    )
    failed = [
        r
        for r in routers
        if r.id not in maintenance
        and fresh(r)
        and not r.health.get("reachable", False)
        and r.health.get("failure_count", 0) >= 3
    ]
    upstream = [r for r in failed if r.role == "GATEWAY"]
    mass = bool(len(failed) >= 2 and len(failed) >= len(routers) / 2)
    if upstream or mass:
        ids = [r.id for r in failed]
        incident(
            db,
            "network:upstream",
            "incident.upstream",
            "cause.upstream",
            "HIGH" if upstream else "MEDIUM",
            "critical",
            ids,
            [d for i in ids for d in related[i]],
            [
                {
                    "source": "router",
                    "fact": "management_api_failures",
                    "routers": ids,
                    "failed_samples": [r.health.get("failure_count") for r in failed],
                }
            ],
            ["recommend.upstream", "recommend.management_path", "recommend.logs"],
        )
    observations = db.scalars(
        select(ClientObservation)
        .where(ClientObservation.observed_at >= now - timedelta(minutes=10))
        .order_by(ClientObservation.observed_at.desc())
        .limit(2000)
    ).all()
    by_device = defaultdict(list)
    for observation in observations:
        by_device[observation.device_id].append(observation)
    samples = defaultdict(list)
    for t in db.scalars(
        select(RouterTelemetry)
        .where(RouterTelemetry.created_at >= now - timedelta(minutes=10))
        .order_by(RouterTelemetry.created_at.desc())
        .limit(3000)
    ):
        if len(samples[t.router_id]) < 12:
            samples[t.router_id].append(t)
    for r in routers:
        if r.id in maintenance:
            continue
        facts = [
            {
                "source": "router",
                "observed_at": r.last_health.isoformat() if r.last_health else None,
                "metrics": r.health,
            }
        ]
        if r in failed and not (upstream or mass):
            incident(
                db,
                "ap:offline:" + r.id,
                "incident.ap_offline",
                "cause.ap_unreachable",
                "MEDIUM",
                "high",
                [r.id],
                related[r.id],
                facts,
                ["recommend.management_path", "recommend.power", "recommend.logs"],
            )
        history = samples[r.id]
        if not fresh(r) or not r.health.get("reachable"):
            continue
        recent = [
            t
            for t in history
            if t.metrics.get("reachable") and (now - t.created_at).total_seconds() < 360
        ]
        sustained = (
            len(recent) >= 3
            and (
                max(t.created_at for t in recent) - min(t.created_at for t in recent)
            ).total_seconds()
            >= 120
        )
        high_cpu = sustained and all(
            (t.metrics.get("cpu_percent") or 0) >= 90 for t in recent[:3]
        )
        high_ram = sustained and all(
            (t.metrics.get("memory_percent") or 0) >= 90 for t in recent[:3]
        )
        if high_cpu or high_ram:
            incident(
                db,
                "ap:resources:" + r.id,
                "incident.resources",
                "cause.resource_pressure",
                "HIGH",
                "high",
                [r.id],
                related[r.id],
                facts,
                ["recommend.logs", "recommend.load", "recommend.controlled_reboot"],
            )
        old = next(
            (t for t in history if 60 <= (now - t.created_at).total_seconds() <= 180),
            None,
        )
        lost = []
        if old:
            old_macs = {c.get("mac-address") for c in old.clients}
            current_macs = {
                c.get("mac-address") for c in (history[0].clients if history else [])
            }
            lost = list(old_macs - current_macs)
            if len(lost) >= 3 and len(lost) >= max(1, len(old_macs)) * 0.5:
                resets = [
                    f
                    for t in recent[:3]
                    for f in t.facts
                    if any(
                        v in str(f.get("message", "")).lower()
                        for v in ("reset", "restarted", "interface down")
                    )
                ]
                affected_reports = [
                    observation
                    for device_id in related[r.id]
                    for observation in by_device[device_id]
                    if (now - observation.observed_at).total_seconds() <= 180
                    and (
                        observation.data.get("management_reachable") is False
                        or observation.data.get("connection_state")
                        in ("DISCONNECTED", "disconnected")
                        or any(
                            e.get("event_id") in (8002, 8003)
                            for e in observation.data.get("events", [])
                        )
                    )
                ]
                confidence = (
                    "HIGH"
                    if (
                        high_cpu
                        and resets
                        or len({o.device_id for o in affected_reports}) >= 3
                    )
                    and any(
                        o.id != r.id and fresh(o) and o.health.get("reachable")
                        for o in routers
                    )
                    else "MEDIUM"
                )
                client_facts = [
                    {
                        "source": "agent",
                        "device_id": o.device_id,
                        "observed_at": o.observed_at.isoformat(),
                        "diagnostics": o.data,
                    }
                    for o in affected_reports[:20]
                ]
                incident(
                    db,
                    "ap:instability:" + r.id,
                    "incident.ap_instability",
                    "cause.ap_instability",
                    confidence,
                    "high",
                    [r.id],
                    related[r.id],
                    facts
                    + [
                        {
                            "source": "router",
                            "fact": "client_loss",
                            "previous_clients": len(old_macs),
                            "lost_macs": lost,
                            "reset_events": resets[:10],
                        }
                    ]
                    + client_facts,
                    [
                        "recommend.logs",
                        "recommend.power",
                        "recommend.wireless",
                        "recommend.controlled_reboot",
                    ],
                )
        auth = {
            str(f.get(".id", f.get("message")))
            for t in recent
            for f in t.facts
            if any(
                v in str(f.get("message", "")).lower()
                for v in (
                    "authentication failed",
                    "wrong password",
                    "auth failed",
                    "4-way handshake timeout",
                )
            )
        }
        if len(auth) >= 5:
            incident(
                db,
                "ap:auth:" + r.id,
                "incident.auth_failures",
                "cause.credentials_or_radio",
                "MEDIUM",
                "medium",
                [r.id],
                related[r.id],
                [{"source": "router_log", "distinct_events": len(auth)}],
                ["recommend.credentials", "recommend.wireless"],
            )
        reboots = 0
        ordered = sorted(history, key=lambda t: t.created_at)
        for a, b in zip(ordered, ordered[1:]):
            if (
                a.metrics.get("uptime_seconds") is not None
                and b.metrics.get("uptime_seconds") is not None
                and b.metrics["uptime_seconds"] < a.metrics["uptime_seconds"]
            ):
                reboots += 1
        if reboots >= 2:
            incident(
                db,
                "ap:restarts:" + r.id,
                "incident.frequent_restarts",
                "cause.power_or_crash",
                "MEDIUM",
                "high",
                [r.id],
                related[r.id],
                [
                    {
                        "source": "router",
                        "observed_restarts": reboots,
                        "window_minutes": 10,
                    }
                ],
                ["recommend.power", "recommend.logs"],
            )
        for interface, expected in r.desired_config.items():
            actual = next(
                (
                    i
                    for i in r.health.get("interfaces", [])
                    if i.get("name") == interface
                ),
                {},
            )
            if expected.get("disabled") is False and actual.get("disabled") == "true":
                incident(
                    db,
                    "ap:radio:" + r.id + ":" + interface,
                    "incident.radio_disabled",
                    "cause.configuration_drift",
                    "HIGH",
                    "high",
                    [r.id],
                    related[r.id],
                    [
                        {
                            "source": "router",
                            "interface": interface,
                            "expected_disabled": False,
                            "actual_disabled": True,
                        }
                    ],
                    ["recommend.wireless"],
                )
            stack = expected.get("stack")
            settings = next(
                (
                    i
                    for i in r.inventory.get("wireless", {}).get(stack, [])
                    if i.get("name") == interface
                ),
                {},
            )
            ssid_key = "configuration.ssid" if stack == "wifi" else "ssid"
            if (
                expected.get("ssid")
                and settings.get(ssid_key) is not None
                and settings.get(ssid_key) != expected["ssid"]
            ):
                incident(
                    db,
                    "ap:configuration:" + r.id + ":" + interface,
                    "incident.configuration_drift",
                    "cause.configuration_drift",
                    "HIGH",
                    "medium",
                    [r.id],
                    related[r.id],
                    [
                        {
                            "source": "router",
                            "interface": interface,
                            "field": ssid_key,
                            "expected": expected["ssid"],
                            "actual": settings.get(ssid_key),
                        }
                    ],
                    ["recommend.wireless", "recommend.logs"],
                )
        by_address = defaultdict(set)
        by_mac = defaultdict(list)
        for lease in r.inventory.get("dhcp_leases", []):
            address, mac = lease.get("address"), lease.get("mac-address")
            if address and mac:
                by_address[address].add(mac)
                by_mac[mac].append(lease)
        conflicts = {
            ip: sorted(macs) for ip, macs in by_address.items() if len(macs) > 1
        }
        if conflicts:
            incident(
                db,
                "network:duplicate_ip:" + r.id,
                "incident.duplicate_ip",
                "cause.address_conflict",
                "HIGH",
                "high",
                [r.id],
                related[r.id],
                [{"source": "router_dhcp", "conflicts": conflicts}],
                ["recommend.addresses"],
            )
        for mac, leases in by_mac.items():
            if len(leases) > 1:
                incident(
                    db,
                    "network:duplicate_lease:" + r.id + ":" + mac,
                    "incident.duplicate_lease",
                    "cause.address_conflict",
                    "HIGH",
                    "medium",
                    [r.id],
                    related[r.id],
                    [{"source": "router_dhcp", "mac": mac, "leases": leases}],
                    ["recommend.addresses"],
                )
        for row in r.health.get("interfaces", []):
            try:
                errors = int(row.get("rx-error", "0")) + int(row.get("tx-error", "0"))
            except (ValueError, TypeError):
                continue
            if old:
                before = next(
                    (
                        x
                        for x in old.metrics.get("interfaces", [])
                        if x.get("name") == row.get("name")
                    ),
                    None,
                )
                if before:
                    try:
                        delta = (
                            errors
                            - int(before.get("rx-error", "0"))
                            - int(before.get("tx-error", "0"))
                        )
                    except (ValueError, TypeError):
                        continue
                    if delta >= 100:
                        incident(
                            db,
                            "network:errors:" + r.id + ":" + str(row.get("name")),
                            "incident.interface_errors",
                            "cause.link_errors",
                            "MEDIUM",
                            "medium",
                            [r.id],
                            related[r.id],
                            [
                                {
                                    "source": "router_interface",
                                    "interface": row.get("name"),
                                    "new_errors": delta,
                                    "window_seconds": (
                                        now - old.created_at
                                    ).total_seconds(),
                                }
                            ],
                            ["recommend.power", "recommend.wireless"],
                        )
    for d in devices:
        reports = by_device[d.id]
        if len(reports) < 3:
            continue
        weak = [
            x
            for x in reports[:3]
            if x.data.get("signal_quality") is not None
            and x.data["signal_quality"] < 30
        ]
        if len(weak) == 3:
            incident(
                db,
                "client:signal:" + d.id,
                "incident.weak_signal",
                "cause.radio_coverage",
                "MEDIUM",
                "medium",
                [d.network_evidence["router_id"]]
                if d.network_evidence.get("router_id")
                else [],
                [d.id],
                [
                    {
                        "source": "agent",
                        "observed_at": x.observed_at.isoformat(),
                        "signal_quality": x.data["signal_quality"],
                        "bssid": x.data.get("bssid"),
                    }
                    for x in weak
                ],
                ["recommend.signal", "recommend.wireless"],
            )
    # A deduplicated incident remains historical; silence never automatically becomes a confirmed repair.
