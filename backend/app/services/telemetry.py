import asyncio
import re
from datetime import timedelta
from sqlalchemy import select
from app.db import utcnow
from app.models import Router, RouterTelemetry, Device
from app.mikrotik.connector import STACKS, redact
from app.security.crypto import digest, canonical
from app.services.network import connector, discover
from app.services import capsman


def number(value):
    try:
        return float(value)
    except (ValueError, TypeError):
        return None


def uptime_seconds(value):
    if value is None:
        return None
    value = str(value)
    if re.fullmatch(r"\d+(\.\d+)?", value):
        return float(value)
    seconds = sum(
        float(v) * {"w": 604800, "d": 86400, "h": 3600, "m": 60, "s": 1}[u]
        for v, u in re.findall(r"(\d+(?:\.\d+)?)([wdhms])", value)
    )
    if not seconds and ":" in value:
        parts = value.split(":")
        try:
            seconds = sum(float(v) * 60**i for i, v in enumerate(reversed(parts)))
        except ValueError:
            return None
    return seconds if re.search(r"\d[wdhms]|:", value) else None


def metrics(resource, sensors=()):
    total, free = (
        number(resource.get("total-memory")),
        number(resource.get("free-memory")),
    )
    disk, disk_free = (
        number(resource.get("total-hdd-space")),
        number(resource.get("free-hdd-space")),
    )
    values = {}
    for sensor in sensors or []:
        if "name" in sensor:
            values[sensor["name"]] = number(sensor.get("value"))
        else:
            values.update(
                {k: number(v) for k, v in sensor.items() if not k.startswith(".")}
            )
    return {
        "cpu_percent": number(resource.get("cpu-load")),
        "memory_percent": round((1 - free / total) * 100, 2)
        if total and free is not None
        else None,
        "total_memory_bytes": total,
        "free_memory_bytes": free,
        "storage_percent": round((1 - disk_free / disk) * 100, 2)
        if disk and disk_free is not None
        else None,
        "free_storage_bytes": disk_free,
        "uptime_seconds": uptime_seconds(resource.get("uptime")),
        "temperature": values.get(
            "temperature",
            values.get("cpu-temperature", values.get("board-temperature")),
        ),
        "voltage": values.get("voltage"),
        "power": values.get("power-consumption"),
        "sensors": values,
    }


def update_inventory(router, snapshot):
    resource = next(iter(snapshot.get("system/resource", [])), {})
    board = next(iter(snapshot.get("system/routerboard", [])), {})
    identity = next(iter(snapshot.get("system/identity", [])), {})
    router.inventory = {
        "model": board.get("model", resource.get("board-name")),
        "serial_number": board.get("serial-number"),
        "version": resource.get("version"),
        "architecture": resource.get("architecture-name"),
        "system_name": identity.get("name"),
        "mac": next(
            (
                i.get("mac-address")
                for i in snapshot.get("interface", [])
                if i.get("mac-address")
            ),
            None,
        ),
        "interfaces": redact(snapshot.get("interface", [])),
        "ethernet": redact(snapshot.get("interface/ethernet", [])),
        "vlans": redact(snapshot.get("interface/bridge/vlan", [])),
        "logs": redact(snapshot.get("log", [])[-100:]),
        "vlan_interfaces": redact(snapshot.get("interface/vlan", [])),
        "firewall": {
            "ipv4": redact(snapshot.get("ip/firewall/filter", [])),
            "ipv6": redact(snapshot.get("ipv6/firewall/filter", [])),
        },
        "wireless_security": {
            p: redact(snapshot.get(p, []))
            for p in (
                "interface/wifi/security",
                "interface/wireless/security-profiles",
                "caps-man/security",
            )
        },
        "dhcp_leases": redact(snapshot.get("ip/dhcp-server/lease", [])),
        "dhcp_servers": redact(snapshot.get("ip/dhcp-server", [])),
        "ip_addresses": redact(snapshot.get("ip/address", [])),
        "wireless": {
            s: redact(snapshot.get(paths[0], [])) for s, paths in STACKS.items()
        },
        "unsupported_metrics": [
            k
            for k, v in metrics(resource, snapshot.get("system/health", [])).items()
            if v is None
        ],
    }
    router.last_inventory = utcnow()
    router.config_hash = digest(
        canonical(
            {
                p: rows
                for p, rows in snapshot.items()
                if p not in ("system/resource", "system/health", "log", "ip/arp")
                and not p.endswith("registration-table")
            }
        )
    )


async def poll_router(app, router_id, full=False):
    with app.state.sessions() as db:
        r = db.get(Router, router_id)
        if not r or r.archived:
            return
        now = utcnow()
        try:
            if (
                full
                or not r.snapshot
                or not r.last_inventory
                or (now - r.last_inventory).total_seconds()
                >= app.state.settings.network_inventory_seconds
            ):
                result = await discover(app, db, r)
                snapshot = result["snapshot"]
                update_inventory(r, snapshot)
                resource = snapshot["system/resource"][0]
                sensor = snapshot.get("system/health", [])
                clients = [
                    dict(c, stack=s)
                    for s, (_, _, path) in STACKS.items()
                    for c in snapshot.get(path, [])
                ]
                interfaces = snapshot.get("interface", [])
                logs = snapshot.get("log", [])
                caps = []  # discover() already synchronized CAPsMAN access points
            else:
                async with connector(app, r) as api:
                    resource = (await api.read("system/resource"))[0]
                    sensor = await api.read("system/health", optional=True)
                    interfaces = await api.read(
                        "interface",
                        properties=".id,name,type,disabled,running,rx-byte,tx-byte,rx-error,tx-error,link-downs,mac-address",
                    )
                    clients = []
                    for stack in r.capabilities.get("stacks", []):
                        clients.extend(
                            dict(c, stack=stack)
                            for c in (await api.read(STACKS[stack][2]))
                        )
                    logs = (
                        await api.read(
                            "log", optional=True, properties=".id,time,topics,message"
                        )
                        or []
                    )
                    logs = logs[-100:]
                    caps = []
                    if r.capabilities.get("cap_radios") is not None:
                        caps = [c for path in capsman.REMOTE_CAP_PATHS
                                for c in (await api.read(path, optional=True) or [])]
            previous = r.health
            current = metrics(resource, sensor)
            if (
                current["uptime_seconds"] is not None
                and previous.get("uptime_seconds") is not None
                and current["uptime_seconds"] < previous["uptime_seconds"]
            ):
                r.last_reboot = now - timedelta(seconds=current["uptime_seconds"])
            previous_logs = set(previous.get("log_cursor", []))
            log_pairs = [(digest(canonical(entry)), entry) for entry in logs]
            new_logs = [
                entry
                for fingerprint, entry in log_pairs
                if fingerprint not in previous_logs
            ][-20:]
            current.update(
                {
                    "reachable": True,
                    "failure_count": 0,
                    "client_count": len(clients),
                    "interfaces": redact(interfaces),
                    "observed_at": now.isoformat(),
                    "log_cursor": [fingerprint for fingerprint, _ in log_pairs][-100:],
                }
            )
            r.health, r.last_health, r.last_seen, r.status = current, now, now, "ONLINE"
            if caps:
                capsman.sync_caps(app, db, r, caps, r.capabilities.get("cap_radios", {}), clients, now)
            r.inventory = {**r.inventory, "logs": redact(logs)}
            db.add(
                RouterTelemetry(
                    router_id=r.id,
                    metrics={k: v for k, v in current.items() if k != "log_cursor"},
                    clients=redact(clients),
                    facts=redact(new_logs),
                )
            )
            by_mac = {c.get("mac-address", "").upper(): c for c in clients}
            for device in db.scalars(select(Device).where(Device.enabled.is_(True))):
                client = by_mac.get(device.primary_mac)
                if client:
                    device.network_evidence = {
                        **device.network_evidence,
                        "router_id": r.id,
                        "ap": client.get("interface"),
                        "ssid": client.get("ssid"),
                        "bssid": client.get("bssid"),
                        "connected": True,
                        "signal": client.get("signal", client.get("signal-strength")),
                        "observed_at": now.isoformat(),
                    }
                elif device.network_evidence.get("router_id") == r.id:
                    device.network_evidence = {
                        **device.network_evidence,
                        "connected": False,
                        "observed_at": now.isoformat(),
                    }
        except Exception as exc:
            r.health = {
                **r.health,
                "reachable": False,
                "failure_count": r.health.get("failure_count", 0) + 1,
                "failure_since": r.health.get("failure_since") or now.isoformat(),
                "error": type(exc).__name__,
                "observed_at": now.isoformat(),
            }
            r.last_health, r.status = now, "UNAVAILABLE"
            capsman.mark_unknown(db, r, now)
            db.add(
                RouterTelemetry(
                    router_id=r.id,
                    metrics=r.health,
                    clients=[],
                    facts=[{"kind": "management_api_unreachable"}],
                )
            )
        db.commit()


async def poll_all(app):
    with app.state.sessions() as db:
        # CAPsMAN access points are polled through their controller, never directly.
        routers = db.scalars(select(Router).where(Router.archived.is_(False), Router.transport != "CAPSMAN")).all()
        now = utcnow()
        ids = [
            r.id
            for r in routers
            if not r.last_health
            or (now - r.last_health).total_seconds()
            >= app.state.settings.network_health_seconds
            * (2 if r.status == "UNAVAILABLE" else 1)
        ]
    semaphore = asyncio.Semaphore(
        max(1, min(4, app.state.settings.network_poll_concurrency))
    )

    async def bounded(router_id):
        async with semaphore:
            try:
                await asyncio.wait_for(poll_router(app, router_id), 100)
            except TimeoutError:
                pass

    await asyncio.gather(*(bounded(i) for i in ids))
