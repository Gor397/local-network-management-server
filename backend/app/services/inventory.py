"""Passive network inventory built from router data that discovery already collected.

No packets are sent to endpoints and no router is contacted here. Each fact keeps its source so the
dashboard can separate observations (lease, ARP entry, Wi-Fi registration) from inferences.
"""
import re
from datetime import timedelta
from types import SimpleNamespace
from app.services import capsman
from app.mikrotik.connector import STACKS

CATEGORIES = ("UNKNOWN", "INFRASTRUCTURE", "ADMIN_WORKSTATION", "COMPUTER_UNMANAGED", "PRINTER", "PHONE_TABLET", "IOT", "OTHER")


def randomized(mac):
    # Locally administered bit: typical of Wi-Fi MAC randomization (also of some VMs/adapters).
    try:
        return bool(int(mac[:2], 16) & 2)
    except ValueError:
        return False


def observations(router, snapshot, capabilities):
    """Yield (mac, fact) for every endpoint the router reported."""
    for lease in snapshot.get("ip/dhcp-server/lease", []):
        mac = (lease.get("mac-address") or lease.get("active-mac-address") or "").upper()
        if mac:
            yield mac, {"source": "dhcp_lease", "router": router.name, "address": lease.get("active-address") or lease.get("address"),
                        "hostname": lease.get("host-name"), "status": lease.get("status"), "static": lease.get("dynamic") == "false",
                        "last_seen": lease.get("last-seen"), "server": lease.get("server")}
    for entry in snapshot.get("ip/arp", []):
        mac = (entry.get("mac-address") or "").upper()
        if mac and entry.get("complete", "true") != "false":
            yield mac, {"source": "arp", "router": router.name, "address": entry.get("address"), "interface": entry.get("interface")}
    for stack in capabilities.get("stacks", []):
        for client in snapshot.get(STACKS[stack][2], []):
            mac = (client.get("mac-address") or "").upper()
            if mac:
                yield mac, {"source": "wifi_registration", "router": router.name, "interface": client.get("interface"),
                            "ssid": client.get("ssid"), "signal": client.get("signal", client.get("signal-strength", client.get("rx-signal"))),
                            "uptime": client.get("uptime"), "comment": client.get("comment")}


MAC = re.compile(r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})")
REMOTE_CAP_PATHS = ("caps-man/remote-cap", "interface/wifi/capsman/remote-cap")


def access_points(routers):
    """Physical APs a CAPsMAN controller reports, exactly as reported (fields vary by RouterOS version)."""
    found = []
    for router, snapshot in routers:
        for path in REMOTE_CAP_PATHS:
            for cap in snapshot.get(path, []):
                match = MAC.search(cap.get("base-mac") or cap.get("address") or "")
                found.append({"controller": router.name, "identity": cap.get("identity") or cap.get("name"),
                              "address": cap.get("address"), "mac": match.group(1).upper() if match else None,
                              "board": cap.get("board"), "version": cap.get("version"), "serial": cap.get("serial"),
                              "state": cap.get("state"), "radios": cap.get("radios")})
    return found


def enrollment_state(device, enrolled, now, deadline_seconds):
    """What the server can prove about the Suro client, from its own records only."""
    if not device:
        return "NOT_REGISTERED"
    if device.device_class == "DEVELOPER":
        return "EXEMPT_UNMANAGED"
    if not enrolled:
        return "REGISTERED_NOT_ENROLLED"
    if not device.last_heartbeat:
        return "ENROLLED_NO_HEARTBEAT"
    if device.last_heartbeat < now - timedelta(seconds=deadline_seconds):
        return "AGENT_STALE"
    return "AGENT_HEALTHY"


def build(routers, devices, enrolled_ids, labels, now, deadline_seconds):
    """routers: [(router, snapshot)]; devices/labels keyed by upper-case MAC."""
    merged = {}
    infrastructure = {}
    for router, snapshot in routers:
        for interface in snapshot.get("interface/ethernet", []) + snapshot.get("interface", []):
            mac = (interface.get("mac-address") or "").upper()
            if mac:
                infrastructure.setdefault(mac, router)
        cap_names = {c["base-mac"].upper(): c.get("identity") or c["base-mac"] for c in capsman.remote_caps(snapshot)}
        for base, name in cap_names.items():
            # A CAP's ethernet and radio MACs sit just above its base MAC.
            value = int(base.replace(":", ""), 16)
            for offset in range(capsman.MAX_RADIO_OFFSET + 1):
                raw = f"{value + offset:012X}"
                infrastructure.setdefault(":".join(raw[i:i + 2] for i in range(0, 12, 2)), SimpleNamespace(name=name))
        radio_caps = {radio: cap_names.get(base) for radio, base in capsman.radio_map(snapshot).items()}
        fresh = bool(router.last_seen and router.last_seen > now - timedelta(seconds=1800))
        for mac, fact in observations(router, snapshot, router.capabilities or {}):
            if fact["source"] == "wifi_registration":
                fact["access_point"] = radio_caps.get(fact.get("interface"))
            row = merged.setdefault(mac, {"mac": mac, "facts": [], "fresh": False})
            row["facts"].append(fact)
            row["fresh"] = row["fresh"] or fresh
    by_address = {}
    for row in merged.values():
        addresses = sorted({f["address"] for f in row["facts"] if f.get("address")})
        row["addresses"] = addresses
        for address in addresses:
            by_address.setdefault(address, set()).add(row["mac"])
    items = []
    for mac, row in merged.items():
        device, label = devices.get(mac), labels.get(mac)
        hostnames = sorted({f["hostname"] for f in row["facts"] if f.get("hostname")})
        sources = sorted({f["source"] for f in row["facts"]})
        infra = infrastructure.get(mac)
        items.append({
            "mac": mac,
            "addresses": row["addresses"],
            "hostnames": hostnames,
            "sources": sources,
            "routers": sorted({f["router"] for f in row["facts"]}),
            "wifi": next(({"ssid": f.get("ssid"), "interface": f.get("interface"), "signal": f.get("signal"),
                           "access_point": f.get("access_point")}
                          for f in row["facts"] if f["source"] == "wifi_registration"), None),
            "facts": row["facts"],
            "fresh": row["fresh"],
            # Inferences, labelled as such.
            "randomized_mac": randomized(mac),
            "duplicate_address": [a for a in row["addresses"] if len(by_address[a]) > 1],
            "mikrotik_router": infra.name if infra else None,
            "device_id": device.id if device else None,
            "device_hostname": device.hostname if device else None,
            "enrollment": enrollment_state(device, device and device.id in enrolled_ids, now, deadline_seconds),
            "category": label.category if label else ("INFRASTRUCTURE" if infra else "UNKNOWN"),
            # Administrator label first; otherwise the router's own access-list comment.
            "label": label.label if label and label.label else next((f["comment"] for f in row["facts"] if f.get("comment")), ""),
            "note": label.note if label else "",
        })
    # End devices first, network equipment last.
    items.sort(key=lambda r: (r["category"] == "INFRASTRUCTURE", r["enrollment"] != "NOT_REGISTERED",
                              not r["wifi"], not r["addresses"], r["addresses"][:1], r["mac"]))
    return items
