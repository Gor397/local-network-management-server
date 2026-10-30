"""Mandatory Suro Client: the network, not the endpoint, decides whether a computer gets normal access.

Mechanism (RouterOS 6.43+ and 7, on the router that routes the computer's subnet):

- Static per-computer rules, installed once through a reviewed plan, all matching only that computer's MAC:
    forward: drop unless its source IP is in the `suro-admitted` address list or the destination is Suro;
    input:   drop TCP to the router itself (WinBox, API, SSH, web) unless admitted; DHCP and DNS still work;
    IPv6:    drop forwarded IPv6 (Suro admission is IPv4).
  No other device matches these rules, so the pilot cannot restrict anyone else.
- A timed grant: the computer's confirmed IP in `suro-admitted` with a router-side timeout. The worker
  refreshes it while the authenticated agent keeps reporting; if the agent or Suro stops, the router
  expires it by itself.

Limits (reported by `feasibility`): rules on a router see only traffic the router forwards or receives.
Hosts in the same subnet reach each other at Layer 2 without the router, so full isolation needs the
computer in a dedicated pilot SSID/VLAN subnet. MAC matching is not authentication; the grant is issued
only for an enrolled agent's signed heartbeat whose IP the router's own ARP/DHCP table ties to that MAC.
"""

from datetime import timedelta
from ipaddress import ip_address, ip_network
from urllib.parse import urlsplit
from app.db import utcnow

ADMITTED_LIST = "suro-admitted"
FILTER = "ip/firewall/filter"
FILTER6 = "ipv6/firewall/filter"
ADDRESS_LIST = "ip/firewall/address-list"


def tag(device, part):
    return f"lantern:{device.id}:admission:{part}"


def owned(row, device):
    return str(row.get("comment", "")).startswith(f"lantern:{device.id}:admission:")


def server_address(settings):
    for value in (settings.management_address, urlsplit(settings.public_origin).hostname or ""):
        try:
            return str(ip_address(value))
        except ValueError:
            continue
    return None


# ---- who should be admitted -------------------------------------------------------------------------

def ttl_seconds(policy):
    """Router-side lifetime of a grant. HOLD keeps access through a Suro outage; revocation is then explicit."""
    return 0 if policy.outage_policy == "HOLD" else policy.heartbeat_timeout_seconds + policy.grace_seconds


def evaluate(device, admission, policy, credential_active, compliance_state, now=None):
    """(desired, reason). desired is EXEMPT, NOT_REQUIRED, AUTHORIZED or RESTRICTED."""
    now = now or utcnow()
    if device.device_class == "INFRASTRUCTURE":
        return "EXEMPT", "admission.infrastructure"
    if device.admission_exempt or (device.device_class == "DEVELOPER" and policy.exempt_developers):
        return "EXEMPT", "admission.developer_exempt"
    if policy.mode == "DISABLED" or not admission or not admission.enabled:
        return "NOT_REQUIRED", "admission.not_required"
    if admission.override and (not admission.override_until or admission.override_until > now):
        return ("AUTHORIZED", "admission.override_authorized") if admission.override == "AUTHORIZE" \
            else ("RESTRICTED", "admission.override_restricted")
    if policy.require_enrollment and not credential_active:
        return "RESTRICTED", "admission.not_enrolled"
    if policy.require_running_agent:
        if not device.last_heartbeat:
            return "RESTRICTED", "admission.agent_never_connected"
        age = (now - device.last_heartbeat).total_seconds()
        if age > policy.heartbeat_timeout_seconds + policy.grace_seconds:
            return "RESTRICTED", "admission.agent_offline"
        if age > policy.heartbeat_timeout_seconds:
            # A short outage or Wi-Fi drop keeps access until the grace period ends: no reconnect loops.
            return "AUTHORIZED", "admission.grace_period"
    if policy.require_compliance and compliance_state != "COMPLIANT":
        return "RESTRICTED", "admission.noncompliant"
    return "AUTHORIZED", "admission.agent_verified"


def network_state(admission, desired, now=None):
    """What the router is confirmed to do, never what was merely requested."""
    now = now or utcnow()
    if desired in ("EXEMPT", "NOT_REQUIRED") and (not admission or admission.gate_state != "INSTALLED"):
        return desired
    if not admission or admission.gate_state != "INSTALLED":
        return "GATE_NOT_INSTALLED"
    if admission.error:
        return "ERROR"
    granted = admission.applied == "AUTHORIZED" and (not admission.grant_expires_at or admission.grant_expires_at > now)
    if desired in ("AUTHORIZED", "EXEMPT", "NOT_REQUIRED"):
        return "AUTHORIZED" if granted else "AUTHORIZATION_PENDING"
    return "REVOCATION_PENDING" if granted else "RESTRICTED"


# ---- what the router must contain -------------------------------------------------------------------

def _first_id(rows):
    return rows[0][".id"] if rows else None


def ipv6_present(snapshot):
    version = next(iter(snapshot.get("system/resource", [])), {}).get("version", "")
    if version[:1].isdigit() and int(version.split(".")[0]) >= 7:
        return True
    return any(p.get("name") == "ipv6" and p.get("disabled") != "true" for p in snapshot.get("system/package", []))


def gate_rules(device, server_ip, snapshot):
    """The exact rules that restrict only this MAC. Placement: before every existing rule."""
    if not server_ip:
        raise ValueError("admission.server_address_required")
    mac = device.primary_mac
    rules = [
        (FILTER, {"chain": "forward", "src-mac-address": mac, "src-address-list": "!" + ADMITTED_LIST,
                  "dst-address": "!" + server_ip, "action": "drop", "comment": tag(device, "forward")}),
        (FILTER, {"chain": "input", "src-mac-address": mac, "src-address-list": "!" + ADMITTED_LIST,
                  "protocol": "tcp", "action": "drop", "comment": tag(device, "input")}),
    ]
    if ipv6_present(snapshot):
        rules.append((FILTER6, {"chain": "forward", "src-mac-address": mac, "action": "drop", "comment": tag(device, "ipv6")}))
    return rules


def gate_plan(device, server_ip, snapshot):
    """Idempotent: an identical owned rule is kept; a changed one is replaced; others are never touched."""
    operations = []
    for path, data in gate_rules(device, server_ip, snapshot):
        rows = snapshot.get(path, [])
        mine = [r for r in rows if r.get("comment") == data["comment"]]
        if len(mine) > 1:
            raise ValueError("network.duplicate_managed_rule")
        if mine and all(mine[0].get(k) == v for k, v in data.items()) and first_in_chain(rows, data["chain"], data["comment"]):
            continue
        for row in mine:
            operations.append({"method": "DELETE", "path": path, "id": row[".id"], "owned_comment": row["comment"]})
        others = [r for r in rows if r not in mine]
        operations.append({"method": "PUT", "path": path, "data": {**data, **({"place-before": others[0][".id"]} if others else {})},
                           "placement": "first"})
    return operations


def removal_plan(device, snapshot):
    """Rollback: remove every rule and grant this computer owns. Nothing else is touched."""
    return [{"method": "DELETE", "path": path, "id": row[".id"], "owned_comment": row["comment"]}
            for path in (FILTER, FILTER6, ADDRESS_LIST) for row in snapshot.get(path, []) if owned(row, device)]


def rollback_commands(device):
    """For an administrator at the router console if Suro itself is unavailable."""
    prefix = f"lantern:{device.id}:admission:"
    return [f'/ip firewall filter remove [find comment~"^{prefix}"]',
            f'/ipv6 firewall filter remove [find comment~"^{prefix}"]',
            f'/ip firewall address-list remove [find comment~"^{prefix}"]']


def first_in_chain(rows, chain, comment):
    """True when the enabled rule `comment` precedes every non-Suro rule of its chain."""
    ordered = [r for r in rows if r.get("chain") == chain and r.get("disabled") != "true"]
    position = next((i for i, r in enumerate(ordered) if r.get("comment") == comment), None)
    return position is not None and all(str(r.get("comment", "")).startswith("lantern:") for r in ordered[:position])


def placement_verified(operations, after):
    """Each owned drop rule must precede every rule an administrator created in the same chain."""
    return all(first_in_chain(after.get(op["path"], []), op["data"]["chain"], op["data"]["comment"])
               for op in operations if op.get("placement") == "first" and op["method"] == "PUT")


# ---- the timed grant ------------------------------------------------------------------------------

def confirmed_ip(device, reported_ip, snapshot):
    """The agent's reported IP, accepted only if the router ties it to this MAC (ARP or bound DHCP lease)."""
    if not reported_ip:
        return None
    mac = device.primary_mac
    for row in snapshot.get("ip/arp", []):
        if row.get("address") == reported_ip and str(row.get("mac-address", "")).upper() == mac and row.get("invalid") != "true":
            return reported_ip
    for row in snapshot.get("ip/dhcp-server/lease", []):
        if row.get("address") == reported_ip and str(row.get("mac-address", "")).upper() == mac and row.get("status") == "bound":
            return reported_ip
    return None


def router_address(device, snapshot):
    """The address the router itself associates with this MAC; used only for permanent (exempt) grants."""
    mac = device.primary_mac
    for row in snapshot.get("ip/arp", []) + snapshot.get("ip/dhcp-server/lease", []):
        if str(row.get("mac-address", "")).upper() == mac and row.get("address") and row.get("invalid") != "true":
            return row["address"]
    return None


def grant_operations(device, ip, ttl, rows):
    mine = [r for r in rows if r.get("comment") == tag(device, "grant")]
    data = {"list": ADMITTED_LIST, "address": ip, "comment": tag(device, "grant")}
    if ttl:
        data["timeout"] = f"{ttl}s"
    stale = [r for r in mine if r.get("address") != ip]
    keep = [r for r in mine if r.get("address") == ip]
    operations = [{"method": "DELETE", "path": ADDRESS_LIST, "id": r[".id"], "owned_comment": r["comment"]} for r in stale + keep[1:]]
    # Refresh by replacement: setting a dynamic entry's timeout is not consistent across RouterOS versions.
    if keep:
        operations.append({"method": "DELETE", "path": ADDRESS_LIST, "id": keep[0][".id"], "owned_comment": keep[0]["comment"]})
    operations.append({"method": "PUT", "path": ADDRESS_LIST, "data": data})
    return operations


def revoke_operations(device, rows):
    return [{"method": "DELETE", "path": ADDRESS_LIST, "id": r[".id"], "owned_comment": r["comment"]}
            for r in rows if r.get("comment") == tag(device, "grant")]


def needs_refresh(admission, ip, ttl, now=None):
    now = now or utcnow()
    if admission.applied != "AUTHORIZED" or admission.granted_ip != ip:
        return True
    if not ttl:
        return False
    return not admission.grant_expires_at or (admission.grant_expires_at - now).total_seconds() < ttl / 2


# ---- can this router do it safely -----------------------------------------------------------------

def feasibility(router, snapshot, device, server_ip):
    """Facts for the administrator before anything is written. Blocking problems are listed in `blockers`."""
    blockers, warnings, facts = [], [], {}
    resource = next(iter(snapshot.get("system/resource", [])), {})
    facts["routeros_version"] = resource.get("version")
    facts["board"] = resource.get("board-name")
    facts["transport"] = router.transport
    facts["wireless_stacks"] = router.capabilities.get("stacks", [])
    facts["ipv6"] = ipv6_present(snapshot)
    if router.transport in ("API", "CAPSMAN"):
        blockers.append("admission.router_read_only_transport")
    if router.role == "GATEWAY" or router.protected:
        warnings.append("admission.protected_router")
    if not server_ip:
        blockers.append("admission.server_address_required")
    mac = device.primary_mac
    seen = [r for r in snapshot.get("ip/arp", []) + snapshot.get("ip/dhcp-server/lease", []) if str(r.get("mac-address", "")).upper() == mac]
    address = next((r.get("address") for r in seen if r.get("address")), None)
    facts["device_seen"] = bool(seen)
    facts["device_address"] = address
    if not seen:
        warnings.append("admission.device_not_seen")
    routed = None
    for row in snapshot.get("ip/address", []):
        try:
            network = ip_network(row.get("address", ""), strict=False)
        except ValueError:
            continue
        if address and ip_address(address) in network:
            routed = network
    facts["routes_device_subnet"] = bool(routed)
    if address and not routed:
        blockers.append("admission.router_not_gateway_for_device")
    if routed:
        peers = {r.get("address") for r in snapshot.get("ip/arp", []) + snapshot.get("ip/dhcp-server/lease", [])
                 if r.get("address") and str(r.get("mac-address", "")).upper() != mac and _inside(r.get("address"), routed)}
        facts["same_subnet_hosts"] = len(peers)
        facts["server_in_same_subnet"] = bool(server_ip and _inside(server_ip, routed))
        if peers:
            # Layer-2 peers are not filtered by IP firewall rules on the router.
            warnings.append("admission.same_subnet_not_isolated")
    infrastructure = {str(r.get("mac-address", "")).upper() for r in snapshot.get("interface", [])}
    infrastructure |= {str(c.get("base-mac", "")).upper() for c in snapshot.get("caps-man/remote-cap", [])}
    if mac in infrastructure:
        blockers.append("admission.infrastructure_mac")
    if server_ip and address == server_ip:
        blockers.append("admission.server_mac")
    return {"blockers": blockers, "warnings": warnings, "facts": facts}


def _inside(address, network):
    try:
        return ip_address(address) in network
    except ValueError:
        return False


def grant_expiry(ttl, now=None):
    return (now or utcnow()) + timedelta(seconds=ttl) if ttl else None
