from ipaddress import ip_address, ip_network
from app.mikrotik.connector import STACKS


def allocate_address(subnet, snapshot, reservations):
    network = ip_network(subnet.cidr)
    start, end = ip_address(subnet.allocation_start), ip_address(subnet.allocation_end)
    if start not in network or end not in network or start > end or int(end) - int(start) > 65535:
        raise ValueError("network.invalid_allocation_range")
    occupied = {str(ip_address(a.split("/")[0])) for a in reservations}
    for path, fields in {"ip/dhcp-server/lease": ("address", "active-address"), "ip/address": ("address",), "ip/arp": ("address",)}.items():
        for row in snapshot.get(path, []):
            for field in fields:
                if row.get(field):
                    occupied.add(row[field].split("/")[0])
    exclusions = [ip_network(e, strict=False) for e in subnet.exclusions]
    # Dynamic pools belong to RouterOS, never allocate within them.
    ranges = []
    for pool in snapshot.get("ip/pool", []):
        for part in pool.get("ranges", "").split(","):
            if "-" in part:
                a, b = part.split("-")
                ranges.append((int(ip_address(a)), int(ip_address(b))))
            elif part:
                ranges.append((int(ip_address(part)), int(ip_address(part))))
    for number in range(int(start), int(end) + 1):
        candidate = ip_address(number)
        if candidate in (network.network_address, network.broadcast_address) or str(candidate) in occupied:
            continue
        if any(candidate in n for n in exclusions) or any(a <= number <= b for a, b in ranges):
            continue
        return str(candidate)
    raise ValueError("network.no_available_address")


def reservation_plan(device, subnet, address, snapshot):
    existing = [r for r in snapshot.get("ip/dhcp-server/lease", []) if r.get("mac-address", "").upper() == device.primary_mac and r.get("server") == subnet.dhcp_server]
    if len(existing) > 1:
        raise ValueError("network.duplicate_reservations")
    if existing:
        row = existing[0]
        if row.get("dynamic") == "false" and row.get("address") == address:
            return []
        # Existing manually owned entries and their credentials are preserved.
        raise ValueError("network.existing_lease_requires_manual_import")
    return [{"method": "PUT", "path": "ip/dhcp-server/lease", "data": {"server": subnet.dhcp_server,
             "mac-address": device.primary_mac, "address": address, "comment": f"lantern:{device.id}:lease"}}]


def disconnect_plan(device, snapshot, capabilities):
    operations = []
    for stack in capabilities.get("stacks", []):
        _, acl, registrations = STACKS[stack]
        tag = f"lantern:{device.id}:quarantine:{stack}"
        rows = snapshot.get(acl, [])
        owned = [r for r in rows if r.get("comment") == tag]
        if len(owned) > 1:
            raise ValueError("network.duplicate_managed_rule")
        rule = {"mac-address": device.primary_mac, "comment": tag, "disabled": "false"}
        rule.update({"authentication": "no", "forwarding": "no"} if stack == "wireless" else {"action": "reject"})
        if owned:
            operations.append({"method": "PATCH", "path": acl, "id": owned[0][".id"], "data": rule})
        else:
            if rows:
                rule["place-before"] = rows[0][".id"]
            operations.append({"method": "PUT", "path": acl, "data": rule})
        for client in snapshot.get(registrations, []):
            if client.get("mac-address", "").upper() == device.primary_mac:
                operations.append({"method": "DELETE", "path": registrations, "id": client[".id"], "mac": device.primary_mac})
    if not operations:
        raise ValueError("network.no_supported_wireless_enforcement")
    return operations


def release_plan(device, snapshot):
    operations = []
    for _, acl, _ in STACKS.values():
        for row in snapshot.get(acl, []):
            if row.get("comment", "").startswith(f"lantern:{device.id}:quarantine:"):
                operations.append({"method": "DELETE", "path": acl, "id": row[".id"], "owned_comment": row["comment"]})
    return operations


def verify_operations(operations, after):
    for op in operations:
        rows = after.get(op["path"], [])
        if op["method"] == "DELETE":
            if any(r.get(".id") == op["id"] for r in rows):
                return False
        else:
            expected = {k: v for k, v in op["data"].items() if k != "place-before"}
            match = next((r for r in rows if all(r.get(k) == v for k, v in expected.items())), None)
            if not match:
                return False
            # Reject must precede any potentially matching manual rules.
            if op["path"].endswith("access-list") and rows[0].get(".id") != match.get(".id"):
                return False
    return True
