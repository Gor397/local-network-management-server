"""MAC admission to an existing reviewed SSID. This does not assert endpoint trust or Layer-2 isolation."""

from app.mikrotik.connector import STACKS
from app.mikrotik.planner import release_plan
from app.security.crypto import digest


def radio_bindings(snapshot, capabilities, ssid, vlan_id=None):
    found = []
    for stack in capabilities.get("stacks", []):
        path = STACKS[stack][0]
        for radio in snapshot.get(path, []):
            actual = radio.get("configuration.ssid", radio.get("ssid"))
            if not actual and stack in ("wifi", "capsman"):
                config_path = (
                    "interface/wifi/configuration"
                    if stack == "wifi"
                    else "caps-man/configuration"
                )
                config = next(
                    (
                        c
                        for c in snapshot.get(config_path, [])
                        if c.get("name") == radio.get("configuration")
                    ),
                    {},
                )
                actual = config.get("ssid")
            if actual != ssid:
                continue
            if radio.get("disabled") in ("true", True):
                raise ValueError("network.profile_radio_disabled")
            if vlan_id:
                vlan = radio.get("datapath.vlan-id", radio.get("vlan-id"))
                if str(vlan) != str(vlan_id):
                    bridge = next(
                        (
                            p
                            for p in snapshot.get("interface/bridge/port", [])
                            if p.get("interface") == radio.get("name")
                        ),
                        {},
                    )
                    filtering = any(
                        b.get("name") == bridge.get("bridge")
                        and b.get("vlan-filtering") == "true"
                        for b in snapshot.get("interface/bridge", [])
                    )
                    if not filtering or str(bridge.get("pvid")) != str(vlan_id):
                        raise ValueError("network.profile_vlan_unverified")
            found.append({"stack": stack, "interface": radio["name"], "ssid": ssid})
    if not found:
        raise ValueError("network.profile_ssid_unavailable")
    return found


def admission_plan(device, profile, snapshot, capabilities):
    bindings = radio_bindings(snapshot, capabilities, profile.ssid, profile.vlan_id)
    operations = release_plan(device, snapshot)
    reused = []
    for binding in bindings:
        stack, name = binding["stack"], binding["interface"]
        acl = STACKS[stack][1]
        rows = snapshot.get(acl, [])
        tag = f"lantern:{device.id}:developer:{profile.id}:{stack}:{digest(name)[:8]}"
        matching = [
            r
            for r in rows
            if r.get("mac-address", "").upper() == device.primary_mac
            and r.get("interface", "all") in ("all", "any", name, "")
            and r.get("disabled") not in ("true", True)
        ]
        manual = [
            r
            for r in matching
            if not r.get("comment", "").startswith(f"lantern:{device.id}:")
        ]
        if any(
            r.get("action") == "reject"
            or r.get("authentication") in ("no", "false", False)
            for r in manual
        ):
            raise ValueError("network.manual_admission_conflict")
        accepted = next(
            (
                r
                for r in manual
                if r.get("action") == "accept"
                or r.get("authentication") in ("yes", "true", True)
            ),
            None,
        )
        if accepted:
            reused.append(
                {"path": acl, "id": accepted[".id"], "mac-address": device.primary_mac}
            )
            continue
        owned = [r for r in rows if r.get("comment") == tag]
        if len(owned) > 1:
            raise ValueError("network.duplicate_managed_rule")
        values = {
            "mac-address": device.primary_mac,
            "interface": name,
            "disabled": "false",
            "comment": tag,
        }
        values.update(
            {"authentication": "yes", "forwarding": "yes"}
            if stack == "wireless"
            else {"action": "accept"}
        )
        operation = {
            "method": "PATCH" if owned else "PUT",
            "path": acl,
            "data": values,
            "priority_mode": "before_conflicts",
        }
        if owned:
            operation["id"] = owned[0][".id"]
        elif rows:
            values["place-before"] = rows[0][".id"]
        operations.append(operation)
    return operations, {
        "profile_id": profile.id,
        "vlan_id": profile.vlan_id,
        "bindings": bindings,
        "reused_rules": reused,
        "scope": "wireless_admission_only",
    }


def verify_admission(requirements, snapshot, capabilities):
    for binding in requirements.get("bindings", []):
        actual = radio_bindings(
            snapshot, capabilities, binding["ssid"], requirements.get("vlan_id")
        )
        if binding not in actual:
            return False
    for reused in requirements.get("reused_rules", []):
        row = next(
            (
                r
                for r in snapshot.get(reused["path"], [])
                if r.get(".id") == reused["id"]
            ),
            {},
        )
        if row.get("mac-address", "").upper() != reused["mac-address"] or row.get(
            "disabled"
        ) in ("true", True):
            return False
        if row.get("action") != "accept" and row.get("authentication") not in (
            "yes",
            "true",
            True,
        ):
            return False
    return True


def update_admission_state(db, device):
    from sqlalchemy import select
    from datetime import timedelta
    from app.db import utcnow
    from app.models import (
        NetworkProfile,
        ApGroupMember,
        NetworkAccessRule,
        DhcpReservation,
    )

    if device.network_state!='ADMISSION_PENDING':return
    profile = db.get(NetworkProfile, device.network_profile_id)
    if not profile or not profile.enabled or device.device_class != "DEVELOPER":
        return
    targets = set(
        db.scalars(
            select(ApGroupMember.router_id).where(
                ApGroupMember.group_id == profile.ap_group_id
            )
        )
    )
    records = db.scalars(
        select(NetworkAccessRule).where(NetworkAccessRule.device_id == device.id)
    ).all()
    verified = {
        r.router_id
        for r in records
        if r.rule.get("profile_id") == profile.id
        and r.rule.get("verified_at", "")
        > (utcnow() - timedelta(seconds=120)).isoformat()
    }
    lease = db.scalar(
        select(DhcpReservation).where(
            DhcpReservation.device_id == device.id,
            DhcpReservation.subnet_id == profile.subnet_id,
        )
    )
    if (
        targets
        and targets <= verified
        and lease
        and lease.verified_at
        and lease.verified_at > utcnow() - timedelta(seconds=120)
    ):
        device.network_state = "ADMISSION_CONFIGURATION_VERIFIED"
