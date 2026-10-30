import json
import asyncio
from datetime import timedelta
from fastapi import HTTPException
from sqlalchemy import select, update
from app.db import utcnow
from app.models import Router, AccessPoint, Device, NetworkPlan, DhcpReservation, Subnet, QuarantineState
from app.mikrotik.connector import RouterOS, STACKS, snapshot_hash, redact, validate_host
from app.mikrotik.planner import verify_operations
from app.auth.dependencies import audit
from app.services.devices import notify, reassess


def connector(app, router):
    # Validate on every connection. Prefer literal management IPs to avoid DNS rebinding.
    if router.transport == "CAPSMAN":
        raise ValueError("router.managed_by_controller")
    validate_host(router.base_url, app.state.settings.router_allowed_networks)
    from app.mikrotik.native import NativeRouterOS, PlainRouterOS
    from app.services.safety import GuardedRouter
    if router.transport == "API" and not app.state.settings.router_plaintext_api_allowed:
        raise ValueError("network.plaintext_api_disabled")
    adapter = {"API_SSL": NativeRouterOS, "API": PlainRouterOS}.get(router.transport, RouterOS)
    return GuardedRouter(adapter(router.base_url, router.username, app.state.vault.open(router.secret), router.ca_file), app.state.settings, router)


async def discover(app, db, router):
    if router.transport == "CAPSMAN":
        raise ValueError("router.managed_by_controller")  # observed through its controller only
    try:
        async with connector(app, router) as api:
            result = await asyncio.wait_for(api.discovery(), timeout=90)
        router.snapshot = app.state.vault.seal(json.dumps(result["snapshot"]))
        router.capabilities, router.last_seen, router.status = result["capabilities"], utcnow(), "ONLINE"
        from app.services.telemetry import update_inventory
        update_inventory(router, result["snapshot"])
        from app.services import capsman
        caps = capsman.remote_caps(result["snapshot"])
        if caps:
            radios = capsman.radio_map(result["snapshot"])
            router.capabilities = {**router.capabilities, "cap_radios": radios}
            clients = [c for path in capsman.REGISTRATION_PATHS for c in result["snapshot"].get(path, [])]
            capsman.sync_caps(app, db, router, caps, radios, clients, utcnow())
        for stack in router.capabilities["stacks"]:
            interface_path, _, reg_path = STACKS[stack]
            for interface in result["snapshot"].get(interface_path, []):
                name = interface.get("name", interface.get(".id", "unknown"))
                ap = db.scalar(select(AccessPoint).where(AccessPoint.router_id == router.id, AccessPoint.interface_name == name, AccessPoint.stack == stack))
                if not ap:
                    ap = AccessPoint(router_id=router.id, interface_name=name, stack=stack, details={})
                    db.add(ap)
                ap.details = redact(interface)
            for client in result["snapshot"].get(reg_path, []):
                device = db.scalar(select(Device).where(Device.primary_mac == client.get("mac-address", "").upper()))
                if device:
                    # Presence proves association only. It does not prove isolation or internet blocking.
                    device.network_evidence = {**device.network_evidence, "router_id": router.id,
                       "ap": client.get("interface"), "ssid": client.get("ssid"), "connected": True,
                       "observed_at": utcnow().isoformat(), "signal": client.get("signal", client.get("signal-strength"))}
                else:
                    notify(db, "network.unknown_mac", router_id=router.id, mac=client.get("mac-address"))
        return result
    except Exception:
        router.status = "UNAVAILABLE"
        notify(db, "router.unavailable", router_id=router.id)
        raise


async def execute_plan(app, db, plan, actor_id):
    settings = app.state.settings
    router = db.get(Router, plan.router_id)
    if plan.state != "PREVIEW" or plan.created_at < utcnow() - timedelta(minutes=10):
        raise HTTPException(409, "network.preview_expired")
    from app.services.safety import operation_mode, router_write_block
    if operation_mode(settings) == "dry_run":
        # Nothing is sent to the router and the plan stays a preview.
        audit(db, actor_id, "network.plan_dry_run", plan.device_id or router.id, plan_id=plan.id)
        return {"id": plan.id, "state": "DRY_RUN", "router_id": router.id, "router_name": router.name,
                "operations": redact(plan.operations), "result": {}}
    blocked = router_write_block(settings, router)
    if blocked:
        raise HTTPException(409, blocked)
    # Commit durable claim before external side effects; another worker cannot enter.
    claimed = db.execute(update(Router).where(Router.id == router.id,
                  (Router.lock_until.is_(None) | (Router.lock_until < utcnow())), Router.generation == plan.generation)
                  .values(lock_until=utcnow() + timedelta(minutes=5))).rowcount
    if claimed != 1:
        raise HTTPException(409, "network.concurrent_change")
    plan.state = "APPLYING"
    db.commit()
    applied = []
    backup = None
    admission=plan.result.get('admission')
    try:
        async with connector(app, router) as api:
            before = await asyncio.wait_for(api.discovery(), timeout=90)
            if snapshot_hash(before["snapshot"]) != plan.snapshot_hash:
                raise ValueError("network.configuration_changed")
            if admission:
                from app.services.admission import verify_admission
                if not verify_admission(admission,before['snapshot'],router.capabilities):raise ValueError('network.profile_binding_changed')
            # Encrypted snapshot persisted before writes, preserving unique passwords.
            router.snapshot = app.state.vault.seal(json.dumps(before["snapshot"]))
            backup = router.snapshot
            plan.result = {"backup": backup, "applied": [],'admission':admission}
            db.commit()
            for operation in plan.operations:
                # Mutation ownership is revalidated against the current before-state.
                if operation["method"] in ("PATCH", "DELETE") and not operation["path"].endswith("registration-table"):
                    row = next((r for r in before["snapshot"].get(operation["path"], []) if r.get(".id") == operation.get("id")), {})
                    if not row.get("comment", "").startswith(f"lantern:{plan.device_id}:"):
                        raise ValueError("network.unmanaged_entry")
                result = await api.apply(operation)
                applied.append({"operation": operation, "created_id": result.get(".id") if isinstance(result, dict) else None})
                plan.result = {"backup": backup, "applied": applied,'admission':admission}
                router.lock_until = utcnow() + timedelta(minutes=5)
                db.commit()
            after = await asyncio.wait_for(api.discovery(), timeout=90)
            if not verify_operations(plan.operations, after["snapshot"]):
                raise ValueError("network.readback_failed")
            if admission and not verify_admission(admission,after['snapshot'],router.capabilities):raise ValueError('network.profile_binding_changed')
        plan.state, plan.result = "VERIFIED", {"backup": backup, "applied": applied, "readback": True, "scope": "configuration_only"}
        if admission:plan.result={**plan.result,'admission':admission,'scope':'wireless_admission_only'}
        router.generation += 1
        router.snapshot = app.state.vault.seal(json.dumps(after["snapshot"]))
        if plan.device_id:
            device = db.get(Device, plan.device_id)
            if admission:
                from app.models import NetworkAccessRule
                tag=f'lantern:{device.id}:developer:{admission["profile_id"]}:{router.id[:8]}'
                record=db.scalar(select(NetworkAccessRule).where(NetworkAccessRule.owner_tag==tag))
                if not record:record=NetworkAccessRule(device_id=device.id,router_id=router.id,owner_tag=tag,rule={});db.add(record)
                record.rule={**admission,'verified_at':utcnow().isoformat(),'plan_id':plan.id}
                device.network_state='ADMISSION_PENDING'
            elif any(op["path"].endswith("access-list") for op in plan.operations):
                # Per-router ACL readback does not establish global or wired isolation.
                device.network_state = "RESTRICTION_APPLIED_VERIFICATION_REQUIRED"
            for reservation in db.scalars(select(DhcpReservation).where(DhcpReservation.device_id == device.id)):
                subnet = db.get(Subnet, reservation.subnet_id)
                if subnet.router_id == router.id:
                    match = next((r for r in after["snapshot"]["ip/dhcp-server/lease"] if r.get("address") == reservation.address and r.get("mac-address", "").upper() == device.primary_mac and r.get("dynamic") == "false" and r.get("server") == subnet.dhcp_server), None)
                    if match:
                        reservation.verified_at = utcnow()
                        checks = dict(device.network_evidence.get("checks", {}))
                        checks["network.ip_reservation.valid"] = {"source": "network", "status": "PASS", "actual": reservation.address,
                               "verified_at": utcnow().isoformat(), "version_id": device.policy_version_id, "evidence": {"router_id": router.id, "lease_id": match.get(".id")}}
                        device.network_evidence = {**device.network_evidence, "checks": checks, "ip": reservation.address}
            if device.network_profile_id:
                from app.services.admission import update_admission_state
                update_admission_state(db,device)
        audit(db, actor_id, "network.plan_verified", plan.device_id or router.id, plan_id=plan.id)
    except Exception as exc:
        # No blind rollback: a concurrent manual change could be overwritten. Snapshot + inverse preview supports recovery.
        plan.state, plan.result = "ERROR", {"backup": backup, "applied": applied, "error": type(exc).__name__, "recovery": "reconcile_snapshot"}
        router.status = "ERROR"
        if plan.device_id:
            db.get(Device, plan.device_id).network_state = "ERROR"
        notify(db, "network.enforcement_failed", plan.device_id, router_id=router.id, plan_id=plan.id)
        audit(db, actor_id, "network.plan_failed", plan.device_id or router.id, plan_id=plan.id, error=type(exc).__name__)
    finally:
        router.lock_until = None
        db.commit()
    return {"id": plan.id, "state": plan.state, "result": plan.result}
