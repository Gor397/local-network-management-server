"""Worker side of mandatory Suro Client admission: decide, then keep the router's timed grant in step.

Router I/O happens only when a grant must be created, refreshed (about every half TTL) or revoked, and reads
only the address list (plus ARP/leases when the computer's IP changed). Every write goes through
GuardedRouter, so OPERATION_MODE and per-router write switches apply exactly as for other changes.
"""

import asyncio
from sqlalchemy import select
from app.auth.dependencies import audit
from app.db import utcnow
from app.models import AdmissionPolicy, Device, DeviceCredential, NetworkAdmission, Router
from app.services import admission_gate as gate
from app.services.devices import effective_state, notify


def get_policy(db):
    policy = db.get(AdmissionPolicy, 1)
    if not policy:
        policy = AdmissionPolicy(id=1)
        db.add(policy)
        db.flush()
    return policy


def credential_active(db, device, now=None):
    now = now or utcnow()
    return bool(db.scalar(select(DeviceCredential.id).where(DeviceCredential.device_id == device.id,
                                                            DeviceCredential.revoked.is_(False),
                                                            DeviceCredential.expires_at > now)))


def decide(db, settings, admission, device, policy, now=None):
    now = now or utcnow()
    desired, reason = gate.evaluate(device, admission, policy, credential_active(db, device, now),
                                    effective_state(device, settings, now)[0], now)
    if (desired, reason) != (admission.desired, admission.reason):
        audit(db, "admission-worker", "admission.decision", device.id, desired=desired, reason=reason)
        admission.desired, admission.reason = desired, reason
        admission.revision += 1
    return desired


async def reconcile(app, db, now=None):
    now = now or utcnow()
    settings = app.state.settings
    policy = get_policy(db)
    ttl = gate.ttl_seconds(policy)
    work = {}
    for admission in db.scalars(select(NetworkAdmission)):
        device = db.get(Device, admission.device_id)
        desired = decide(db, settings, admission, device, policy, now)
        if admission.gate_state != "INSTALLED" or not admission.router_id:
            continue
        # With the gate installed, an exempt or no-longer-required computer must be let through, permanently.
        grant, lifetime = ("AUTHORIZED", 0) if desired in ("EXEMPT", "NOT_REQUIRED") else (desired, ttl)
        # Timed grants follow the agent's signed report; permanent ones keep their address or use the router's.
        target = admission.reported_ip if lifetime else admission.granted_ip or admission.reported_ip
        if grant == "AUTHORIZED" and (not target or gate.needs_refresh(admission, target, lifetime, now)):
            work.setdefault(admission.router_id, []).append((admission, device, "GRANT", lifetime, target))
        elif grant == "RESTRICTED" and admission.applied == "AUTHORIZED" and (policy.auto_revoke or admission.override == "RESTRICT"):
            work.setdefault(admission.router_id, []).append((admission, device, "REVOKE", 0, None))
    for router_id, items in work.items():
        await _sync_router(app, db, db.get(Router, router_id), items, now)


async def _sync_router(app, db, router, items, now):
    from app.services.network import connector
    try:
        async with connector(app, router) as api:
            rows = await asyncio.wait_for(api.read(gate.ADDRESS_LIST), timeout=30)
            neighbours = None
            for admission, device, action, lifetime, ip in items:
                if action == "GRANT":
                    if not ip or ip != admission.granted_ip:
                        if neighbours is None:
                            neighbours = {"ip/arp": await api.read("ip/arp"), "ip/dhcp-server/lease": await api.read("ip/dhcp-server/lease")}
                        ip = gate.confirmed_ip(device, ip, neighbours) if ip or lifetime else gate.router_address(device, neighbours)
                    if not ip:
                        _error(db, admission, "admission.ip_unconfirmed")
                        continue
                    operations = gate.grant_operations(device, ip, lifetime, rows)
                else:
                    operations = gate.revoke_operations(device, rows)
                for operation in operations:
                    await asyncio.wait_for(api.apply(operation), timeout=30)
                rows = await asyncio.wait_for(api.read(gate.ADDRESS_LIST), timeout=30)
                mine = [r for r in rows if r.get("comment") == gate.tag(device, "grant")]
                if action == "GRANT" and [r.get("address") for r in mine] == [ip] and mine[0].get("list") == gate.ADMITTED_LIST:
                    _applied(db, admission, "AUTHORIZED", ip, gate.grant_expiry(lifetime, now), now)
                elif action == "REVOKE" and not mine:
                    _applied(db, admission, "RESTRICTED", None, None, now)
                else:
                    _error(db, admission, "admission.readback_failed")
    except ValueError as exc:
        # Safety modes and write switches block here; the decision stays visible as pending, never as applied.
        for admission, *_rest in items:
            _error(db, admission, str(exc) if str(exc).startswith(("safety.", "network.")) else "admission.router_error")
    except Exception:
        for admission, device, *_rest in items:
            _error(db, admission, "admission.router_unreachable")
            notify(db, "admission.router_unreachable", device.id, router_id=router.id)


def _applied(db, admission, state, ip, expires, now):
    if admission.applied != state or admission.granted_ip != ip:
        audit(db, "admission-worker", "admission.applied", admission.device_id, state=state, ip=ip)
    admission.applied, admission.granted_ip, admission.grant_expires_at = state, ip, expires
    admission.applied_at, admission.error = now, None


def _error(db, admission, code):
    if admission.error != code:
        audit(db, "admission-worker", "admission.apply_failed", admission.device_id, error=code)
    admission.error = code
