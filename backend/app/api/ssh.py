import asyncio
import ipaddress
import json
import secrets
from datetime import timedelta
import asyncssh
from fastapi import APIRouter, Depends, HTTPException, Request, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field
from sqlalchemy import select
from app.auth.dependencies import db_session, require, audit, PERMISSIONS
from app.db import utcnow
from app.models import SshTarget, SshSession, AdminSession, Administrator, DeviceCredential, DhcpReservation
from app.security.crypto import digest
from app.services.devices import device_or_404

router = APIRouter(tags=["ssh"])


class Target(BaseModel):
    host: str
    port: int = Field(default=22, ge=1, le=65535)
    username: str = Field(pattern=r"^[A-Za-z0-9_.\\-]{1,128}$")
    host_public_key: str = Field(max_length=4096)
    private_key: str = Field(max_length=16000)


@router.put("/devices/{device_id}/ssh-target")
def configure(device_id: str, body: Target, request: Request, admin=Depends(require("approve", mfa=True)), db=Depends(db_session)):
    device_or_404(db, device_id)
    try:
        address = ipaddress.ip_address(body.host)
        if not any(address in ipaddress.ip_network(n.strip()) for n in request.app.state.settings.ssh_allowed_networks.split(",")):
            raise ValueError()
        asyncssh.import_public_key(body.host_public_key)
        asyncssh.import_private_key(body.private_key)
    except (ValueError, asyncssh.KeyImportError):
        raise HTTPException(422, "ssh.invalid_target_or_key") from None
    reservation = db.scalar(select(DhcpReservation).where(DhcpReservation.device_id == device_id,
                              DhcpReservation.address == body.host, DhcpReservation.verified_at.is_not(None)))
    if not reservation:
        raise HTTPException(409, "ssh.verified_reservation_required")
    target = db.get(SshTarget, device_id)
    if not target:
        target = SshTarget(device_id=device_id)
        db.add(target)
    for k in ("host", "port", "username", "host_public_key"):
        setattr(target, k, getattr(body, k))
    target.private_key = request.app.state.vault.seal(body.private_key)
    audit(db, admin.id, "ssh.target_configured", device_id,
          host_key_fingerprint=asyncssh.import_public_key(body.host_public_key).get_fingerprint())
    return {"ok": True}


class Authorize(BaseModel):
    reason: str = Field(min_length=5, max_length=2000)
    maintenance_approved: bool = False


@router.post("/devices/{device_id}/ssh-sessions")
def authorize(device_id: str, body: Authorize, request: Request, admin=Depends(require("ssh", mfa=True)), db=Depends(db_session)):
    if not request.app.state.settings.ssh_enabled:
        raise HTTPException(409, "ssh.disabled")
    d = device_or_404(db, device_id)
    if d.device_class == "DEVELOPER" or not d.enabled or not d.last_heartbeat or (utcnow() - d.last_heartbeat).total_seconds() > request.app.state.settings.heartbeat_deadline_seconds:
        raise HTTPException(409, "ssh.device_unavailable")
    if not db.scalar(select(DeviceCredential.id).where(DeviceCredential.device_id == d.id, DeviceCredential.revoked.is_(False))):
        raise HTTPException(409, "ssh.identity_required")
    if not db.get(SshTarget, d.id):
        raise HTTPException(409, "ssh.not_configured")
    if d.network_state not in ("UNKNOWN", "AUTHORIZED_VERIFIED") and not body.maintenance_approved:
        raise HTTPException(409, "ssh.maintenance_approval_required")
    active = db.scalars(select(SshSession).where(SshSession.state.in_(["AUTHORIZED", "ACTIVE"]), SshSession.expires_at > utcnow())).all()
    if len(active) >= 2:
        raise HTTPException(429, "ssh.concurrency_limit")
    ticket = secrets.token_urlsafe(48)
    session = SshSession(device_id=d.id, admin_id=admin.id, ticket_hash=digest(ticket),
                         expires_at=utcnow() + timedelta(minutes=1), reason=body.reason, maintenance_approved=body.maintenance_approved)
    db.add(session)
    db.flush()
    audit(db, admin.id, "ssh.authorized", d.id, session_id=session.id, reason=body.reason, maintenance=body.maintenance_approved)
    return {"id": session.id, "ticket": ticket, "websocket": f"/api/v1/ssh/sessions/{session.id}/terminal"}


@router.get("/ssh/sessions")
def sessions(admin=Depends(require("ssh")), db=Depends(db_session)):
    return [{"id": s.id, "device_id": s.device_id, "admin_id": s.admin_id, "state": s.state,
             "created_at": s.created_at, "expires_at": s.expires_at, "bytes_recorded": s.bytes_recorded} for s in db.scalars(select(SshSession).order_by(SshSession.created_at.desc()).limit(100))]


@router.post("/ssh/sessions/{session_id}/terminate")
def terminate(session_id: str, admin=Depends(require("ssh", mfa=True)), db=Depends(db_session)):
    s = db.get(SshSession, session_id)
    if not s:
        raise HTTPException(404, "ssh.session_not_found")
    s.state = "TERMINATED"
    audit(db, admin.id, "ssh.terminated", s.device_id, session_id=s.id)
    return {"ok": True}


@router.websocket("/ssh/sessions/{session_id}/terminal")
async def terminal(ws: WebSocket, session_id: str):
    app = ws.app
    if not app.state.settings.ssh_enabled or ws.headers.get("origin") != app.state.settings.public_origin:
        await ws.close(4403)
        return
    await ws.accept()
    with app.state.sessions() as db:
        s = db.get(SshSession, session_id)
        login = db.get(AdminSession, digest(ws.cookies.get("lantern_session", "")))
        admin = db.get(Administrator, login.admin_id) if login else None
        try:
            ticket = await asyncio.wait_for(ws.receive_text(), 5)
        except (TimeoutError, WebSocketDisconnect):
            await ws.close(4401)
            return
        if (not s or not login or not admin or not admin.enabled or "ssh" not in PERMISSIONS.get(admin.role, set())
                or login.expires_at <= utcnow() or (app.state.settings.mfa_required and (not login.mfa_at or login.mfa_at < utcnow() - timedelta(minutes=10)))
                or s.admin_id != admin.id or s.state != "AUTHORIZED" or s.expires_at < utcnow()
                or not secrets.compare_digest(digest(ticket), s.ticket_hash)):
            await ws.close(4403)
            return
        target = db.get(SshTarget, s.device_id)
        s.state, s.expires_at = "ACTIVE", utcnow() + timedelta(minutes=30)
        db.commit()
        host, port, username, key, hostkey = target.host, target.port, target.username, app.state.vault.open(target.private_key), target.host_public_key
        admin_id, device_id = admin.id, s.device_id
    recording = app.state.settings.data_dir / "recordings"
    recording.mkdir(exist_ok=True, mode=0o700)
    total_bytes = 0
    connection = None
    running = []
    def record(direction, value):
        nonlocal total_bytes
        encoded = value.encode()
        total_bytes += len(encoded)
        if total_bytes > 4 * 1024**2:
            raise ValueError("ssh.recording_limit")
        frame = json.dumps({"time": utcnow().isoformat(), "direction": direction, "data": value})
        with (recording / f"{session_id}.log.enc").open("a", encoding="utf-8") as f:
            f.write(app.state.vault.seal(frame) + "\n")
    try:
        connection = await asyncssh.connect(host, port=port, username=username,
                  client_keys=[asyncssh.import_private_key(key)], known_hosts=([asyncssh.import_public_key(hostkey)], [], []),
                  login_timeout=10, keepalive_interval=15, keepalive_count_max=2)
        process = await connection.create_process(term_type="xterm-256color", term_size=(110, 32))
        async def output():
            while True:
                chunk = await process.stdout.read(8192)
                if not chunk:
                    return
                record("out", chunk)
                await ws.send_text(chunk)
        async def input_():
            while True:
                value = await asyncio.wait_for(ws.receive_text(), timeout=300)
                if len(value) > 8192:
                    raise ValueError("ssh.input_limit")
                record("in", value)
                process.stdin.write(value)
        async def watchdog():
            while True:
                await asyncio.sleep(1)
                with app.state.sessions() as db:
                    state = db.get(SshSession, session_id)
                    login = db.get(AdminSession, digest(ws.cookies.get("lantern_session", "")))
                    device = device_or_404(db, device_id)
                    operator = db.get(Administrator, admin_id)
                    if not state or state.state != "ACTIVE" or state.expires_at <= utcnow() or not login or login.expires_at <= utcnow() or not operator.enabled or not device.enabled:
                        return
        running = [asyncio.create_task(coro()) for coro in (output, input_, watchdog)]
        await asyncio.wait(running, return_when=asyncio.FIRST_COMPLETED)
    except Exception:
        # Avoid leaking keys or connect exception details to the browser.
        try:
            await ws.send_text("\r\n[ssh.session_closed]\r\n")
        except Exception:
            pass
    finally:
        for task in running:
            task.cancel()
        if running:
            await asyncio.gather(*running, return_exceptions=True)
        if connection:
            connection.close()
            await connection.wait_closed()
        with app.state.sessions() as db:
            s = db.get(SshSession, session_id)
            if s:
                if s.state == "ACTIVE":
                    s.state = "CLOSED"
                s.bytes_recorded = total_bytes
                audit(db, admin_id, "ssh.closed", device_id, session_id=session_id, bytes=total_bytes)
                db.commit()
        try:
            await ws.close()
        except RuntimeError:
            pass
