import base64
import secrets
import time
from datetime import timedelta
from fastapi import Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from app.db import utcnow
from app.models import AdminSession, Administrator, DeviceCredential, Device, RequestNonce, AuditLog
from app.security.crypto import digest


def db_session(request: Request):
    with request.app.state.sessions() as db:
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise


def audit(db, actor, action, target="", **details):
    db.add(AuditLog(actor_id=str(actor), action=action, target_id=str(target), details=details))


def admin_session(request: Request, db=Depends(db_session)):
    token = request.cookies.get("lantern_session", "")
    session = db.get(AdminSession, digest(token))
    if not session or session.expires_at <= utcnow():
        raise HTTPException(401, "auth.required")
    admin = db.get(Administrator, session.admin_id)
    if not admin or not admin.enabled:
        raise HTTPException(401, "auth.required")
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        if request.headers.get("origin") != request.app.state.settings.public_origin:
            raise HTTPException(403, "auth.origin")
        if not secrets.compare_digest(request.headers.get("x-csrf-token", ""), session.csrf):
            raise HTTPException(403, "auth.csrf")
    return admin, session


PERMISSIONS = {
    "owner": {"read", "manage", "policy", "network", "approve", "deploy", "ssh", "administrators"},
    "operator": {"read", "manage", "policy", "network"},
    "viewer": {"read"},
    "deployer": {"read", "deploy"},
}


def require(permission, mfa=False):
    def dependency(identity=Depends(admin_session)):
        admin, session = identity
        if permission not in PERMISSIONS.get(admin.role, set()):
            raise HTTPException(403, "auth.forbidden")
        if mfa and (not session.mfa_at or session.mfa_at < utcnow() - timedelta(minutes=10)):
            raise HTTPException(403, "auth.mfa_required")
        return admin
    return dependency


async def agent_identity(request: Request, db=Depends(db_session)):
    fingerprint = request.headers.get("x-device-certificate", "")
    credential = db.scalar(select(DeviceCredential).where(DeviceCredential.fingerprint == fingerprint))
    if not credential or credential.revoked or credential.expires_at <= utcnow():
        raise HTTPException(401, "agent.identity_invalid")
    device = db.get(Device, credential.device_id)
    if not device or not device.enabled or device.device_class == "DEVELOPER":
        raise HTTPException(401, "agent.identity_invalid")
    timestamp = request.headers.get("x-device-time", "")
    nonce = request.headers.get("x-device-nonce", "")
    try:
        if abs(time.time() - int(timestamp)) > 90 or not 32 <= len(nonce) <= 128:
            raise ValueError()
        body = await request.body()
        message = f"{request.method}\n{request.url.path}{'?' + request.url.query if request.url.query else ''}\n{timestamp}\n{nonce}\n{digest(body)}".encode()
        cert = x509.load_pem_x509_certificate(credential.certificate.encode())
        signature = base64.b64decode(request.headers.get("x-device-signature", ""), validate=True)
        cert.public_key().verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
        db.add(RequestNonce(nonce=nonce, expires_at=utcnow() + timedelta(minutes=5)))
        db.flush()
    except Exception:
        raise HTTPException(401, "agent.signature_or_replay") from None
    return device
