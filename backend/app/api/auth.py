import secrets
import time
from datetime import timedelta
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, InvalidHashError
import pyotp
from app.auth.dependencies import db_session, admin_session, require, audit
from app.db import utcnow
from app.models import Administrator, AdminSession
from app.security.crypto import digest

router = APIRouter(prefix="/auth", tags=["authentication"])
hasher = PasswordHasher()
dummy_hash = hasher.hash(secrets.token_urlsafe(32))


class Login(BaseModel):
    username: str = Field(max_length=128)
    password: str = Field(max_length=1024)
    totp: str | None = Field(default=None, max_length=6)


def verify_totp(db, admin, secret, code):
    step = int(time.time()) // 30
    if not code or not pyotp.TOTP(secret).verify(code, valid_window=0):
        raise HTTPException(401, "auth.invalid_totp")
    # Row lock prevents the same TOTP being used concurrently.
    locked = db.scalar(select(Administrator).where(Administrator.id == admin.id).with_for_update().execution_options(populate_existing=True))
    if locked.totp_last_step >= step:
        raise HTTPException(401, "auth.totp_replay")
    locked.totp_last_step = step


@router.post("/login")
def login(body: Login, response: Response, request: Request, db=Depends(db_session)):
    if request.headers.get("origin") != request.app.state.settings.public_origin:
        raise HTTPException(403, "auth.origin")
    admin = db.scalar(select(Administrator).where(Administrator.username == body.username))
    try:
        valid = hasher.verify(admin.password_hash if admin else dummy_hash, body.password)
    except (VerificationError, InvalidHashError):
        valid = False
    if not admin or not admin.enabled or not valid:
        audit(db, "anonymous", "auth.login_failed", body.username)
        db.commit()
        raise HTTPException(401, "auth.invalid_credentials")
    mfa_at = None
    if admin.totp_secret and (body.totp or request.app.state.settings.mfa_login_required):
        verify_totp(db, admin, request.app.state.vault.open(admin.totp_secret), body.totp)
        mfa_at = utcnow()
    token, csrf = secrets.token_urlsafe(48), secrets.token_hex(32)
    db.add(AdminSession(token_hash=digest(token), admin_id=admin.id, csrf=csrf,
                        expires_at=utcnow() + timedelta(hours=8), mfa_at=mfa_at))
    response.set_cookie("lantern_session", token, httponly=True, secure=request.app.state.settings.cookie_secure,
                        samesite="strict", max_age=28800, path="/api")
    audit(db, admin.id, "auth.login", admin.id)
    return {"csrf": csrf, "username": admin.username, "role": admin.role, "mfa": bool(mfa_at),
            "mfa_available": bool(admin.totp_secret), "mfa_required": request.app.state.settings.mfa_required}


@router.get("/me")
def me(identity=Depends(admin_session)):
    admin, session = identity
    return {"username": admin.username, "role": admin.role, "csrf": session.csrf, "mfa": bool(session.mfa_at)}


@router.post("/logout")
def logout(response: Response, identity=Depends(admin_session), db=Depends(db_session)):
    admin, session = identity
    db.delete(session)
    response.delete_cookie("lantern_session", path="/api")
    audit(db, admin.id, "auth.logout", admin.id)
    return {"ok": True}


@router.post("/mfa/setup")
def mfa_setup(request: Request, identity=Depends(admin_session)):
    admin, _ = identity
    if admin.totp_secret:
        raise HTTPException(409, "auth.mfa_already_enabled")
    # Stateless short-lived sealed challenge; only confirmation persists a secret.
    import json
    secret = pyotp.random_base32()
    challenge = request.app.state.vault.seal(json.dumps({"admin": admin.id, "secret": secret, "until": time.time() + 300}))
    return {"challenge": challenge, "uri": pyotp.TOTP(secret).provisioning_uri(admin.username, issuer_name="Suro")}


class MfaConfirm(BaseModel):
    challenge: str = Field(max_length=2048)
    code: str = Field(min_length=6, max_length=6)


@router.post("/mfa/confirm")
def mfa_confirm(body: MfaConfirm, request: Request, identity=Depends(admin_session), db=Depends(db_session)):
    import json
    admin, session = identity
    try:
        data = json.loads(request.app.state.vault.open(body.challenge))
        assert data["admin"] == admin.id and data["until"] > time.time() and not admin.totp_secret
    except Exception:
        raise HTTPException(400, "auth.invalid_challenge") from None
    verify_totp(db, admin, data["secret"], body.code)
    admin.totp_secret = request.app.state.vault.seal(data["secret"])
    session.mfa_at = utcnow()
    audit(db, admin.id, "auth.mfa_enabled", admin.id)
    return {"ok": True}


class MfaCode(BaseModel):
    code: str = Field(min_length=6, max_length=6)


@router.post("/mfa/reauthenticate")
def mfa_reauth(body: MfaCode, request: Request, identity=Depends(admin_session), db=Depends(db_session)):
    admin, session = identity
    if not admin.totp_secret:
        raise HTTPException(409, "auth.mfa_not_enabled")
    verify_totp(db, admin, request.app.state.vault.open(admin.totp_secret), body.code)
    session.mfa_at = utcnow()
    return {"ok": True}
