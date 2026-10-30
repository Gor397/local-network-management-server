import base64
from datetime import timedelta
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from cryptography import x509
from app.auth.dependencies import db_session, agent_identity, audit
from app.db import utcnow
from app.models import Enrollment, DeviceCredential, Device, PolicyVersion, HealthReport, RemediationResult, BackgroundJob, NetworkInterface
from app.security.crypto import digest
from app.services.devices import normalize_mac, reassess, notify

router = APIRouter(prefix="/agent", tags=["agent"])


class Enroll(BaseModel):
    token: str = Field(min_length=32, max_length=128)
    csr: str = Field(max_length=16000)
    primary_mac: str


@router.post("/enroll")
def enroll(body: Enroll, request: Request, response: Response, db=Depends(db_session)):
    enrollment = db.scalar(select(Enrollment).where(Enrollment.token_hash == digest(body.token)).with_for_update())
    if not enrollment or enrollment.expires_at < utcnow():
        raise HTTPException(401, "enrollment.invalid_token")
    d = db.get(Device, enrollment.device_id)
    if not d.enabled or d.device_class == "DEVELOPER" or normalize_mac(body.primary_mac) != d.primary_mac:
        raise HTTPException(401, "enrollment.identity_mismatch")
    if enrollment.csr and enrollment.csr != body.csr:
        raise HTTPException(409, "enrollment.token_used")
    if not enrollment.csr:
        try:
            # Validate before consuming token; issue only after approval.
            request.app.state.vault.issue(body.csr, d.id)
        except ValueError:
            raise HTTPException(422, "enrollment.invalid_csr") from None
        enrollment.csr, enrollment.used_at = body.csr, utcnow()
        audit(db, d.id, "enrollment.requested", d.id, csr_sha256=digest(body.csr))
    if not enrollment.approved:
        response.status_code = 202
        return {"status": "PENDING_APPROVAL", "device_id": d.id}
    existing = db.scalar(select(DeviceCredential).where(DeviceCredential.device_id == d.id, DeviceCredential.revoked.is_(False)).order_by(DeviceCredential.created_at.desc()))
    if existing:
        csr = x509.load_pem_x509_csr(body.csr.encode())
        cert = x509.load_pem_x509_certificate(existing.certificate.encode())
        if csr.public_key().public_numbers() != cert.public_key().public_numbers():
            raise HTTPException(409, "enrollment.revoke_previous_identity")
        pem, fingerprint = existing.certificate, existing.fingerprint
    else:
        pem, fingerprint = request.app.state.vault.issue(body.csr, d.id)
        db.add(DeviceCredential(device_id=d.id, certificate=pem, fingerprint=fingerprint, expires_at=utcnow() + timedelta(days=365)))
    d.state = "ASSESSING"
    audit(db, d.id, "enrollment.issued", d.id, fingerprint=fingerprint)
    return {"device_id": d.id, "certificate": pem, "fingerprint": fingerprint}


@router.get("/policy")
def policy(request: Request, response: Response, d=Depends(agent_identity), db=Depends(db_session)):
    if not d.policy_version_id:
        raise HTTPException(404, "policy.unassigned")
    from app.services.safety import agent_mode
    mode = agent_mode(request.app.state.settings, d)
    etag = f'"{d.policy_version_id}:{d.revision}:{mode}"'
    if request.headers.get("if-none-match") == etag:
        response.status_code = 304
        return None
    version = db.get(PolicyVersion, d.policy_version_id)
    response.headers["ETag"] = etag
    return request.app.state.vault.signed({"schema_version": 1, "device_id": d.id, "version_id": version.id,
                                          "revision": d.revision, "mode": mode, "document": version.document,
                                          "valid_until": (utcnow() + timedelta(hours=24)).isoformat()+"Z"})


class Heartbeat(BaseModel):
    agent_version: str = Field(max_length=32)
    os_version: str = Field(max_length=256)
    policy_version_id: str | None = Field(default=None, max_length=36)
    health: dict = Field(default_factory=dict)


@router.post("/heartbeat")
def heartbeat(body: Heartbeat, request: Request, d=Depends(agent_identity), db=Depends(db_session)):
    d.last_heartbeat, d.agent_version, d.os_version = utcnow(), body.agent_version, body.os_version
    d.reported_policy_id = body.policy_version_id
    # Retain a bounded set of metrics, never arbitrary file or user content.
    allowed = {"cpu_percent", "ram_percent", "disk_free_bytes", "uptime_seconds", "last_boot", "ip", "gateway", "signal", "service_running", "critical_errors"}
    metrics = {k: v for k, v in body.health.items() if k in allowed}
    db.add(HealthReport(device_id=d.id, metrics=metrics))
    jobs = db.scalars(select(BackgroundJob).where(BackgroundJob.device_id == d.id, BackgroundJob.kind == "SYNC", BackgroundJob.status == "PENDING").limit(20)).all()
    for job in jobs:
        job.status = "DELIVERED"
    return {"server_time": utcnow(), "poll_seconds": request.app.state.settings.poll_seconds, "sync_requested": bool(jobs), "revision": d.revision}


class Evidence(BaseModel):
    policy_version_id: str
    claims: dict
    inventory: dict = Field(default_factory=dict)


@router.post("/compliance")
def compliance(body: Evidence, d=Depends(agent_identity), db=Depends(db_session)):
    from app.policies.schema import CATALOG
    if body.policy_version_id != d.policy_version_id:
        raise HTTPException(409, "policy.version_mismatch")
    if len(body.claims) > len(CATALOG):
        raise HTTPException(422, "compliance.too_many_checks")
    claims = {}
    for name, claim in body.claims.items():
        if name not in CATALOG or CATALOG[name][0] != "agent" or not isinstance(claim, dict):
            raise HTTPException(422, "compliance.invalid_source")
        # Arrival time is authoritative for freshness; endpoint clock isn't trusted.
        claims[name] = {**claim, "verified_at": utcnow().isoformat(), "source": "agent", "version_id": d.policy_version_id}
    allowed = {"users", "volumes", "partitions", "firewall", "network_adapters", "hardware", "os", "bitlocker", "storage_readiness", "data_locations", "settings", "session"}
    d.inventory = {k: v for k, v in body.inventory.items() if k in allowed}
    d.inventory = {**d.inventory, "claims": claims}
    session = d.inventory.get("session", {})
    if isinstance(session, dict) and isinstance(session.get("windows_account"), str) and isinstance(session.get("windows_sid"), str):
        d.last_user_account, d.last_user_sid, d.last_user_seen = session["windows_account"][:256], session["windows_sid"][:184], utcnow()
    d.reported_policy_id = body.policy_version_id
    for adapter in d.inventory.get("network_adapters", []):
        try:
            mac = normalize_mac(adapter["mac"])
        except (ValueError, KeyError):
            continue
        existing = db.scalar(select(NetworkInterface).where(NetworkInterface.mac == mac))
        if existing and existing.device_id != d.id:
            notify(db, "network.duplicate_mac", d.id, conflicting_device=existing.device_id, mac=mac)
        elif not existing:
            db.add(NetworkInterface(device_id=d.id, mac=mac, interface_id=str(adapter.get("id", ""))[:128], details=adapter))
    result = reassess(db, d, claims)
    audit(db, d.id, "compliance.reported", d.id, state=result["state"], score=result["score"])
    return result


class Remediation(BaseModel):
    policy_version_id: str
    operation: str = Field(max_length=64)
    result: dict


@router.post("/remediation-result")
def remediation(body: Remediation, d=Depends(agent_identity), db=Depends(db_session)):
    if body.policy_version_id != d.policy_version_id or body.operation not in ("firewall.enable", "account.demote_user", "settings.hide_c", "firewall.apply_allowlist"):
        raise HTTPException(422, "remediation.unsupported")
    db.add(RemediationResult(device_id=d.id, **body.model_dump()))
    # Results are execution records; they do not constitute verification.
    audit(db, d.id, "remediation.reported", d.id, operation=body.operation)
    return {"accepted": True, "verification_required": True}
