import re
from datetime import timedelta
from fastapi import HTTPException
from sqlalchemy import select
from app.db import utcnow
from app.models import Device, PolicyVersion, PolicyException, ComplianceReport, ComplianceCheck, Alert
from app.compliance.engine import evaluate


def normalize_mac(value):
    raw = value.replace(":", "").replace("-", "").upper()
    if not re.fullmatch(r"[0-9A-F]{12}", raw) or int(raw[:2], 16) & 1 or raw == "000000000000":
        raise ValueError("device.invalid_mac")
    return ":".join(raw[i:i + 2] for i in range(0, 12, 2))


def device_or_404(db, device_id):
    device = db.get(Device, device_id)
    if not device:
        raise HTTPException(404, "device.not_found")
    return device


def notify(db, code, device_id=None, severity="high", **details):
    existing = db.scalar(select(Alert).where(Alert.device_id == device_id, Alert.code == code, Alert.resolved_at.is_(None)))
    if not existing:
        db.add(Alert(code=code, device_id=device_id, severity=severity, details=details))


def effective_state(device, settings, now=None):
    now = now or utcnow()
    if device.device_class == "DEVELOPER":
        return "UNVERIFIED", None
    if device.last_heartbeat and device.last_heartbeat < now - timedelta(seconds=settings.heartbeat_deadline_seconds):
        return "UNVERIFIED", 0
    if device.state == "COMPLIANT" and (not device.last_heartbeat or not device.last_verified or device.last_verified < now - timedelta(seconds=settings.evidence_ttl_seconds)):
        return "UNVERIFIED", min(device.compliance_score, 99)
    return device.state, device.compliance_score


def serialize_device(device, settings):
    state, score = effective_state(device, settings)
    return {"id": device.id, "hostname": device.hostname, "device_class": device.device_class,
            "primary_mac": device.primary_mac, "randomized_mac_indicator": bool(int(device.primary_mac[:2], 16) & 2),
            "mode": device.mode, "state": state, "compliance_score": score,
            "network_state": device.network_state, "agent_version": device.agent_version,
            "os_version": device.os_version, "last_heartbeat": device.last_heartbeat,
            "last_verified": device.last_verified, "policy_version_id": device.policy_version_id,
            "enabled": device.enabled, "revision": device.revision, "network": device.network_evidence}


def reassess(db, device, claims=None):
    if device.device_class == "DEVELOPER":
        device.state, device.compliance_score = "UNVERIFIED", 0
        return {"state": "UNVERIFIED", "score": None, "checks": []}
    version = db.get(PolicyVersion, device.policy_version_id) if device.policy_version_id else None
    if not version:
        device.state, device.compliance_score = "ASSESSING", 0
        return {"state": "ASSESSING", "score": 0, "checks": []}
    exceptions = db.scalars(select(PolicyException).where(PolicyException.device_id == device.id,
                           PolicyException.revoked_at.is_(None))).all()
    waived = [c for e in exceptions if not e.expires_at or e.expires_at > utcnow() for c in e.controls]
    agent_claims = claims if claims is not None else device.inventory.get("claims", {})
    result = evaluate(version.document, version.id, device.reported_policy_id, agent_claims,
                      device.network_evidence.get("checks", {}), waived)
    device.compliance_score = result["score"]
    device.state = "QUARANTINED" if device.network_state in ("DISCONNECTED_VERIFIED", "ISOLATED_VERIFIED") else result["state"]
    device.last_verified = utcnow() if result["state"] == "COMPLIANT" else None
    report = ComplianceReport(device_id=device.id, version_id=version.id, state=result["state"], score=result["score"])
    db.add(report)
    db.flush()
    for check in result["checks"]:
        db.add(ComplianceCheck(report_id=report.id, check_id=check["check_id"], status=check["status"], severity=check["severity"], details=check))
    if result["state"] != "COMPLIANT":
        notify(db, "device.noncompliant" if result["state"] == "NONCOMPLIANT" else "device.unverified", device.id,
               checks=[c["check_id"] for c in result["checks"] if c["status"] != "PASS"])
    else:
        for alert in db.scalars(select(Alert).where(Alert.device_id == device.id, Alert.code.in_(["device.noncompliant", "device.unverified"]), Alert.resolved_at.is_(None))):
            alert.resolved_at = utcnow()
    device.revision += 1
    return result
