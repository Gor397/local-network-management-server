from datetime import timedelta
from app.db import utcnow
from app.policies.schema import CATALOG, PolicyDocument


def evaluate(policy: dict, version_id, reported_version, agent_claims, network_claims, exceptions=(), now=None):
    now = now or utcnow()
    document = PolicyDocument.model_validate(policy)
    results = []
    applicable = [c for c in document.mandatory_checks if c not in set(exceptions)]
    if not document.require_d:
        applicable = [c for c in applicable if c not in ("disk.d.valid", "disk.user_data_location.valid")]
    # Core identity, network, freshness and integrity gates cannot be waived.
    core = ["agent.policy_version_current", "agent.integrity_valid", "network.mac_identity.valid", "network.isolation.valid", "network.internet_restriction.valid"]
    applicable = sorted(set(applicable) | set(core))
    for check in applicable:
        source, severity = CATALOG[check]
        status, evidence, error, actual, verified_at = "UNKNOWN", {}, None, None, None
        if source == "server":
            actual = reported_version
            status = "PASS" if version_id and version_id == reported_version else "FAIL"
            verified_at = now.isoformat()
        else:
            claim = (network_claims if source == "network" else agent_claims).get(check, {})
            try:
                from datetime import datetime
                timestamp = datetime.fromisoformat(claim["verified_at"]).replace(tzinfo=None)
                fresh = now - timedelta(seconds=document.evidence_ttl_seconds) <= timestamp <= now + timedelta(seconds=30)
                correct_version = claim.get("version_id") == version_id
                correct_source = claim.get("source") == source
                if fresh and correct_version and correct_source and claim.get("status") in ("PASS", "FAIL", "UNKNOWN"):
                    status = claim["status"]
                else:
                    error = "compliance.stale_or_wrong_version"
                evidence = claim.get("evidence", {})
                actual = claim.get("actual")
                verified_at = claim.get("verified_at")
            except (KeyError, ValueError, TypeError):
                error = "compliance.missing_evidence"
        results.append({"check_id": check, "expected": True if source != "server" else version_id,
                        "actual": actual, "status": status, "severity": severity,
                        "source": source, "evidence": evidence, "verified_at": verified_at,
                        "remediation_eligible": check in ("firewall.enabled", "account.user.not_administrator"),
                        "remediation_result": None, "error": error})
    total = sum(document.weights.get(r["check_id"], 1) for r in results)
    passed = sum(document.weights.get(r["check_id"], 1) for r in results if r["status"] == "PASS")
    all_pass = bool(results) and all(r["status"] == "PASS" for r in results)
    score = 100 if all_pass else min(99, int(100 * passed / max(1, total)))
    state = "COMPLIANT" if all_pass else ("NONCOMPLIANT" if any(r["status"] == "FAIL" for r in results) else "UNVERIFIED")
    return {"score": score, "state": state, "checks": results}
