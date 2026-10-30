"""The one definition of every policy setting the visual editor shows.

The dashboard renders its form from `SETTINGS`; labels come from `policySetting.<id>.*` translation keys.
`enforcement` states honestly what happens on Windows:

- agent:      the Windows agent changes it automatically (only in Continuous / Approved remediation mode).
- approval:   applied only by a separately approved maintenance job with verification and rollback.
- detected:   the agent checks and reports it; nothing is changed on the computer.
- server:     Suro's server acts on it (scheduling, freshness, deployment gates).
- protected:  an always-on safety rule; it cannot be switched off and is not stored in the policy.
- unavailable: not implemented; shown so administrators know, never stored or reported compliant.

A setting with `feature` is delivered only to agents that report that feature (see `agent_document`).
"""

from ipaddress import ip_address, ip_network
from urllib.parse import urlsplit
from app.policies.schema import CATALOG, PolicyDocument

CATEGORIES = ["accounts", "disk", "network", "firewall", "system", "software", "agent", "advanced"]


def _s(id, category, control, enforcement, risk="safe", **extra):
    return {"id": id, "key": extra.pop("key", id), "category": category, "control": control,
            "enforcement": enforcement, "risk": risk, **extra}


SETTINGS = [
    _s("require_admin_account", "accounts", "toggle", "detected"),
    _s("admin_account", "accounts", "text", "detected", visible_if={"require_admin_account": [True]}),
    _s("require_standard_user", "accounts", "toggle", "detected"),
    _s("user_account", "accounts", "text", "detected", visible_if={"require_standard_user": [True]}),
    _s("demote_standard_user", "accounts", "flag", "agent", "high", key="auto_remediate", value="account.demote_user",
       visible_if={"require_standard_user": [True]}),
    _s("approved_admins", "accounts", "list", "detected"),
    _s("legacy_admin_accepted", "accounts", "flag", "detected", key="approved_admins", value="AcademyAdmin"),
    _s("preserve_user_files", "accounts", "protected", "protected"),

    _s("require_d", "disk", "toggle", "detected", "high"),
    _s("min_d_gb", "disk", "number", "detected", "high", unit="GB", min=0, max=16384, feature="min_d_gb",
       visible_if={"require_d": [True]}),
    _s("require_user_data_on_d", "disk", "toggle", "detected", "high", visible_if={"require_d": [True]}),
    _s("backup_before_disk_changes", "disk", "protected", "protected"),
    _s("no_automatic_repartition", "disk", "protected", "protected"),
    _s("protect_system_files", "disk", "unavailable", "unavailable"),

    _s("ip_mode", "network", "select", "detected", "network", options=["unmanaged", "dhcp", "dhcp_reservation", "static"],
       feature="ip_mode"),
    _s("ip_prefix", "network", "text", "detected", "network", format="cidr", feature="ip_mode",
       visible_if={"ip_mode": ["static"]}),
    _s("ip_gateway", "network", "text", "detected", "network", format="ipv4", feature="ip_mode",
       visible_if={"ip_mode": ["static"]}),
    _s("dns_servers", "network", "list", "detected", "network", format="ipv4", max_items=4, feature="ip_mode",
       visible_if={"ip_mode": ["static"]}),
    _s("static_address_per_computer", "network", "protected", "protected", visible_if={"ip_mode": ["static"]}),
    _s("verify_connectivity", "network", "protected", "protected"),
    _s("apply_ip_configuration", "network", "unavailable", "unavailable", visible_if={"ip_mode": ["static", "dhcp"]}),

    _s("block_internet", "firewall", "toggle", "approval", "network"),
    _s("management_always_allowed", "firewall", "protected", "protected"),
    _s("firewall_allowances", "firewall", "allowances", "approval", "network", visible_if={"block_internet": [True]}),
    _s("firewall_auto_enable", "firewall", "flag", "agent", key="auto_remediate", value="firewall.enable"),

    _s("hide_c", "system", "toggle", "detected", "restart"),
    _s("hide_c_auto", "system", "flag", "agent", "restart", key="auto_remediate", value="settings.hide_c",
       visible_if={"hide_c": [True]}),

    _s("allow_software_deployment", "software", "toggle", "server"),

    _s("heartbeat_seconds", "agent", "number", "agent", unit="seconds", min=30, max=3600, feature="heartbeat_interval"),
    _s("heartbeat_deadline_seconds", "agent", "number", "server", unit="seconds", min=90, max=86400),
    _s("evidence_ttl_seconds", "agent", "number", "server", unit="seconds", min=60, max=3600),
    _s("offline_policy_cache", "agent", "protected", "protected"),
    _s("automatic_retry", "agent", "unavailable", "unavailable"),

    _s("mandatory_checks", "advanced", "checks", "server", options=list(CATALOG)),
    _s("quarantine_on_failure", "advanced", "toggle", "server", "network"),
    _s("quarantine_on_missing_heartbeat", "advanced", "toggle", "server", "network"),
    _s("remediation_grace_seconds", "advanced", "number", "server", unit="seconds", min=0, max=86400,
       visible_if={"quarantine_on_failure": [True]}),
]

# The document keys that v1 agents accept (agent/src/PolicyEngine/SignedDocument.cs); anything else makes them
# reject the whole policy, so other keys are sent only to agents that report the matching feature.
AGENT_V1_KEYS = {"schema_version", "admin_account", "user_account", "require_d", "hide_c", "approved_admins",
                 "firewall_allowances", "mandatory_checks", "weights", "heartbeat_seconds", "heartbeat_deadline_seconds",
                 "evidence_ttl_seconds", "quarantine_on_failure", "quarantine_on_missing_heartbeat",
                 "remediation_grace_seconds", "auto_remediate"}
AGENT_FEATURE_KEYS = {"min_d_gb": "min_d_gb", "ip_mode": "ip_mode", "ip_prefix": "ip_mode", "ip_gateway": "ip_mode",
                      "dns_servers": "ip_mode", "static_ip_address": "ip_mode"}
AGENT_FEATURES = sorted(set(AGENT_FEATURE_KEYS.values()) | {"heartbeat_interval"})


def agent_document(document, features):
    features = set(features or [])
    return {k: v for k, v in document.items()
            if k in AGENT_V1_KEYS or (k in AGENT_FEATURE_KEYS and AGENT_FEATURE_KEYS[k] in features)}


def management_allowance(public_origin):
    """The firewall allowance that keeps the agent able to reach Suro, or None if the address is a host name."""
    parts = urlsplit(public_origin)
    try:
        address = ip_address(parts.hostname or "")
    except ValueError:
        return None
    if not address.is_private:
        return None
    return {"remote": f"{address}/{32 if address.version == 4 else 128}", "protocol": "TCP", "ports": [parts.port or 443]}


def server_checks(document, public_origin):
    """Problems only the server can see. Errors block saving; warnings are shown before publishing."""
    errors, warnings = [], []
    management = management_allowance(public_origin)
    allowances = document.get("firewall_allowances") or []
    if document.get("block_internet", True):
        if management is None:
            warnings.append({"field": "firewall_allowances", "code": "policy.management_address_unverified"})
        elif not any(a.get("remote") == management["remote"] and a.get("protocol") == "TCP"
                     and management["ports"][0] in (a.get("ports") or []) for a in allowances):
            # The firewall job refuses to run without it; saving it would only create a policy that cannot be applied.
            errors.append({"field": "firewall_allowances", "code": "policy.management_not_allowed", "fix": management})
        for dns in document.get("dns_servers") or []:
            if not any(_covers(a, dns, 53) for a in allowances):
                warnings.append({"field": "dns_servers", "code": "policy.dns_blocked", "value": dns})
    if not document.get("allow_software_deployment", True):
        warnings.append({"field": "allow_software_deployment", "code": "policy.deployment_disabled"})
    if document.get("require_d") and "disk.d.valid" in (document.get("mandatory_checks") or []):
        warnings.append({"field": "require_d", "code": "policy.disk_changes_manual"})
    return errors, warnings


def _covers(allowance, address, port):
    try:
        return (ip_address(address) in ip_network(allowance.get("remote", ""), strict=False)
                and (not allowance.get("ports") or port in allowance["ports"]))
    except ValueError:
        return False


def validation_errors(exc):
    """Pydantic errors as {field, code} pairs whose codes the dashboard translates."""
    result = []
    for error in exc.errors():
        message = str(error.get("msg", ""))
        code = message.split(", ", 1)[1] if message.startswith("Value error, ") else "policy.invalid_value"
        field = ".".join(str(p) for p in error.get("loc", ()) if p not in ("body", "document")) or None
        if error.get("type") in ("string_pattern_mismatch",):
            code = "policy.invalid_account_name"
        elif error.get("type") in ("greater_than_equal", "less_than_equal", "too_long", "too_short"):
            code = "policy.out_of_range"
        elif error.get("type") == "extra_forbidden":
            code = "policy.unknown_setting"
        result.append({"field": field, "code": code})
    return result


RISK_KEYS = {
    "network": {"block_internet", "ip_mode", "ip_prefix", "ip_gateway", "dns_servers", "static_ip_address",
                "firewall_allowances", "quarantine_on_failure", "quarantine_on_missing_heartbeat"},
    "high": {"require_d", "min_d_gb", "require_user_data_on_d", "auto_remediate"},
    "restart": {"hide_c"},
}
# Publishing changes these on computers automatically (in Continuous / Approved remediation mode only).
AUTOMATIC_KEYS = {"auto_remediate", "hide_c", "heartbeat_seconds"}


def diff(old, new):
    """Readable setting-level changes between two documents (missing keys take today's defaults)."""
    defaults = PolicyDocument().model_dump()
    old = {**defaults, **(old or {})}
    new = {**defaults, **(new or {})}
    changes = []
    for key in PolicyDocument.model_fields:
        before, after = old.get(key), new.get(key)
        if before == after:
            continue
        risk = next((name for name, keys in RISK_KEYS.items() if key in keys), "safe")
        change = {"key": key, "before": before, "after": after, "risk": risk, "automatic": key in AUTOMATIC_KEYS}
        if isinstance(before, list) and isinstance(after, list):
            change["added"] = [v for v in after if v not in before]
            change["removed"] = [v for v in before if v not in after]
        changes.append(change)
    return changes


def _base(**changes):
    return PolicyDocument(**changes).model_dump()


def templates(public_origin):
    management = management_allowance(public_origin)
    allow = [management] if management else []
    return {
        "standard": _base(firewall_allowances=allow, auto_remediate=["firewall.enable"], ip_mode="dhcp_reservation"),
        "restricted": _base(firewall_allowances=allow, hide_c=True, ip_mode="dhcp_reservation",
                            auto_remediate=["firewall.enable", "account.demote_user", "settings.hide_c"]),
        # More reporting, no automatic changes: technicians work on these computers by hand.
        "maintenance": _base(firewall_allowances=allow, auto_remediate=[], heartbeat_seconds=60),
        "custom": _base(firewall_allowances=allow),
    }
