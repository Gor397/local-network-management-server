from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, model_validator

CATALOG = {
    "account.admin.exists": ("agent", "critical"),
    "account.admin.member_of_administrators": ("agent", "critical"),
    "account.user.exists": ("agent", "high"),
    "account.user.not_administrator": ("agent", "critical"),
    "account.unexpected_administrators.absent": ("agent", "critical"),
    "disk.c.valid": ("agent", "high"),
    "disk.d.valid": ("agent", "high"),
    "disk.user_data_location.valid": ("agent", "high"),
    "firewall.enabled": ("agent", "critical"),
    "firewall.outbound_policy.valid": ("agent", "critical"),
    "firewall.managed_rules.valid": ("agent", "critical"),
    "network.ip_reservation.valid": ("network", "high"),
    "network.mac_identity.valid": ("network", "high"),
    "network.internet_restriction.valid": ("network", "critical"),
    "network.isolation.valid": ("network", "critical"),
    "security.user_restrictions.valid": ("agent", "high"),
    "agent.service_running": ("agent", "critical"),
    "agent.integrity_valid": ("agent", "critical"),
    "agent.policy_version_current": ("server", "critical"),
}


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Allowance(Strict):
    remote: str
    protocol: Literal["TCP", "UDP", "ICMPv4", "ICMPv6"]
    ports: list[int] = Field(default_factory=list, max_length=32)

    @model_validator(mode="after")
    def valid(self):
        from ipaddress import ip_network
        network = ip_network(self.remote, strict=False)
        if network.prefixlen == 0 or not network.is_private or network.is_multicast:
            raise ValueError("policy.internal_network_required")
        if any(not 1 <= p <= 65535 for p in self.ports):
            raise ValueError("policy.invalid_port")
        return self


class PolicyDocument(Strict):
    schema_version: Literal[1] = 1
    admin_account: str = Field(default="admin", pattern=r"^[A-Za-z][A-Za-z0-9_-]{0,19}$")
    user_account: str = Field(default="user", pattern=r"^[A-Za-z][A-Za-z0-9_-]{0,19}$")
    require_d: bool = True
    hide_c: bool = False
    approved_admins: list[str] = Field(default_factory=lambda: ["admin"])
    firewall_allowances: list[Allowance] = Field(default_factory=list, max_length=100)
    mandatory_checks: list[str] = Field(default_factory=lambda: list(CATALOG))
    weights: dict[str, int] = Field(default_factory=dict)
    heartbeat_seconds: int = Field(default=120, ge=30, le=3600)
    heartbeat_deadline_seconds: int = Field(default=300, ge=90, le=86400)
    evidence_ttl_seconds: int = Field(default=300, ge=60, le=3600)
    quarantine_on_failure: bool = False
    quarantine_on_missing_heartbeat: bool = False
    remediation_grace_seconds: int = Field(default=300, ge=0, le=86400)
    auto_remediate: list[Literal["firewall.enable", "account.demote_user", "settings.hide_c"]] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_checks(self):
        if self.admin_account == self.user_account:
            raise ValueError("policy.accounts_must_differ")
        if not self.mandatory_checks or len(set(self.mandatory_checks)) != len(self.mandatory_checks):
            raise ValueError("policy.invalid_checks")
        if set(self.mandatory_checks) - CATALOG.keys() or set(self.weights) - CATALOG.keys():
            raise ValueError("policy.unknown_check")
        if any(w < 1 or w > 100 for w in self.weights.values()):
            raise ValueError("policy.invalid_weight")
        return self


def merge_layers(base: dict, layers: list[dict]):
    """Stable priority order; relaxation requires separate approval metadata."""
    merged = dict(base)
    for layer in sorted(layers, key=lambda x: (x["priority"], x["id"])):
        for key, value in layer["controls"].items():
            old = merged.get(key)
            relaxation = (key in ("require_d", "quarantine_on_failure", "quarantine_on_missing_heartbeat") and old is True and value is False)
            relaxation |= key == "mandatory_checks" and not set(old or []).issubset(value)
            relaxation |= key == "firewall_allowances" and any(a not in (old or []) for a in value)
            relaxation |= key == "approved_admins" and not set(value).issubset(old or [])
            relaxation |= key == "auto_remediate" and bool(value)
            relaxation |= key in ("evidence_ttl_seconds", "heartbeat_deadline_seconds", "remediation_grace_seconds") and value > (old or 0)
            if relaxation and not layer.get("approved_relaxation"):
                raise ValueError(f"policy.relaxation_requires_approval:{key}")
            merged[key] = value
    return PolicyDocument.model_validate(merged).model_dump()
