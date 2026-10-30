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
    "endpoint.ip_configuration.valid": ("agent", "high"),
}

ACCOUNT_NAME = r"^[A-Za-z][A-Za-z0-9_-]{0,19}$"


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


def _address(value, code):
    from ipaddress import ip_address
    try:
        address = ip_address(value)
    except ValueError:
        raise ValueError(code) from None
    if address.version != 4 or address.is_multicast or address.is_unspecified or address.is_loopback:
        raise ValueError(code)
    return address


class PolicyDocument(Strict):
    """Desired configuration. Fields added after v1 have defaults that keep older documents' meaning.

    The visual editor, labels and enforcement status for each field live in policies/catalog.py.
    """
    schema_version: Literal[1] = 1
    require_admin_account: bool = True
    admin_account: str = Field(default="admin", pattern=ACCOUNT_NAME)
    require_standard_user: bool = True
    user_account: str = Field(default="user", pattern=ACCOUNT_NAME)
    require_d: bool = True
    require_user_data_on_d: bool = True
    min_d_gb: int = Field(default=0, ge=0, le=16384)
    hide_c: bool = False
    approved_admins: list[str] = Field(default_factory=lambda: ["admin"], max_length=20)
    block_internet: bool = True
    ip_mode: Literal["unmanaged", "dhcp", "dhcp_reservation", "static"] = "unmanaged"
    ip_prefix: str | None = Field(default=None, max_length=43)
    ip_gateway: str | None = Field(default=None, max_length=39)
    dns_servers: list[str] = Field(default_factory=list, max_length=4)
    # Set only by a computer-specific layer; a shared policy cannot give many computers one address.
    static_ip_address: str | None = Field(default=None, max_length=39)
    allow_software_deployment: bool = True
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
        import re
        if any(not re.fullmatch(ACCOUNT_NAME, name) for name in self.approved_admins):
            raise ValueError("policy.invalid_account_name")
        if self.min_d_gb and not self.require_d:
            raise ValueError("policy.min_d_without_d")
        if self.ip_mode == "static":
            from ipaddress import ip_network
            if not self.ip_prefix:
                raise ValueError("policy.static_prefix_required")
            try:
                network = ip_network(self.ip_prefix, strict=True)
            except ValueError:
                raise ValueError("policy.invalid_prefix") from None
            if network.version != 4 or not network.is_private or not 8 <= network.prefixlen <= 30:
                raise ValueError("policy.invalid_prefix")
            reserved = {network.network_address, network.broadcast_address}
            if self.ip_gateway:
                gateway = _address(self.ip_gateway, "policy.invalid_gateway")
                if gateway not in network or gateway in reserved:
                    raise ValueError("policy.gateway_outside_prefix")
            for value in self.dns_servers:
                _address(value, "policy.invalid_dns")
            if self.static_ip_address:
                address = _address(self.static_ip_address, "policy.invalid_static_address")
                if address not in network or address in reserved:
                    raise ValueError("policy.static_address_outside_prefix")
                if self.ip_gateway and address == _address(self.ip_gateway, "policy.invalid_gateway"):
                    raise ValueError("policy.static_address_is_gateway")
        elif self.ip_prefix or self.ip_gateway or self.dns_servers or self.static_ip_address:
            raise ValueError("policy.static_fields_without_static_mode")
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
            relaxation |= key in ("require_admin_account", "require_standard_user", "require_user_data_on_d", "block_internet") and old is True and value is False
            relaxation |= key == "min_d_gb" and value < (old or 0)
            relaxation |= key == "ip_mode" and value == "unmanaged" and old not in (None, "unmanaged")
            if relaxation and not layer.get("approved_relaxation"):
                raise ValueError(f"policy.relaxation_requires_approval:{key}")
            merged[key] = value
    return PolicyDocument.model_validate(merged).model_dump()
