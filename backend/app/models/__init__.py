from datetime import datetime
from uuid import uuid4
from sqlalchemy import (
    String,
    Text,
    DateTime,
    ForeignKey,
    UniqueConstraint,
    JSON,
    Integer,
    Boolean,
    Index,
)
from sqlalchemy.orm import Mapped, mapped_column
from app.db import Base, utcnow


def uid():
    return str(uuid4())


class Record:
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)


class Role(Base):
    __tablename__ = "roles"
    name: Mapped[str] = mapped_column(String(30), primary_key=True)
    permissions: Mapped[list] = mapped_column(JSON, default=list)


class Administrator(Record, Base):
    __tablename__ = "administrators"
    username: Mapped[str] = mapped_column(String(128), unique=True)
    password_hash: Mapped[str] = mapped_column(Text)
    role: Mapped[str] = mapped_column(ForeignKey("roles.name"))
    totp_secret: Mapped[str | None] = mapped_column(Text)
    totp_last_step: Mapped[int] = mapped_column(Integer, default=-1)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)


class AdminSession(Base):
    __tablename__ = "admin_sessions"
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    admin_id: Mapped[str] = mapped_column(ForeignKey("administrators.id"), index=True)
    csrf: Mapped[str] = mapped_column(String(64))
    expires_at: Mapped[datetime] = mapped_column(DateTime, index=True)
    mfa_at: Mapped[datetime | None] = mapped_column(DateTime)


class Device(Record, Base):
    __tablename__ = "devices"
    hostname: Mapped[str] = mapped_column(String(128))
    device_class: Mapped[str] = mapped_column(String(24), default="STANDARD")
    primary_mac: Mapped[str] = mapped_column(String(17), unique=True)
    mode: Mapped[str] = mapped_column(String(30), default="AUDIT")
    state: Mapped[str] = mapped_column(
        String(30), default="PENDING_ENROLLMENT", index=True
    )
    agent_version: Mapped[str | None] = mapped_column(String(32))
    os_version: Mapped[str | None] = mapped_column(String(256))
    last_heartbeat: Mapped[datetime | None] = mapped_column(DateTime, index=True)
    last_verified: Mapped[datetime | None] = mapped_column(DateTime)
    policy_version_id: Mapped[str | None] = mapped_column(
        ForeignKey("policy_versions.id")
    )
    reported_policy_id: Mapped[str | None] = mapped_column(String(36))
    compliance_score: Mapped[int] = mapped_column(Integer, default=0)
    network_state: Mapped[str] = mapped_column(String(32), default="UNKNOWN")
    inventory: Mapped[dict] = mapped_column(JSON, default=dict)
    network_evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    revision: Mapped[int] = mapped_column(Integer, default=0)
    owner_name: Mapped[str | None] = mapped_column(String(256), index=True)
    owner_rank: Mapped[str | None] = mapped_column(String(128), index=True)
    owner_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    owner_account: Mapped[str | None] = mapped_column(String(256))
    identity_status: Mapped[str] = mapped_column(String(24), default="PENDING")
    last_user_account: Mapped[str | None] = mapped_column(String(256))
    last_user_sid: Mapped[str | None] = mapped_column(String(184))
    last_user_seen: Mapped[datetime | None] = mapped_column(DateTime)
    network_profile_id: Mapped[str | None] = mapped_column(
        ForeignKey("network_profiles.id"), index=True
    )


class NetworkInterface(Record, Base):
    __tablename__ = "network_interfaces"
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"), index=True)
    mac: Mapped[str] = mapped_column(String(17), unique=True)
    interface_id: Mapped[str] = mapped_column(String(128))
    details: Mapped[dict] = mapped_column(JSON, default=dict)


class Enrollment(Record, Base):
    __tablename__ = "enrollments"
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    used_at: Mapped[datetime | None] = mapped_column(DateTime)
    csr: Mapped[str | None] = mapped_column(Text)
    approved: Mapped[bool] = mapped_column(Boolean, default=False)


class DeviceCredential(Record, Base):
    __tablename__ = "device_credentials"
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"), index=True)
    fingerprint: Mapped[str] = mapped_column(String(64), unique=True)
    certificate: Mapped[str] = mapped_column(Text)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime)


class AdminCredential(Record, Base):
    """The local Windows administrator credential Suro can reveal for recovery.

    LEGACY_MAC_V1 stores only the pinned MAC (the password is derived on demand);
    RANDOM_V1 stores the Vault-sealed password. Never serialize `secret`.
    """
    __tablename__ = "admin_credentials"
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"), index=True)
    account: Mapped[str] = mapped_column(String(20))
    scheme: Mapped[str] = mapped_column(String(20))
    source_mac: Mapped[str | None] = mapped_column(String(17))
    secret: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(20), default="UNVERIFIED")
    verified_at: Mapped[datetime | None] = mapped_column(DateTime)
    verified_by: Mapped[str | None] = mapped_column(ForeignKey("administrators.id"))
    revision: Mapped[int] = mapped_column(Integer, default=0)
    __table_args__ = (UniqueConstraint("device_id", "account"),)


class RequestNonce(Base):
    __tablename__ = "request_nonces"
    nonce: Mapped[str] = mapped_column(String(128), primary_key=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime, index=True)


class DeviceGroup(Record, Base):
    __tablename__ = "device_groups"
    name: Mapped[str] = mapped_column(String(128), unique=True)
    description: Mapped[str] = mapped_column(Text, default="")


class GroupMember(Base):
    __tablename__ = "group_members"
    group_id: Mapped[str] = mapped_column(
        ForeignKey("device_groups.id"), primary_key=True
    )
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"), primary_key=True)


class Policy(Record, Base):
    __tablename__ = "policies"
    name: Mapped[str] = mapped_column(String(128), unique=True)
    active_version_id: Mapped[str | None] = mapped_column(String(36))


class PolicyVersion(Record, Base):
    __tablename__ = "policy_versions"
    policy_id: Mapped[str] = mapped_column(ForeignKey("policies.id"), index=True)
    sequence: Mapped[int] = mapped_column(Integer)
    content_hash: Mapped[str] = mapped_column(String(64))
    document: Mapped[dict] = mapped_column(JSON)
    payload: Mapped[str] = mapped_column(Text)
    signature: Mapped[str] = mapped_column(Text)
    author_id: Mapped[str] = mapped_column(ForeignKey("administrators.id"))
    reason: Mapped[str] = mapped_column(Text)
    __table_args__ = (UniqueConstraint("policy_id", "sequence"),)


class PolicyAssignment(Record, Base):
    __tablename__ = "policy_assignments"
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"), index=True)
    version_id: Mapped[str] = mapped_column(ForeignKey("policy_versions.id"))
    author_id: Mapped[str] = mapped_column(ForeignKey("administrators.id"))


class PolicyOverride(Record, Base):
    __tablename__ = "policy_overrides"
    device_id: Mapped[str | None] = mapped_column(ForeignKey("devices.id"), index=True)
    policy_id: Mapped[str | None] = mapped_column(ForeignKey("policies.id"), index=True)
    group_id: Mapped[str | None] = mapped_column(ForeignKey("device_groups.id"))
    device_class: Mapped[str | None] = mapped_column(String(24))
    reason: Mapped[str] = mapped_column(Text, default="")
    scope: Mapped[str] = mapped_column(String(24))
    priority: Mapped[int] = mapped_column(Integer)
    controls: Mapped[dict] = mapped_column(JSON)
    approved_relaxation: Mapped[bool] = mapped_column(Boolean, default=False)
    author_id: Mapped[str] = mapped_column(ForeignKey("administrators.id"))


class PolicyException(Record, Base):
    __tablename__ = "policy_exceptions"
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"), index=True)
    controls: Mapped[list] = mapped_column(JSON)
    reason: Mapped[str] = mapped_column(Text)
    author_id: Mapped[str] = mapped_column(ForeignKey("administrators.id"))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime)


class ComplianceReport(Record, Base):
    __tablename__ = "compliance_reports"
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"), index=True)
    version_id: Mapped[str | None] = mapped_column(ForeignKey("policy_versions.id"))
    state: Mapped[str] = mapped_column(String(30))
    score: Mapped[int] = mapped_column(Integer)


class ComplianceCheck(Record, Base):
    __tablename__ = "compliance_checks"
    report_id: Mapped[str] = mapped_column(
        ForeignKey("compliance_reports.id", ondelete="CASCADE"), index=True
    )
    check_id: Mapped[str] = mapped_column(String(128))
    status: Mapped[str] = mapped_column(String(12))
    severity: Mapped[str] = mapped_column(String(12))
    details: Mapped[dict] = mapped_column(JSON)


class HealthReport(Record, Base):
    __tablename__ = "health_reports"
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"), index=True)
    metrics: Mapped[dict] = mapped_column(JSON)


class Router(Record, Base):
    __tablename__ = "routers"
    name: Mapped[str] = mapped_column(String(128), unique=True)
    base_url: Mapped[str] = mapped_column(String(256), unique=True)
    username: Mapped[str] = mapped_column(String(128))
    secret: Mapped[str] = mapped_column(Text)
    ca_file: Mapped[str | None] = mapped_column(String(256))
    capabilities: Mapped[dict] = mapped_column(JSON, default=dict)
    snapshot: Mapped[str | None] = mapped_column(Text)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime)
    status: Mapped[str] = mapped_column(String(24), default="UNKNOWN")
    write_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    generation: Mapped[int] = mapped_column(Integer, default=0)
    lock_until: Mapped[datetime | None] = mapped_column(DateTime)
    role: Mapped[str] = mapped_column(String(24), default="ACCESS_POINT")
    transport: Mapped[str] = mapped_column(String(16), default="REST")
    protected: Mapped[bool] = mapped_column(Boolean, default=False)
    archived: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    inventory: Mapped[dict] = mapped_column(JSON, default=dict)
    health: Mapped[dict] = mapped_column(JSON, default=dict)
    last_health: Mapped[datetime | None] = mapped_column(DateTime)
    last_inventory: Mapped[datetime | None] = mapped_column(DateTime)
    last_reboot: Mapped[datetime | None] = mapped_column(DateTime)
    desired_config: Mapped[dict] = mapped_column(JSON, default=dict)
    recovery_policy: Mapped[dict] = mapped_column(JSON, default=dict)
    config_hash: Mapped[str | None] = mapped_column(String(64))
    ssh_host_key: Mapped[str | None] = mapped_column(Text)
    # Set for CAPsMAN access points: observed through this controller, never contacted directly.
    controller_id: Mapped[str | None] = mapped_column(ForeignKey("routers.id"), index=True)


class AccessPoint(Record, Base):
    __tablename__ = "access_points"
    router_id: Mapped[str] = mapped_column(ForeignKey("routers.id"), index=True)
    interface_name: Mapped[str] = mapped_column(String(128))
    stack: Mapped[str] = mapped_column(String(32))
    details: Mapped[dict] = mapped_column(JSON)
    __table_args__ = (UniqueConstraint("router_id", "interface_name", "stack"),)


class Subnet(Record, Base):
    __tablename__ = "subnets"
    router_id: Mapped[str] = mapped_column(ForeignKey("routers.id"))
    cidr: Mapped[str] = mapped_column(String(48))
    dhcp_server: Mapped[str] = mapped_column(String(128))
    allocation_start: Mapped[str] = mapped_column(String(48))
    allocation_end: Mapped[str] = mapped_column(String(48))
    exclusions: Mapped[list] = mapped_column(JSON, default=list)
    profile: Mapped[str] = mapped_column(String(32), default="developer")
    __table_args__ = (UniqueConstraint("router_id", "cidr", "dhcp_server"),)


class DhcpReservation(Record, Base):
    __tablename__ = "dhcp_reservations"
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"))
    subnet_id: Mapped[str] = mapped_column(ForeignKey("subnets.id"))
    address: Mapped[str] = mapped_column(String(48), unique=True)
    mac: Mapped[str] = mapped_column(String(17))
    verified_at: Mapped[datetime | None] = mapped_column(DateTime)
    __table_args__ = (
        UniqueConstraint("subnet_id", "address"),
        UniqueConstraint("subnet_id", "mac"),
    )


class NetworkAccessRule(Record, Base):
    __tablename__ = "network_access_rules"
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"))
    router_id: Mapped[str] = mapped_column(ForeignKey("routers.id"))
    owner_tag: Mapped[str] = mapped_column(String(128), unique=True)
    rule: Mapped[dict] = mapped_column(JSON)


class NetworkPlan(Record, Base):
    __tablename__ = "network_plans"
    device_id: Mapped[str | None] = mapped_column(ForeignKey("devices.id"))
    router_id: Mapped[str] = mapped_column(ForeignKey("routers.id"), index=True)
    generation: Mapped[int] = mapped_column(Integer)
    snapshot_hash: Mapped[str] = mapped_column(String(64))
    operations: Mapped[list] = mapped_column(JSON)
    state: Mapped[str] = mapped_column(String(24), default="PREVIEW")
    reason: Mapped[str] = mapped_column(Text)
    author_id: Mapped[str | None] = mapped_column(ForeignKey("administrators.id"))
    result: Mapped[dict] = mapped_column(JSON, default=dict)


class QuarantineState(Record, Base):
    __tablename__ = "quarantine_states"
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"), index=True)
    requested: Mapped[bool] = mapped_column(Boolean)
    verified: Mapped[bool] = mapped_column(Boolean, default=False)
    reason: Mapped[str] = mapped_column(Text)
    plan_ids: Mapped[list] = mapped_column(JSON, default=list)


class Alert(Record, Base):
    __tablename__ = "alerts"
    device_id: Mapped[str | None] = mapped_column(ForeignKey("devices.id"), index=True)
    severity: Mapped[str] = mapped_column(String(16))
    code: Mapped[str] = mapped_column(String(128))
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime)
    acknowledged_by: Mapped[str | None] = mapped_column(ForeignKey("administrators.id"))


class AuditLog(Record, Base):
    __tablename__ = "audit_logs"
    actor_id: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(128))
    target_id: Mapped[str] = mapped_column(String(128), index=True)
    details: Mapped[dict] = mapped_column(JSON, default=dict)


class BackgroundJob(Record, Base):
    __tablename__ = "background_jobs"
    device_id: Mapped[str | None] = mapped_column(ForeignKey("devices.id"))
    kind: Mapped[str] = mapped_column(String(40))
    status: Mapped[str] = mapped_column(String(24), default="PENDING", index=True)
    data: Mapped[dict] = mapped_column(JSON, default=dict)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    available_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class MigrationAssessment(Record, Base):
    __tablename__ = "migration_assessments"
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"), index=True)
    inventory_hash: Mapped[str] = mapped_column(String(64))
    report: Mapped[dict] = mapped_column(JSON)
    approved_by: Mapped[str | None] = mapped_column(ForeignKey("administrators.id"))
    backup_verified_at: Mapped[datetime | None] = mapped_column(DateTime)
    status: Mapped[str] = mapped_column(String(40), default="PREVIEW")


class RemediationResult(Record, Base):
    __tablename__ = "remediation_results"
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"), index=True)
    policy_version_id: Mapped[str] = mapped_column(ForeignKey("policy_versions.id"))
    operation: Mapped[str] = mapped_column(String(64))
    result: Mapped[dict] = mapped_column(JSON)


class SoftwarePackage(Record, Base):
    __tablename__ = "software_packages"
    name: Mapped[str] = mapped_column(String(128))
    filename: Mapped[str] = mapped_column(String(256))
    sha256: Mapped[str] = mapped_column(String(64), unique=True)
    size: Mapped[int] = mapped_column(Integer)
    kind: Mapped[str] = mapped_column(String(32))
    publisher_thumbprint: Mapped[str] = mapped_column(String(128))
    metadata_: Mapped[dict] = mapped_column("metadata", JSON, default=dict)
    approved_by: Mapped[str | None] = mapped_column(ForeignKey("administrators.id"))


class Upload(Record, Base):
    __tablename__ = "uploads"
    admin_id: Mapped[str] = mapped_column(ForeignKey("administrators.id"))
    sha256: Mapped[str] = mapped_column(String(64))
    size: Mapped[int] = mapped_column(Integer)
    offset: Mapped[int] = mapped_column(Integer, default=0)
    descriptor: Mapped[dict] = mapped_column(JSON)
    completed: Mapped[bool] = mapped_column(Boolean, default=False)


class Deployment(Record, Base):
    __tablename__ = "deployments"
    package_id: Mapped[str] = mapped_column(ForeignKey("software_packages.id"))
    author_id: Mapped[str] = mapped_column(ForeignKey("administrators.id"))
    action: Mapped[str] = mapped_column(String(32))
    arguments: Mapped[list] = mapped_column(JSON, default=list)
    not_before: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    reason: Mapped[str] = mapped_column(Text)
    cancelled: Mapped[bool] = mapped_column(Boolean, default=False)


class DeploymentTask(Record, Base):
    __tablename__ = "deployment_tasks"
    deployment_id: Mapped[str] = mapped_column(ForeignKey("deployments.id"))
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"), index=True)
    state: Mapped[str] = mapped_column(String(32), default="PENDING", index=True)
    lease_until: Mapped[datetime | None] = mapped_column(DateTime)
    attempt: Mapped[int] = mapped_column(Integer, default=0)
    manifest: Mapped[dict] = mapped_column(JSON, default=dict)
    result: Mapped[dict] = mapped_column(JSON, default=dict)
    __table_args__ = (UniqueConstraint("deployment_id", "device_id"),)


class SshTarget(Base):
    __tablename__ = "ssh_targets"
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"), primary_key=True)
    host: Mapped[str] = mapped_column(String(128))
    port: Mapped[int] = mapped_column(Integer, default=22)
    username: Mapped[str] = mapped_column(String(128))
    host_public_key: Mapped[str] = mapped_column(Text)
    private_key: Mapped[str] = mapped_column(Text)


class SshSession(Record, Base):
    __tablename__ = "ssh_sessions"
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"))
    admin_id: Mapped[str] = mapped_column(ForeignKey("administrators.id"))
    ticket_hash: Mapped[str] = mapped_column(String(64), unique=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    state: Mapped[str] = mapped_column(String(24), default="AUTHORIZED")
    maintenance_approved: Mapped[bool] = mapped_column(Boolean, default=False)
    reason: Mapped[str] = mapped_column(Text)
    bytes_recorded: Mapped[int] = mapped_column(Integer, default=0)


class UserIdentity(Record, Base):
    __tablename__ = "user_identities"
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"), index=True)
    windows_sid: Mapped[str] = mapped_column(String(184))
    windows_account: Mapped[str] = mapped_column(String(256))
    full_name: Mapped[str] = mapped_column(String(256), index=True)
    military_rank: Mapped[str | None] = mapped_column(String(128), index=True)
    verified_by: Mapped[str | None] = mapped_column(ForeignKey("administrators.id"))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    __table_args__ = (UniqueConstraint("device_id", "windows_sid"),)


class OwnerAssignment(Record, Base):
    __tablename__ = "owner_assignments"
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"), index=True)
    full_name: Mapped[str | None] = mapped_column(String(256))
    military_rank: Mapped[str | None] = mapped_column(String(128))
    windows_account: Mapped[str | None] = mapped_column(String(256))
    verified: Mapped[bool] = mapped_column(Boolean)
    author_id: Mapped[str] = mapped_column(ForeignKey("administrators.id"))
    reason: Mapped[str] = mapped_column(Text)


class ApGroup(Record, Base):
    __tablename__ = "ap_groups"
    name: Mapped[str] = mapped_column(String(128), unique=True)
    description: Mapped[str] = mapped_column(Text, default="")
    template: Mapped[dict] = mapped_column(JSON, default=dict)
    revision: Mapped[int] = mapped_column(Integer, default=0)


class ApGroupMember(Base):
    __tablename__ = "ap_group_members"
    group_id: Mapped[str] = mapped_column(
        ForeignKey("ap_groups.id", ondelete="CASCADE"), primary_key=True
    )
    router_id: Mapped[str] = mapped_column(ForeignKey("routers.id"), primary_key=True)


class RouterTelemetry(Record, Base):
    __tablename__ = "router_telemetry"
    router_id: Mapped[str] = mapped_column(ForeignKey("routers.id"), index=True)
    metrics: Mapped[dict] = mapped_column(JSON)
    clients: Mapped[list] = mapped_column(JSON, default=list)
    facts: Mapped[list] = mapped_column(JSON, default=list)


class ClientObservation(Record, Base):
    __tablename__ = "client_observations"
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"), index=True)
    observed_at: Mapped[datetime] = mapped_column(DateTime, index=True)
    sequence: Mapped[str] = mapped_column(String(64))
    data: Mapped[dict] = mapped_column(JSON)
    __table_args__ = (UniqueConstraint("device_id", "sequence"),)


class NetworkBatch(Record, Base):
    __tablename__ = "network_batches"
    author_id: Mapped[str | None] = mapped_column(ForeignKey("administrators.id"))
    kind: Mapped[str] = mapped_column(String(32), default="NETWORK")
    state: Mapped[str] = mapped_column(String(32), default="PREVIEW", index=True)
    operation: Mapped[str] = mapped_column(String(40))
    parameters: Mapped[dict] = mapped_column(JSON, default=dict)
    batch_size: Mapped[int] = mapped_column(Integer, default=1)
    stop_on_failure: Mapped[bool] = mapped_column(Boolean, default=True)
    not_before: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    window_end: Mapped[datetime | None] = mapped_column(DateTime)
    reason: Mapped[str] = mapped_column(Text)
    automatic: Mapped[bool] = mapped_column(Boolean, default=False)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime)


class OperationTarget(Record, Base):
    __tablename__ = "operation_targets"
    batch_id: Mapped[str] = mapped_column(ForeignKey("network_batches.id"), index=True)
    router_id: Mapped[str | None] = mapped_column(ForeignKey("routers.id"), index=True)
    device_id: Mapped[str | None] = mapped_column(ForeignKey("devices.id"), index=True)
    state: Mapped[str] = mapped_column(String(32), default="PENDING", index=True)
    preview: Mapped[dict] = mapped_column(JSON, default=dict)
    result: Mapped[dict] = mapped_column(JSON, default=dict)
    started_at: Mapped[datetime | None] = mapped_column(DateTime)
    deadline: Mapped[datetime | None] = mapped_column(DateTime)
    __table_args__ = (
        UniqueConstraint("batch_id", "router_id"),
        UniqueConstraint("batch_id", "device_id"),
    )


class ConfigurationBackup(Record, Base):
    __tablename__ = "configuration_backups"
    router_id: Mapped[str] = mapped_column(ForeignKey("routers.id"), index=True)
    author_id: Mapped[str | None] = mapped_column(ForeignKey("administrators.id"))
    kind: Mapped[str] = mapped_column(String(24))
    encrypted_content: Mapped[str] = mapped_column(Text)
    content_hash: Mapped[str] = mapped_column(String(64))
    metadata_: Mapped[dict] = mapped_column("metadata", JSON, default=dict)


class Incident(Record, Base):
    __tablename__ = "incidents"
    dedup_key: Mapped[str] = mapped_column(String(256), unique=True)
    title_key: Mapped[str] = mapped_column(String(128))
    cause_key: Mapped[str] = mapped_column(String(128))
    confidence: Mapped[str] = mapped_column(String(16))
    severity: Mapped[str] = mapped_column(String(16))
    state: Mapped[str] = mapped_column(String(24), default="OPEN", index=True)
    router_ids: Mapped[list] = mapped_column(JSON, default=list)
    device_ids: Mapped[list] = mapped_column(JSON, default=list)
    facts: Mapped[list] = mapped_column(JSON, default=list)
    recommendations: Mapped[list] = mapped_column(JSON, default=list)
    last_observed: Mapped[datetime] = mapped_column(
        DateTime, default=utcnow, index=True
    )
    acknowledged_by: Mapped[str | None] = mapped_column(ForeignKey("administrators.id"))
    assigned_to: Mapped[str | None] = mapped_column(ForeignKey("administrators.id"))
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime)


class IncidentHistory(Record, Base):
    __tablename__ = "incident_history"
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"), index=True)
    actor_id: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(32))
    details: Mapped[dict] = mapped_column(JSON, default=dict)


class MaintenanceWindow(Record, Base):
    __tablename__ = "maintenance_windows"
    name: Mapped[str] = mapped_column(String(128))
    starts_at: Mapped[datetime] = mapped_column(DateTime, index=True)
    ends_at: Mapped[datetime] = mapped_column(DateTime, index=True)
    router_ids: Mapped[list] = mapped_column(JSON, default=list)
    device_ids: Mapped[list] = mapped_column(JSON, default=list)
    author_id: Mapped[str] = mapped_column(ForeignKey("administrators.id"))


class SystemSetting(Base):
    __tablename__ = "system_settings"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[dict] = mapped_column(JSON)


class NetworkProfile(Record, Base):
    __tablename__ = "network_profiles"
    name: Mapped[str] = mapped_column(String(128), unique=True)
    subnet_id: Mapped[str] = mapped_column(ForeignKey("subnets.id"))
    ap_group_id: Mapped[str] = mapped_column(ForeignKey("ap_groups.id"))
    ssid: Mapped[str] = mapped_column(String(128))
    vlan_id: Mapped[int | None] = mapped_column(Integer)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)


class NetworkEndpointLabel(Record, Base):
    """Administrator description of an observed address. Descriptive only: never trust, admission or exemption."""
    __tablename__ = "network_endpoint_labels"
    mac: Mapped[str] = mapped_column(String(17), unique=True)
    category: Mapped[str] = mapped_column(String(24), default="UNKNOWN")
    label: Mapped[str] = mapped_column(String(128), default="")
    note: Mapped[str] = mapped_column(Text, default="")
    updated_by: Mapped[str | None] = mapped_column(String(36))
    updated_at: Mapped[datetime | None] = mapped_column(DateTime)
