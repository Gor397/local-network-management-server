from datetime import datetime
from uuid import uuid4
from sqlalchemy import String, Text, DateTime, ForeignKey, UniqueConstraint, JSON, Integer, Boolean, Index
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
    state: Mapped[str] = mapped_column(String(30), default="PENDING_ENROLLMENT", index=True)
    agent_version: Mapped[str | None] = mapped_column(String(32))
    os_version: Mapped[str | None] = mapped_column(String(256))
    last_heartbeat: Mapped[datetime | None] = mapped_column(DateTime, index=True)
    last_verified: Mapped[datetime | None] = mapped_column(DateTime)
    policy_version_id: Mapped[str | None] = mapped_column(ForeignKey("policy_versions.id"))
    reported_policy_id: Mapped[str | None] = mapped_column(String(36))
    compliance_score: Mapped[int] = mapped_column(Integer, default=0)
    network_state: Mapped[str] = mapped_column(String(32), default="UNKNOWN")
    inventory: Mapped[dict] = mapped_column(JSON, default=dict)
    network_evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    revision: Mapped[int] = mapped_column(Integer, default=0)


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


class RequestNonce(Base):
    __tablename__ = "request_nonces"
    nonce: Mapped[str] = mapped_column(String(128), primary_key=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime, index=True)


class DeviceGroup(Record, Base):
    __tablename__ = "device_groups"
    name: Mapped[str] = mapped_column(String(128), unique=True)


class GroupMember(Base):
    __tablename__ = "group_members"
    group_id: Mapped[str] = mapped_column(ForeignKey("device_groups.id"), primary_key=True)
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
    report_id: Mapped[str] = mapped_column(ForeignKey("compliance_reports.id", ondelete="CASCADE"), index=True)
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
    __table_args__ = (UniqueConstraint("subnet_id", "address"), UniqueConstraint("subnet_id", "mac"))


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
