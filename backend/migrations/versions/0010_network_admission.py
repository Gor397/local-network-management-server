"""Mandatory Suro Client network admission (pilot), developer exemptions, split user names."""

from alembic import op
import sqlalchemy as sa

revision = "0010_network_admission"
down_revision = "0009_policy_drafts"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "admission_policy",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("mode", sa.String(16), nullable=False, server_default="DISABLED"),
        sa.Column("group_ids", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("require_enrollment", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("require_running_agent", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("require_compliance", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("exempt_developers", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("heartbeat_timeout_seconds", sa.Integer(), nullable=False, server_default="300"),
        sa.Column("grace_seconds", sa.Integer(), nullable=False, server_default="300"),
        sa.Column("auto_revoke", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("onboarding_enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("outage_policy", sa.String(8), nullable=False, server_default="EXPIRE"),
        sa.Column("revision", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("updated_by", sa.String(36), sa.ForeignKey("administrators.id"), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
    )
    op.create_table(
        "network_admissions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(), nullable=True, index=True),
        sa.Column("device_id", sa.String(36), sa.ForeignKey("devices.id"), nullable=False, unique=True),
        sa.Column("router_id", sa.String(36), sa.ForeignKey("routers.id"), nullable=True, index=True),
        sa.Column("source", sa.String(16), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("gate_state", sa.String(24), nullable=False),
        sa.Column("gate_plan_id", sa.String(36), nullable=True),
        sa.Column("desired", sa.String(16), nullable=False),
        sa.Column("reason", sa.String(64), nullable=False),
        sa.Column("override", sa.String(16), nullable=True),
        sa.Column("override_until", sa.DateTime(), nullable=True),
        sa.Column("applied", sa.String(16), nullable=False),
        sa.Column("applied_at", sa.DateTime(), nullable=True),
        sa.Column("granted_ip", sa.String(45), nullable=True),
        sa.Column("grant_expires_at", sa.DateTime(), nullable=True),
        sa.Column("reported_ip", sa.String(45), nullable=True),
        sa.Column("reported_at", sa.DateTime(), nullable=True),
        sa.Column("onboarding_until", sa.DateTime(), nullable=True),
        sa.Column("error", sa.String(64), nullable=True),
        sa.Column("revision", sa.Integer(), nullable=False),
    )
    with op.batch_alter_table("devices") as batch:
        batch.add_column(sa.Column("admission_exempt", sa.Boolean(), nullable=False, server_default=sa.false()))
        batch.add_column(sa.Column("exemption_reason", sa.Text(), nullable=True))
    with op.batch_alter_table("user_identities") as batch:
        batch.add_column(sa.Column("first_name", sa.String(128), nullable=True))
        batch.add_column(sa.Column("last_name", sa.String(128), nullable=True))


def downgrade():
    with op.batch_alter_table("user_identities") as batch:
        batch.drop_column("last_name")
        batch.drop_column("first_name")
    with op.batch_alter_table("devices") as batch:
        batch.drop_column("exemption_reason")
        batch.drop_column("admission_exempt")
    op.drop_table("network_admissions")
    op.drop_table("admission_policy")
