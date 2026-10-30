"""Recoverable local administrator credentials (legacy MAC-derived and random)."""

from alembic import op
import sqlalchemy as sa

revision = "0008_admin_credentials"
down_revision = "0007_capsman_access_points"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "admin_credentials",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("device_id", sa.String(36), sa.ForeignKey("devices.id"), nullable=False),
        sa.Column("account", sa.String(20), nullable=False),
        sa.Column("scheme", sa.String(20), nullable=False),
        sa.Column("source_mac", sa.String(17), nullable=True),
        sa.Column("secret", sa.Text(), nullable=True),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("verified_at", sa.DateTime(), nullable=True),
        sa.Column("verified_by", sa.String(36), sa.ForeignKey("administrators.id"), nullable=True),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.UniqueConstraint("device_id", "account"),
    )
    op.create_index("ix_admin_credentials_device_id", "admin_credentials", ["device_id"])
    op.create_index("ix_admin_credentials_created_at", "admin_credentials", ["created_at"])


def downgrade():
    op.drop_index("ix_admin_credentials_created_at", "admin_credentials")
    op.drop_index("ix_admin_credentials_device_id", "admin_credentials")
    op.drop_table("admin_credentials")
