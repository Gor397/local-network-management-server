"""Mandatory Suro Client for all computers of a subnet except exceptions."""

from alembic import op
import sqlalchemy as sa

revision = "0011_admission_subnets"
down_revision = "0010_network_admission"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "admission_subnets",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(), nullable=True, index=True),
        sa.Column("router_id", sa.String(36), sa.ForeignKey("routers.id"), nullable=False, index=True),
        sa.Column("cidr", sa.String(43), nullable=False),
        sa.Column("state", sa.String(16), nullable=False),
        sa.Column("plan_id", sa.String(36), nullable=True),
        sa.Column("error", sa.String(64), nullable=True),
        sa.Column("created_by", sa.String(36), sa.ForeignKey("administrators.id"), nullable=True),
        sa.Column("revision", sa.Integer(), nullable=False),
    )


def downgrade():
    op.drop_table("admission_subnets")
