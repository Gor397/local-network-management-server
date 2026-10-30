"""Add descriptive labels for passively observed network endpoints."""

from alembic import op
import sqlalchemy as sa

revision = "0006_endpoint_labels"
down_revision = "0005_network_profiles"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "network_endpoint_labels",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("mac", sa.String(17), nullable=False, unique=True),
        sa.Column("category", sa.String(24), nullable=False),
        sa.Column("label", sa.String(128), nullable=False),
        sa.Column("note", sa.Text(), nullable=False),
        sa.Column("updated_by", sa.String(36), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
    )
    op.create_index(
        "ix_network_endpoint_labels_created_at", "network_endpoint_labels", ["created_at"]
    )


def downgrade():
    op.drop_index("ix_network_endpoint_labels_created_at", table_name="network_endpoint_labels")
    op.drop_table("network_endpoint_labels")
