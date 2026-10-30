"""Add reviewed developer admission profiles without rewriting existing network records."""

from alembic import op
import sqlalchemy as sa

revision = "0005_network_profiles"
down_revision = "fae1ac5dc81c"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "network_profiles",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("name", sa.String(128), nullable=False, unique=True),
        sa.Column(
            "subnet_id", sa.String(36), sa.ForeignKey("subnets.id"), nullable=False
        ),
        sa.Column(
            "ap_group_id", sa.String(36), sa.ForeignKey("ap_groups.id"), nullable=False
        ),
        sa.Column("ssid", sa.String(128), nullable=False),
        sa.Column("vlan_id", sa.Integer(), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False),
    )
    op.create_index(
        "ix_network_profiles_created_at", "network_profiles", ["created_at"]
    )
    with op.batch_alter_table("devices") as batch:
        batch.add_column(sa.Column("network_profile_id", sa.String(36), nullable=True))
        batch.create_foreign_key(
            "fk_device_network_profile",
            "network_profiles",
            ["network_profile_id"],
            ["id"],
        )
        batch.create_index("ix_devices_network_profile_id", ["network_profile_id"])


def downgrade():
    with op.batch_alter_table("devices") as batch:
        batch.drop_index("ix_devices_network_profile_id")
        batch.drop_constraint("fk_device_network_profile", type_="foreignkey")
        batch.drop_column("network_profile_id")
    op.drop_index("ix_network_profiles_created_at", table_name="network_profiles")
    op.drop_table("network_profiles")
