"""Link CAPsMAN-managed access points to their controller."""

from alembic import op
import sqlalchemy as sa

revision = "0007_capsman_access_points"
down_revision = "0006_endpoint_labels"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("routers") as batch:
        batch.add_column(sa.Column("controller_id", sa.String(36), nullable=True))
        batch.create_foreign_key("fk_router_controller", "routers", ["controller_id"], ["id"])
        batch.create_index("ix_routers_controller_id", ["controller_id"])


def downgrade():
    with op.batch_alter_table("routers") as batch:
        batch.drop_index("ix_routers_controller_id")
        batch.drop_constraint("fk_router_controller", type_="foreignkey")
        batch.drop_column("controller_id")
