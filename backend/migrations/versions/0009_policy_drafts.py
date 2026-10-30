"""Policy drafts, descriptions and templates; agent policy features."""

from alembic import op
import sqlalchemy as sa

revision = "0009_policy_drafts"
down_revision = "0008_admin_credentials"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("policies") as batch:
        batch.add_column(sa.Column("description", sa.Text(), nullable=False, server_default=""))
        batch.add_column(sa.Column("draft", sa.JSON(), nullable=True))
        batch.add_column(sa.Column("draft_updated_at", sa.DateTime(), nullable=True))
        batch.add_column(sa.Column("draft_author_id", sa.String(36), nullable=True))
        batch.add_column(sa.Column("is_template", sa.Boolean(), nullable=False, server_default=sa.false()))
        batch.create_foreign_key("fk_policy_draft_author", "administrators", ["draft_author_id"], ["id"])
    with op.batch_alter_table("devices") as batch:
        batch.add_column(sa.Column("agent_features", sa.JSON(), nullable=False, server_default="[]"))


def downgrade():
    with op.batch_alter_table("devices") as batch:
        batch.drop_column("agent_features")
    with op.batch_alter_table("policies") as batch:
        batch.drop_constraint("fk_policy_draft_author", type_="foreignkey")
        for column in ("is_template", "draft_author_id", "draft_updated_at", "draft", "description"):
            batch.drop_column(column)
