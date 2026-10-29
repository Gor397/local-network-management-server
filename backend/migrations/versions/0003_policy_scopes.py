"""Add policy class, group and device scopes."""
from alembic import op
import sqlalchemy as sa
revision = '0003_policy_scopes'
down_revision = '0002_unique_address'
branch_labels = None
depends_on = None

def upgrade():
    with op.batch_alter_table('policy_overrides') as batch:
        batch.alter_column('device_id', existing_type=sa.String(36), nullable=True)
        batch.add_column(sa.Column('policy_id', sa.String(36), nullable=True))
        batch.add_column(sa.Column('group_id', sa.String(36), nullable=True))
        batch.add_column(sa.Column('device_class', sa.String(24), nullable=True))
        batch.add_column(sa.Column('reason', sa.Text(), nullable=False, server_default=''))
        batch.create_foreign_key('fk_override_policy', 'policies', ['policy_id'], ['id'])
        batch.create_foreign_key('fk_override_group', 'device_groups', ['group_id'], ['id'])
        batch.create_index('ix_policy_overrides_policy_id', ['policy_id'])

def downgrade():
    with op.batch_alter_table('policy_overrides') as batch:
        batch.drop_index('ix_policy_overrides_policy_id')
        batch.drop_constraint('fk_override_policy', type_='foreignkey')
        batch.drop_constraint('fk_override_group', type_='foreignkey')
        for column in ['policy_id', 'group_id', 'device_class', 'reason']:
            batch.drop_column(column)
    # Historical global scopes must be explicitly archived before removing the nullable-device schema.
