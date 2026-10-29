"""Require globally unique inventory reservations (overlapping routed address spaces are unsupported)."""
from alembic import op

revision = '0002_unique_address'
down_revision = '4a74418cf2b8'
branch_labels = None
depends_on = None

def upgrade():
    with op.batch_alter_table('dhcp_reservations') as batch:
        batch.create_unique_constraint('uq_reservation_address', ['address'])

def downgrade():
    with op.batch_alter_table('dhcp_reservations') as batch:
        batch.drop_constraint('uq_reservation_address', type_='unique')
