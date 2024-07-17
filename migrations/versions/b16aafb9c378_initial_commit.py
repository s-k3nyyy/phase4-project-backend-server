"""initial commit

Revision ID: b16aafb9c378
Revises: 0899fa5d7e6b
Create Date: 2024-07-17 16:06:26.958497

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'b16aafb9c378'
down_revision = '0899fa5d7e6b'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('event', schema=None) as batch_op:
        batch_op.add_column(sa.Column('jwt_required', sa.Boolean(), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('event', schema=None) as batch_op:
        batch_op.drop_column('jwt_required')

    # ### end Alembic commands ###
