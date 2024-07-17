"""initial commit

Revision ID: 0899fa5d7e6b
Revises: 63c53d19b9ec
Create Date: 2024-07-17 08:56:37.885918

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '0899fa5d7e6b'
down_revision = '63c53d19b9ec'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('event', schema=None) as batch_op:
        batch_op.add_column(sa.Column('tickets_remaining', sa.Integer(), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('event', schema=None) as batch_op:
        batch_op.drop_column('tickets_remaining')

    # ### end Alembic commands ###
