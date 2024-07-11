"""Added tickets_remaining field to Event model

Revision ID: 51ace24762f8
Revises: 287b0ccd97f3
Create Date: 2024-07-11 16:21:33.016112

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '51ace24762f8'
down_revision = '287b0ccd97f3'
branch_labels = None
depends_on = None


def upgrade():
    # Add column with nullable=True
    op.add_column('event', sa.Column('tickets_remaining', sa.Integer(), nullable=True))


def downgrade():
    # Remove column
    op.drop_column('event', 'tickets_remaining')
