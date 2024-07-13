"""Create admin and event tables

Revision ID: 287b0ccd97f3
Revises: f5dddaffe1be
Create Date: 2024-07-11 03:29:50.983645

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '287b0ccd97f3'
down_revision = 'f5dddaffe1be'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('admin',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('username', sa.String(length=80), nullable=False),
    sa.Column('password_hash', sa.String(length=128), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('username')
    )
    op.create_table('event',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('title', sa.String(length=100), nullable=False),
    sa.Column('description', sa.Text(), nullable=False),
    sa.Column('ticket_price', sa.Float(), nullable=False),
    sa.Column('photo_url', sa.String(length=200), nullable=True),
    sa.Column('event_date', sa.DateTime(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('event')
    op.drop_table('admin')
    # ### end Alembic commands ###