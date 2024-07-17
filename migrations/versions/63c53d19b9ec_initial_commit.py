"""initial commit

Revision ID: 63c53d19b9ec
Revises: dbff4fd4f8ce
Create Date: 2024-07-17 08:47:58.349994

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '63c53d19b9ec'
down_revision = 'dbff4fd4f8ce'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('event',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('title', sa.String(length=100), nullable=False),
    sa.Column('description', sa.Text(), nullable=False),
    sa.Column('ticket_price', sa.Float(), nullable=False),
    sa.Column('photo_url', sa.String(length=255), nullable=True),
    sa.Column('event_date', sa.DateTime(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('user_event',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('event_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['event_id'], ['event.id'], ),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.drop_table('events')
    with op.batch_alter_table('admin', schema=None) as batch_op:
        batch_op.alter_column('username',
               existing_type=sa.VARCHAR(length=80),
               type_=sa.String(length=50),
               existing_nullable=False)
        batch_op.alter_column('password_hash',
               existing_type=sa.VARCHAR(length=128),
               type_=sa.String(length=255),
               existing_nullable=False)
        batch_op.drop_column('created_at')

    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_column('jwt_key')

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('jwt_key', sa.VARCHAR(length=64), nullable=False))

    with op.batch_alter_table('admin', schema=None) as batch_op:
        batch_op.add_column(sa.Column('created_at', sa.DATETIME(), nullable=True))
        batch_op.alter_column('password_hash',
               existing_type=sa.String(length=255),
               type_=sa.VARCHAR(length=128),
               existing_nullable=False)
        batch_op.alter_column('username',
               existing_type=sa.String(length=50),
               type_=sa.VARCHAR(length=80),
               existing_nullable=False)

    op.create_table('events',
    sa.Column('id', sa.INTEGER(), nullable=False),
    sa.Column('title', sa.VARCHAR(length=100), nullable=False),
    sa.Column('description', sa.TEXT(), nullable=False),
    sa.Column('ticket_price', sa.FLOAT(), nullable=False),
    sa.Column('photo_url', sa.VARCHAR(length=200), nullable=True),
    sa.Column('event_date', sa.DATETIME(), nullable=False),
    sa.Column('tickets_remaining', sa.INTEGER(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.drop_table('user_event')
    op.drop_table('event')
    # ### end Alembic commands ###