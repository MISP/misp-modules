"""Repair external tool API keys after incomplete legacy migrations.

Revision ID: 7f2a9c4d8e61
Revises: 206e0e808b0c
"""

from alembic import op
import sqlalchemy as sa


revision = '7f2a9c4d8e61'
down_revision = '206e0e808b0c'
branch_labels = None
depends_on = None


def upgrade():
    # The original migration swallowed OperationalError and could be recorded
    # as complete even when the column or its index had not been added.
    inspector = sa.inspect(op.get_bind())
    columns = {column['name'] for column in inspector.get_columns('external_tools')}
    if 'api_key' not in columns:
        op.add_column('external_tools', sa.Column('api_key', sa.String(60), nullable=True))

    indexes = {index['name'] for index in inspector.get_indexes('external_tools')}
    if 'ix_external_tools_api_key' not in indexes:
        op.create_index('ix_external_tools_api_key', 'external_tools', ['api_key'])


def downgrade():
    # This column and index belong to 206e0e808b0c. Preserve them (and API keys)
    # when returning to that revision; its downgrade owns their removal.
    pass
