"""add enrichments table and analysis extensions

Revision ID: a1b2c3d4e5f6
Revises: c034ee325edf
Create Date: 2026-04-09 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = 'a1b2c3d4e5f6'
down_revision: Union[str, None] = 'c034ee325edf'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table('enrichments',
        sa.Column('id', sa.UUID(), server_default=sa.text('gen_random_uuid()'), nullable=False),
        sa.Column('alert_id', sa.UUID(), nullable=False),
        sa.Column('host', sa.String(length=255), nullable=False),
        sa.Column('data', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('queries_run', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('queries_failed', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['alert_id'], ['alerts.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )

    op.add_column('analyses', sa.Column('criticality_score', sa.Integer(), nullable=True))
    op.add_column('analyses', sa.Column('criticality_level', sa.String(length=50), nullable=True))
    op.add_column('analyses', sa.Column('criticality_justification', sa.Text(), nullable=True))
    op.add_column('analyses', sa.Column('response_action', sa.String(length=50), nullable=True))
    op.add_column('analyses', sa.Column('response_urgency', sa.String(length=50), nullable=True))
    op.add_column('analyses', sa.Column('analysis_mode', sa.String(length=50), nullable=True))


def downgrade() -> None:
    op.drop_column('analyses', 'analysis_mode')
    op.drop_column('analyses', 'response_urgency')
    op.drop_column('analyses', 'response_action')
    op.drop_column('analyses', 'criticality_justification')
    op.drop_column('analyses', 'criticality_level')
    op.drop_column('analyses', 'criticality_score')
    op.drop_table('enrichments')
