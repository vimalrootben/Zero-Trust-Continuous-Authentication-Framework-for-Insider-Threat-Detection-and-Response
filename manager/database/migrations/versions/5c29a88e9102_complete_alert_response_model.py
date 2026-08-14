"""complete_alert_response_model

Revision ID: 5c29a88e9102
Revises: 4b14f115e431
Create Date: 2026-08-13 16:45:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '5c29a88e9102'
down_revision: Union[str, None] = '4b14f115e431'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    # Add new metadata and tracking columns to alerts table
    with op.batch_alter_table('alerts') as batch_op:
        batch_op.add_column(sa.Column('alert_id', sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column('policy_id', sa.Uuid(), nullable=True))
        batch_op.add_column(sa.Column('correlation_id', sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column('risk_score', sa.Float(), nullable=False, server_default='0.0'))
        batch_op.add_column(sa.Column('risk_level', sa.String(length=32), nullable=True))
        batch_op.add_column(sa.Column('source', sa.String(length=64), nullable=True, server_default='endpoint_telemetry'))
        batch_op.add_column(sa.Column('event_type', sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column('process_name', sa.String(length=255), nullable=True))
        batch_op.add_column(sa.Column('process_id', sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column('file_path', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('remote_ip', sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column('remote_port', sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column('username', sa.String(length=128), nullable=True))
        batch_op.add_column(sa.Column('mitre_tactic', sa.String(length=128), nullable=True))
        batch_op.add_column(sa.Column('detected_at', sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column('response_status', sa.String(length=32), nullable=True))
        batch_op.add_column(sa.Column('response_action', sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column('response_requested_at', sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column('response_started_at', sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column('response_completed_at', sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column('response_result', sa.JSON(), nullable=True))
        batch_op.add_column(sa.Column('response_error', sa.Text(), nullable=True))

        batch_op.create_foreign_key('fk_alerts_policy_id', 'policies', ['policy_id'], ['id'], ondelete='SET NULL')
        batch_op.create_index('idx_alerts_alert_id', ['alert_id'])
        batch_op.create_index('idx_alerts_correlation_id', ['correlation_id'])
        batch_op.create_index('idx_alerts_response_status', ['response_status'])

    # Create alert_responses table
    op.create_table(
        'alert_responses',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('alert_id', sa.Uuid(), nullable=False),
        sa.Column('agent_id', sa.Uuid(), nullable=False),
        sa.Column('action', sa.String(length=64), nullable=False),
        sa.Column(
            'status',
            sa.Enum(
                'PENDING', 'AUTHORIZED', 'DISPATCHED', 'EXECUTING', 'SUCCESS', 'FAILED', 'TIMEOUT', 'CANCELLED', 'REJECTED',
                name='alert_response_status_type'
            ),
            nullable=False
        ),
        sa.Column('requested_by', sa.Uuid(), nullable=True),
        sa.Column('authorized_by', sa.Uuid(), nullable=True),
        sa.Column('command_id', sa.Uuid(), nullable=True),
        sa.Column('correlation_id', sa.String(length=64), nullable=True),
        sa.Column('requested_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('result_json', sa.JSON(), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['alert_id'], ['alerts.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['agent_id'], ['agents.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['requested_by'], ['users.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['authorized_by'], ['users.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['command_id'], ['commands.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('idx_alert_responses_alert_id', 'alert_responses', ['alert_id'])
    op.create_index('idx_alert_responses_agent_id', 'alert_responses', ['agent_id'])
    op.create_index('idx_alert_responses_action', 'alert_responses', ['action'])
    op.create_index('idx_alert_responses_status', 'alert_responses', ['status'])
    op.create_index('idx_alert_responses_correlation_id', 'alert_responses', ['correlation_id'])
    op.create_index('idx_alert_responses_alert_status', 'alert_responses', ['alert_id', 'status'])

def downgrade() -> None:
    op.drop_table('alert_responses')
    with op.batch_alter_table('alerts') as batch_op:
        batch_op.drop_constraint('fk_alerts_policy_id', type_='foreignkey')
        batch_op.drop_index('idx_alerts_response_status')
        batch_op.drop_index('idx_alerts_correlation_id')
        batch_op.drop_index('idx_alerts_alert_id')
        batch_op.drop_column('response_error')
        batch_op.drop_column('response_result')
        batch_op.drop_column('response_completed_at')
        batch_op.drop_column('response_started_at')
        batch_op.drop_column('response_requested_at')
        batch_op.drop_column('response_action')
        batch_op.drop_column('response_status')
        batch_op.drop_column('detected_at')
        batch_op.drop_column('mitre_tactic')
        batch_op.drop_column('username')
        batch_op.drop_column('remote_port')
        batch_op.drop_column('remote_ip')
        batch_op.drop_column('file_path')
        batch_op.drop_column('process_id')
        batch_op.drop_column('process_name')
        batch_op.drop_column('event_type')
        batch_op.drop_column('source')
        batch_op.drop_column('risk_level')
        batch_op.drop_column('risk_score')
        batch_op.drop_column('correlation_id')
        batch_op.drop_column('policy_id')
        batch_op.drop_column('alert_id')
