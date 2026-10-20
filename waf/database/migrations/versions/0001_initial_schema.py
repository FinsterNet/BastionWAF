"""Initial schema creation for Bastion WAF

Revision ID: 0001
Revises: None
Create Date: 2026-10-20
"""

from alembic import op
import sqlalchemy as sa

revision = '0001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. Events table
    op.create_table(
        'events',
        sa.Column('id', sa.BigInteger(), sa.Identity(always=False), primary_key=True),
        sa.Column('timestamp', sa.String(length=64)),
        sa.Column('client_ip', sa.String(length=64)),
        sa.Column('method', sa.String(length=16)),
        sa.Column('path', sa.String(length=2048)),
        sa.Column('blocked', sa.SmallInteger(), server_default='0'),
        sa.Column('rule_id', sa.String(length=64)),
        sa.Column('reason', sa.String(length=255)),
        sa.Column('action', sa.String(length=64)),
        sa.Column('payload_snippet', sa.String(length=512), server_default=''),
        sa.Column('rule_score', sa.Float(), server_default='0.0'),
        sa.Column('semantic_score', sa.Float(), server_default='0.0'),
        sa.Column('total_score', sa.Float(), server_default='0.0'),
        sa.Column('raw_payload', sa.Text(), server_default=''),
        sa.Column('normalized_payload', sa.Text(), server_default=''),
    )
    op.create_index('idx_events_timestamp', 'events', ['timestamp'])
    op.create_index('idx_events_client_ip', 'events', ['client_ip'])
    op.create_index('idx_events_blocked', 'events', ['blocked'])

    # 2. WAF Rules
    op.create_table(
        'waf_rules',
        sa.Column('rule_id', sa.String(length=64), primary_key=True),
        sa.Column('rule_name', sa.String(length=255)),
        sa.Column('category', sa.String(length=64)),
        sa.Column('enabled', sa.SmallInteger(), server_default='1'),
    )

    # 3. Protected Sites
    op.create_table(
        'protected_sites',
        sa.Column('id', sa.BigInteger(), sa.Identity(always=False), primary_key=True),
        sa.Column('domain', sa.String(length=255), unique=True),
        sa.Column('upstream', sa.String(length=255)),
        sa.Column('ssl_status', sa.String(length=64), server_default='Active'),
        sa.Column('defense_mode', sa.SmallInteger(), server_default='1'),
    )

    # 4. Users
    op.create_table(
        'users',
        sa.Column('id', sa.BigInteger(), sa.Identity(always=False), primary_key=True),
        sa.Column('email', sa.String(length=255), unique=True, nullable=False),
        sa.Column('password_hash', sa.String(length=255), nullable=False),
        sa.Column('totp_secret_encrypted', sa.Text(), nullable=True),
        sa.Column('totp_enabled', sa.SmallInteger(), server_default='0'),
        sa.Column('failed_attempts', sa.Integer(), server_default='0'),
        sa.Column('locked_until', sa.Float(), server_default='0.0'),
        sa.Column('created_at', sa.String(length=64)),
    )
    op.create_index('idx_users_email', 'users', ['email'])

    # 5. Sessions
    op.create_table(
        'sessions',
        sa.Column('id', sa.BigInteger(), sa.Identity(always=False), primary_key=True),
        sa.Column('user_id', sa.BigInteger(), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
        sa.Column('token_hash', sa.String(length=128), unique=True, nullable=False),
        sa.Column('created_at', sa.Float(), nullable=False),
        sa.Column('last_seen_at', sa.Float(), nullable=False),
        sa.Column('expires_at', sa.Float(), nullable=False),
        sa.Column('ip', sa.String(length=64)),
        sa.Column('user_agent', sa.String(length=255)),
    )
    op.create_index('idx_sessions_token_hash', 'sessions', ['token_hash'])
    op.create_index('idx_sessions_user_id', 'sessions', ['user_id'])

    # 6. Password Resets
    op.create_table(
        'password_resets',
        sa.Column('id', sa.BigInteger(), sa.Identity(always=False), primary_key=True),
        sa.Column('user_id', sa.BigInteger(), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
        sa.Column('token_hash', sa.String(length=128), unique=True, nullable=False),
        sa.Column('expires_at', sa.Float(), nullable=False),
        sa.Column('used_at', sa.Float(), nullable=True),
    )

    # 7. Recovery Codes
    op.create_table(
        'recovery_codes',
        sa.Column('id', sa.BigInteger(), sa.Identity(always=False), primary_key=True),
        sa.Column('user_id', sa.BigInteger(), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
        sa.Column('code_hash', sa.String(length=128), nullable=False),
        sa.Column('used_at', sa.Float(), nullable=True),
    )

    # 8. Login Attempts
    op.create_table(
        'login_attempts',
        sa.Column('id', sa.BigInteger(), sa.Identity(always=False), primary_key=True),
        sa.Column('email', sa.String(length=255)),
        sa.Column('ip', sa.String(length=64)),
        sa.Column('success', sa.SmallInteger(), server_default='0'),
        sa.Column('created_at', sa.String(length=64)),
    )
    op.create_index('idx_login_attempts_ip', 'login_attempts', ['ip', 'created_at'])

    # 9. Audit Actions
    op.create_table(
        'audit_actions',
        sa.Column('id', sa.BigInteger(), sa.Identity(always=False), primary_key=True),
        sa.Column('user_id', sa.BigInteger(), nullable=True),
        sa.Column('email', sa.String(length=255)),
        sa.Column('action', sa.String(length=64)),
        sa.Column('details', sa.Text()),
        sa.Column('ip', sa.String(length=64)),
        sa.Column('timestamp', sa.String(length=64)),
    )


def downgrade() -> None:
    op.drop_table('audit_actions')
    op.drop_table('login_attempts')
    op.drop_table('recovery_codes')
    op.drop_table('password_resets')
    op.drop_table('sessions')
    op.drop_table('users')
    op.drop_table('protected_sites')
    op.drop_table('waf_rules')
    op.drop_table('events')
