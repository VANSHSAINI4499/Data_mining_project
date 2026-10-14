"""Baseline: operations/security tables and the date dimension.

Creates app_user, auth_session, audit_log, job (DATABASE_DESIGN.md §3.6) and dim_date (§3.2),
and populates dim_date for 2000-01-01 .. 2040-12-31.

Revision ID: 3f9a2c7d1b04
Revises:
Create Date: 2026-10-14 12:00:00+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "3f9a2c7d1b04"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TSTZ = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.create_table(
        "app_user",
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("username", sa.Text(), nullable=False),
        sa.Column("password_hash", sa.Text(), nullable=False),
        sa.Column("role", sa.Text(), nullable=False),
        sa.Column("is_active", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("failed_login_count", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("locked_until", TSTZ, nullable=True),
        sa.Column("last_login_at", TSTZ, nullable=True),
        sa.Column("created_at", TSTZ, server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", TSTZ, server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("role IN ('viewer', 'analyst', 'admin')", name=op.f("ck_app_user_role")),
        sa.CheckConstraint(
            "username = lower(username)", name=op.f("ck_app_user_username_lowercase")
        ),
        sa.PrimaryKeyConstraint("user_id", name=op.f("pk_app_user")),
        sa.UniqueConstraint("username", name=op.f("uq_app_user_username")),
    )

    op.create_table(
        "auth_session",
        sa.Column("session_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("token_hash", sa.Text(), nullable=False),
        sa.Column("csrf_token_hash", sa.Text(), nullable=False),
        sa.Column("created_at", TSTZ, server_default=sa.func.now(), nullable=False),
        sa.Column("expires_at", TSTZ, nullable=False),
        sa.Column("last_seen_at", TSTZ, nullable=False),
        sa.Column("revoked_at", TSTZ, nullable=True),
        sa.Column("ip_address", postgresql.INET(), nullable=True),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["app_user.user_id"],
            name=op.f("fk_auth_session_user_id_app_user"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("session_id", name=op.f("pk_auth_session")),
        sa.UniqueConstraint("token_hash", name=op.f("uq_auth_session_token_hash")),
    )
    op.create_index(op.f("ix_auth_session_user_id"), "auth_session", ["user_id"])

    op.create_table(
        "audit_log",
        sa.Column("audit_id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("occurred_at", TSTZ, server_default=sa.func.now(), nullable=False),
        sa.Column("actor_type", sa.Text(), nullable=False),
        sa.Column("actor_user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("actor_label", sa.Text(), nullable=True),
        sa.Column("action", sa.Text(), nullable=False),
        sa.Column("target_type", sa.Text(), nullable=True),
        sa.Column("target_id", sa.Text(), nullable=True),
        sa.Column("outcome", sa.Text(), nullable=False),
        sa.Column("request_id", sa.Text(), nullable=True),
        sa.Column("ip_address", postgresql.INET(), nullable=True),
        sa.Column(
            "details", postgresql.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False
        ),
        sa.CheckConstraint(
            "actor_type IN ('user', 'system', 'cli')", name=op.f("ck_audit_log_actor_type")
        ),
        sa.CheckConstraint(
            "outcome IN ('success', 'denied', 'error')", name=op.f("ck_audit_log_outcome")
        ),
        sa.ForeignKeyConstraint(
            ["actor_user_id"],
            ["app_user.user_id"],
            name=op.f("fk_audit_log_actor_user_id_app_user"),
        ),
        sa.PrimaryKeyConstraint("audit_id", name=op.f("pk_audit_log")),
    )
    op.create_index("ix_audit_log_occurred_at", "audit_log", [sa.text("occurred_at DESC")])
    op.create_index(
        op.f("ix_audit_log_actor_user_id_occurred_at"),
        "audit_log",
        ["actor_user_id", "occurred_at"],
    )
    op.create_index(
        op.f("ix_audit_log_target_type_target_id"), "audit_log", ["target_type", "target_id"]
    )

    op.create_table(
        "job",
        sa.Column("job_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("job_type", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), server_default=sa.text("'queued'"), nullable=False),
        sa.Column(
            "params", postgresql.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False
        ),
        sa.Column("progress", postgresql.JSONB(), nullable=True),
        sa.Column("result", postgresql.JSONB(), nullable=True),
        sa.Column("error", postgresql.JSONB(), nullable=True),
        sa.Column("attempts", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("max_attempts", sa.Integer(), server_default=sa.text("3"), nullable=False),
        sa.Column("run_after", TSTZ, server_default=sa.func.now(), nullable=False),
        sa.Column("heartbeat_at", TSTZ, nullable=True),
        sa.Column(
            "cancel_requested", sa.Boolean(), server_default=sa.text("false"), nullable=False
        ),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("created_at", TSTZ, server_default=sa.func.now(), nullable=False),
        sa.Column("started_at", TSTZ, nullable=True),
        sa.Column("finished_at", TSTZ, nullable=True),
        sa.Column("updated_at", TSTZ, server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint(
            "status IN ('queued', 'running', 'succeeded', 'failed', 'cancelled')",
            name=op.f("ck_job_status"),
        ),
        sa.CheckConstraint("attempts >= 0 AND max_attempts >= 1", name=op.f("ck_job_attempts")),
        sa.ForeignKeyConstraint(
            ["created_by"], ["app_user.user_id"], name=op.f("fk_job_created_by_app_user")
        ),
        sa.PrimaryKeyConstraint("job_id", name=op.f("pk_job")),
    )
    op.create_index(
        op.f("ix_job_status_run_after_created_at"), "job", ["status", "run_after", "created_at"]
    )
    op.create_index("ix_job_created_at", "job", [sa.text("created_at DESC")])

    op.create_table(
        "dim_date",
        sa.Column("date_key", sa.Integer(), autoincrement=False, nullable=False),
        sa.Column("calendar_date", sa.Date(), nullable=False),
        sa.Column("year", sa.SmallInteger(), nullable=False),
        sa.Column("quarter", sa.SmallInteger(), nullable=False),
        sa.Column("month", sa.SmallInteger(), nullable=False),
        sa.Column("day_of_month", sa.SmallInteger(), nullable=False),
        sa.Column("iso_week", sa.SmallInteger(), nullable=False),
        sa.Column("day_of_week", sa.SmallInteger(), nullable=False),
        sa.Column("is_weekend", sa.Boolean(), nullable=False),
        sa.PrimaryKeyConstraint("date_key", name=op.f("pk_dim_date")),
        sa.UniqueConstraint("calendar_date", name=op.f("uq_dim_date_calendar_date")),
    )
    op.execute(
        """
        INSERT INTO dim_date (date_key, calendar_date, year, quarter, month, day_of_month,
                              iso_week, day_of_week, is_weekend)
        SELECT to_char(d, 'YYYYMMDD')::int, d::date,
               extract(year FROM d)::smallint, extract(quarter FROM d)::smallint,
               extract(month FROM d)::smallint, extract(day FROM d)::smallint,
               extract(week FROM d)::smallint, extract(isodow FROM d)::smallint,
               extract(isodow FROM d) IN (6, 7)
        FROM generate_series(DATE '2000-01-01', DATE '2040-12-31', INTERVAL '1 day') AS d
        """
    )


def downgrade() -> None:
    op.drop_table("dim_date")
    op.drop_index("ix_job_created_at", table_name="job")
    op.drop_index(op.f("ix_job_status_run_after_created_at"), table_name="job")
    op.drop_table("job")
    op.drop_index(op.f("ix_audit_log_target_type_target_id"), table_name="audit_log")
    op.drop_index(op.f("ix_audit_log_actor_user_id_occurred_at"), table_name="audit_log")
    op.drop_index("ix_audit_log_occurred_at", table_name="audit_log")
    op.drop_table("audit_log")
    op.drop_index(op.f("ix_auth_session_user_id"), table_name="auth_session")
    op.drop_table("auth_session")
    op.drop_table("app_user")
