"""ML registry and model outputs (Phase 3).

Creates ml_training_run, ml_model (one active model per name), ml_scoring_run,
classification_result (Phase 3) and anomaly_result (used from Phase 4) - DATABASE_DESIGN.md §3.5.

Revision ID: f0d5d5612edb
Revises: 73dd23efe0d5
Create Date: 2026-10-14 18:32:42.853369+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "f0d5d5612edb"
down_revision: str | None = "73dd23efe0d5"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "ml_training_run",
        sa.Column("run_id", sa.UUID(), nullable=False),
        sa.Column("task", sa.Text(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), server_default=sa.text("'queued'"), nullable=False),
        sa.Column("config", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("random_seed", sa.Integer(), nullable=False),
        sa.Column("dataset_snapshot", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("feature_set_version", sa.Text(), nullable=False),
        sa.Column("label_mapping_version", sa.Text(), nullable=True),
        sa.Column("split_strategy", sa.Text(), nullable=True),
        sa.Column("metrics", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("baseline_metrics", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("confusion_matrix", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("leakage_checks", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("warnings_acknowledged", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("environment", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("job_id", sa.UUID(), nullable=True),
        sa.Column("triggered_by", sa.UUID(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.CheckConstraint(
            "status IN ('queued', 'running', 'succeeded', 'failed')",
            name=op.f("ck_ml_training_run_status"),
        ),
        sa.CheckConstraint(
            "task IN ('classification', 'anomaly')", name=op.f("ck_ml_training_run_task")
        ),
        sa.ForeignKeyConstraint(
            ["job_id"], ["job.job_id"], name=op.f("fk_ml_training_run_job_id_job")
        ),
        sa.ForeignKeyConstraint(
            ["triggered_by"],
            ["app_user.user_id"],
            name=op.f("fk_ml_training_run_triggered_by_app_user"),
        ),
        sa.PrimaryKeyConstraint("run_id", name=op.f("pk_ml_training_run")),
    )
    op.create_index(
        op.f("ix_ml_training_run_task_created_at"),
        "ml_training_run",
        ["task", "created_at"],
        unique=False,
    )
    op.create_table(
        "ml_model",
        sa.Column("model_id", sa.UUID(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("task", sa.Text(), nullable=False),
        sa.Column("algorithm", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), server_default=sa.text("'candidate'"), nullable=False),
        sa.Column("training_run_id", sa.UUID(), nullable=False),
        sa.Column("artifact_path", sa.Text(), nullable=False),
        sa.Column("artifact_sha256", sa.Text(), nullable=False),
        sa.Column("feature_set_version", sa.Text(), nullable=False),
        sa.Column("label_mapping_version", sa.Text(), nullable=True),
        sa.Column("class_labels", postgresql.ARRAY(sa.Text()), nullable=True),
        sa.Column("threshold", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("promoted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("promoted_by", sa.UUID(), nullable=True),
        sa.Column("status_note", sa.Text(), nullable=True),
        sa.CheckConstraint(
            "artifact_sha256 ~ '^[0-9a-f]{64}$'", name=op.f("ck_ml_model_artifact_sha256")
        ),
        sa.CheckConstraint(
            "status IN ('candidate', 'active', 'archived', 'rejected')",
            name=op.f("ck_ml_model_status"),
        ),
        sa.CheckConstraint("task IN ('classification', 'anomaly')", name=op.f("ck_ml_model_task")),
        sa.ForeignKeyConstraint(
            ["promoted_by"], ["app_user.user_id"], name=op.f("fk_ml_model_promoted_by_app_user")
        ),
        sa.ForeignKeyConstraint(
            ["training_run_id"],
            ["ml_training_run.run_id"],
            name=op.f("fk_ml_model_training_run_id_ml_training_run"),
        ),
        sa.PrimaryKeyConstraint("model_id", name=op.f("pk_ml_model")),
        sa.UniqueConstraint("name", "version", name=op.f("uq_ml_model_name_version")),
    )
    op.create_index(
        "uq_ml_model_active_name",
        "ml_model",
        ["name"],
        unique=True,
        postgresql_where=sa.text("status = 'active'"),
    )
    op.create_table(
        "ml_scoring_run",
        sa.Column("scoring_run_id", sa.UUID(), nullable=False),
        sa.Column("model_id", sa.UUID(), nullable=False),
        sa.Column("scope", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("status", sa.Text(), server_default=sa.text("'queued'"), nullable=False),
        sa.Column("evaluation_only", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("rows_scored", sa.BigInteger(), server_default=sa.text("0"), nullable=False),
        sa.Column(
            "rows_skipped",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("job_id", sa.UUID(), nullable=True),
        sa.Column("triggered_by", sa.UUID(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.CheckConstraint(
            "status IN ('queued', 'running', 'succeeded', 'failed')",
            name=op.f("ck_ml_scoring_run_status"),
        ),
        sa.ForeignKeyConstraint(
            ["job_id"], ["job.job_id"], name=op.f("fk_ml_scoring_run_job_id_job")
        ),
        sa.ForeignKeyConstraint(
            ["model_id"], ["ml_model.model_id"], name=op.f("fk_ml_scoring_run_model_id_ml_model")
        ),
        sa.ForeignKeyConstraint(
            ["triggered_by"],
            ["app_user.user_id"],
            name=op.f("fk_ml_scoring_run_triggered_by_app_user"),
        ),
        sa.PrimaryKeyConstraint("scoring_run_id", name=op.f("pk_ml_scoring_run")),
    )
    op.create_table(
        "anomaly_result",
        sa.Column("result_id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("model_id", sa.UUID(), nullable=False),
        sa.Column("scoring_run_id", sa.UUID(), nullable=False),
        sa.Column("method", sa.Text(), nullable=False),
        sa.Column("entity_type", sa.Text(), nullable=False),
        sa.Column("entity_value", sa.Text(), nullable=False),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_size", sa.Interval(), nullable=False),
        sa.Column("anomaly_score", sa.Double(), nullable=False),
        sa.Column("score_percentile", sa.REAL(), nullable=True),
        sa.Column("threshold", sa.Double(), nullable=False),
        sa.Column("is_flagged", sa.Boolean(), nullable=False),
        sa.Column("feature_snapshot", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("baseline_snapshot", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column(
            "top_deviations",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "scored_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
        ),
        sa.CheckConstraint(
            "entity_type IN ('host', 'account', 'src_ip')",
            name=op.f("ck_anomaly_result_entity_type"),
        ),
        sa.CheckConstraint(
            "method IN ('isolation_forest', 'robust_zscore')", name=op.f("ck_anomaly_result_method")
        ),
        sa.ForeignKeyConstraint(
            ["model_id"], ["ml_model.model_id"], name=op.f("fk_anomaly_result_model_id_ml_model")
        ),
        sa.ForeignKeyConstraint(
            ["scoring_run_id"],
            ["ml_scoring_run.scoring_run_id"],
            name=op.f("fk_anomaly_result_scoring_run_id_ml_scoring_run"),
        ),
        sa.PrimaryKeyConstraint("result_id", name=op.f("pk_anomaly_result")),
        sa.UniqueConstraint(
            "model_id",
            "entity_type",
            "entity_value",
            "window_start",
            name=op.f("uq_anomaly_result_model_id_entity_type_entity_value_window_start"),
        ),
    )
    op.create_index(
        op.f("ix_anomaly_result_entity_type_entity_value_window_start"),
        "anomaly_result",
        ["entity_type", "entity_value", "window_start"],
        unique=False,
    )
    op.create_index(
        op.f("ix_anomaly_result_model_id_is_flagged_window_start"),
        "anomaly_result",
        ["model_id", "is_flagged", "window_start"],
        unique=False,
    )
    op.create_table(
        "classification_result",
        sa.Column("result_id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("event_id", sa.BigInteger(), nullable=False),
        sa.Column("event_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("model_id", sa.UUID(), nullable=False),
        sa.Column("scoring_run_id", sa.UUID(), nullable=False),
        sa.Column("predicted_category_id", sa.SmallInteger(), nullable=False),
        sa.Column("predicted_score", sa.REAL(), nullable=False),
        sa.Column("class_scores", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "scored_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
        ),
        sa.CheckConstraint(
            "predicted_score >= 0 AND predicted_score <= 1",
            name=op.f("ck_classification_result_score"),
        ),
        sa.ForeignKeyConstraint(
            ["event_id", "event_time"],
            ["fact_security_event.event_id", "fact_security_event.event_time"],
            name=op.f("fk_classification_result_event_id_fact_security_event"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["model_id"],
            ["ml_model.model_id"],
            name=op.f("fk_classification_result_model_id_ml_model"),
        ),
        sa.ForeignKeyConstraint(
            ["predicted_category_id"],
            ["dim_attack_category.attack_category_id"],
            name=op.f("fk_classification_result_predicted_category_id_dim_attack_category"),
        ),
        sa.ForeignKeyConstraint(
            ["scoring_run_id"],
            ["ml_scoring_run.scoring_run_id"],
            name=op.f("fk_classification_result_scoring_run_id_ml_scoring_run"),
        ),
        sa.PrimaryKeyConstraint("result_id", name=op.f("pk_classification_result")),
        sa.UniqueConstraint(
            "event_id",
            "event_time",
            "model_id",
            name=op.f("uq_classification_result_event_id_event_time_model_id"),
        ),
    )
    op.create_index(
        op.f("ix_classification_result_event_id_event_time"),
        "classification_result",
        ["event_id", "event_time"],
        unique=False,
    )
    op.create_index(
        op.f("ix_classification_result_model_id_predicted_category_id"),
        "classification_result",
        ["model_id", "predicted_category_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        op.f("ix_classification_result_model_id_predicted_category_id"),
        table_name="classification_result",
    )
    op.drop_index(
        op.f("ix_classification_result_event_id_event_time"), table_name="classification_result"
    )
    op.drop_table("classification_result")
    op.drop_index(
        op.f("ix_anomaly_result_model_id_is_flagged_window_start"), table_name="anomaly_result"
    )
    op.drop_index(
        op.f("ix_anomaly_result_entity_type_entity_value_window_start"), table_name="anomaly_result"
    )
    op.drop_table("anomaly_result")
    op.drop_table("ml_scoring_run")
    op.drop_index(
        "uq_ml_model_active_name",
        table_name="ml_model",
        postgresql_where=sa.text("status = 'active'"),
    )
    op.drop_table("ml_model")
    op.drop_index(op.f("ix_ml_training_run_task_created_at"), table_name="ml_training_run")
    op.drop_table("ml_training_run")
