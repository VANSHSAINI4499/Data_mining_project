"""ML registry and model outputs (DATABASE_DESIGN.md §3.5)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    REAL,
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Double,
    ForeignKey,
    ForeignKeyConstraint,
    Identity,
    Index,
    Integer,
    Interval,
    SmallInteger,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, created_at_column

TASKS = ("classification", "anomaly")
RUN_STATUSES = ("queued", "running", "succeeded", "failed")
MODEL_STATUSES = ("candidate", "active", "archived", "rejected")


def _in(column: str, values: tuple[str, ...]) -> str:
    return f"{column} IN ({', '.join(repr(v) for v in values)})"


class MlTrainingRun(Base):
    __tablename__ = "ml_training_run"
    __table_args__ = (
        CheckConstraint(_in("task", TASKS), name="task"),
        CheckConstraint(_in("status", RUN_STATUSES), name="status"),
        Index(None, "task", "created_at"),
    )

    run_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    task: Mapped[str] = mapped_column(Text, nullable=False)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default=text("'queued'"))
    config: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    random_seed: Mapped[int] = mapped_column(Integer, nullable=False)
    dataset_snapshot: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    feature_set_version: Mapped[str] = mapped_column(Text, nullable=False)
    label_mapping_version: Mapped[str | None] = mapped_column(Text)
    split_strategy: Mapped[str | None] = mapped_column(Text)
    metrics: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    baseline_metrics: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    confusion_matrix: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    leakage_checks: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    warnings_acknowledged: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    environment: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    job_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("job.job_id"))
    triggered_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("app_user.user_id")
    )
    created_at: Mapped[datetime] = created_at_column()
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error: Mapped[dict[str, Any] | None] = mapped_column(JSONB)


class MlModel(Base):
    __tablename__ = "ml_model"
    __table_args__ = (
        CheckConstraint(_in("task", TASKS), name="task"),
        CheckConstraint(_in("status", MODEL_STATUSES), name="status"),
        CheckConstraint("artifact_sha256 ~ '^[0-9a-f]{64}$'", name="artifact_sha256"),
        UniqueConstraint("name", "version"),
        Index(
            "uq_ml_model_active_name",
            "name",
            unique=True,
            postgresql_where=text("status = 'active'"),
        ),
    )

    model_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    task: Mapped[str] = mapped_column(Text, nullable=False)
    algorithm: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default=text("'candidate'"))
    training_run_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("ml_training_run.run_id"), nullable=False
    )
    artifact_path: Mapped[str] = mapped_column(Text, nullable=False)
    artifact_sha256: Mapped[str] = mapped_column(Text, nullable=False)
    feature_set_version: Mapped[str] = mapped_column(Text, nullable=False)
    label_mapping_version: Mapped[str | None] = mapped_column(Text)
    class_labels: Mapped[list[str] | None] = mapped_column(ARRAY(Text))
    threshold: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    created_at: Mapped[datetime] = created_at_column()
    promoted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    promoted_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("app_user.user_id")
    )
    status_note: Mapped[str | None] = mapped_column(Text)


class MlScoringRun(Base):
    __tablename__ = "ml_scoring_run"
    __table_args__ = (CheckConstraint(_in("status", RUN_STATUSES), name="status"),)

    scoring_run_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    model_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("ml_model.model_id"), nullable=False
    )
    scope: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default=text("'queued'"))
    evaluation_only: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("false")
    )
    rows_scored: Mapped[int] = mapped_column(BigInteger, nullable=False, server_default=text("0"))
    rows_skipped: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )
    job_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("job.job_id"))
    triggered_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("app_user.user_id")
    )
    created_at: Mapped[datetime] = created_at_column()
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error: Mapped[dict[str, Any] | None] = mapped_column(JSONB)


class ClassificationResult(Base):
    __tablename__ = "classification_result"
    __table_args__ = (
        ForeignKeyConstraint(
            ["event_id", "event_time"],
            ["fact_security_event.event_id", "fact_security_event.event_time"],
            ondelete="CASCADE",
        ),
        UniqueConstraint("event_id", "event_time", "model_id"),
        Index(None, "model_id", "predicted_category_id"),
        Index(None, "event_id", "event_time"),
        CheckConstraint("predicted_score >= 0 AND predicted_score <= 1", name="score"),
    )

    result_id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    event_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    event_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    model_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("ml_model.model_id"), nullable=False
    )
    scoring_run_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("ml_scoring_run.scoring_run_id"), nullable=False
    )
    predicted_category_id: Mapped[int] = mapped_column(
        SmallInteger, ForeignKey("dim_attack_category.attack_category_id"), nullable=False
    )
    predicted_score: Mapped[float] = mapped_column(REAL, nullable=False)
    class_scores: Mapped[dict[str, float]] = mapped_column(JSONB, nullable=False)
    scored_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class AnomalyResult(Base):
    """Entity-window anomaly scores (ANOMALY_DETECTION.md). Created in Phase 4."""

    __tablename__ = "anomaly_result"
    __table_args__ = (
        CheckConstraint("method IN ('isolation_forest', 'robust_zscore')", name="method"),
        CheckConstraint("entity_type IN ('host', 'account', 'src_ip')", name="entity_type"),
        UniqueConstraint("model_id", "entity_type", "entity_value", "window_start"),
        Index(None, "model_id", "is_flagged", "window_start"),
        Index(None, "entity_type", "entity_value", "window_start"),
    )

    result_id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    model_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("ml_model.model_id"), nullable=False
    )
    scoring_run_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("ml_scoring_run.scoring_run_id"), nullable=False
    )
    method: Mapped[str] = mapped_column(Text, nullable=False)
    entity_type: Mapped[str] = mapped_column(Text, nullable=False)
    entity_value: Mapped[str] = mapped_column(Text, nullable=False)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    window_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    window_size: Mapped[Any] = mapped_column(Interval, nullable=False)
    anomaly_score: Mapped[float] = mapped_column(Double, nullable=False)
    score_percentile: Mapped[float | None] = mapped_column(REAL)
    threshold: Mapped[float] = mapped_column(Double, nullable=False)
    is_flagged: Mapped[bool] = mapped_column(Boolean, nullable=False)
    feature_snapshot: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    baseline_snapshot: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    top_deviations: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, nullable=False, server_default=text("'[]'::jsonb")
    )
    scored_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
