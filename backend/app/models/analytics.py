"""Phase 8 tables: incremental-processing watermarks, drift reports, pattern mining runs."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, CheckConstraint, DateTime, ForeignKey, Index, Text, func, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, created_at_column

DRIFT_STATUSES = ("ok", "warning", "insufficient_data")


class ProcessingWatermark(Base):
    """How far a downstream consumer has processed ingested data (ARCHITECTURE.md §7)."""

    __tablename__ = "processing_watermark"

    consumer: Mapped[str] = mapped_column(Text, primary_key=True)
    last_ingested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_event_id: Mapped[int | None] = mapped_column(BigInteger)
    details: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class DriftReport(Base):
    """Informational drift check for one model; never triggers retraining."""

    __tablename__ = "drift_report"
    __table_args__ = (
        CheckConstraint(f"status IN ({', '.join(repr(s) for s in DRIFT_STATUSES)})", name="status"),
        Index(None, "model_id", "created_at"),
    )

    report_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    model_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("ml_model.model_id"), nullable=False
    )
    period_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    period_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False)
    metrics: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    warnings: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, server_default=text("'[]'::jsonb")
    )
    created_at: Mapped[datetime] = created_at_column()


class PatternMiningRun(Base):
    """Sequential pattern mining output: candidate rules for human review only."""

    __tablename__ = "pattern_mining_run"

    run_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    entity_type: Mapped[str] = mapped_column(Text, nullable=False)
    period_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    period_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    params: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    stats: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    candidates: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = created_at_column()
