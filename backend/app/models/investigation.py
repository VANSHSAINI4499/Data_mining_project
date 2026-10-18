"""Threat intel, ATT&CK, correlation, alerts, cases, feedback (DATABASE_DESIGN.md §3.4, §3.7)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Identity,
    Index,
    Integer,
    SmallInteger,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, created_at_column, updated_at_column

INDICATOR_TYPES = ("ipv4", "ipv6", "domain", "url", "sha256", "sha1", "md5", "email")
FEED_TYPES = ("manual", "csv_file", "stix_file", "taxii")
ALERT_STATUSES = ("new", "acknowledged", "in_review", "escalated", "dismissed", "closed")
CASE_STATUSES = ("open", "investigating", "closed")
DISPOSITIONS = ("confirmed_incident", "false_positive", "benign_true_positive", "inconclusive")
VERDICTS = ("true_positive", "false_positive", "benign_unusual", "needs_more_info")
EVIDENCE_TYPES = (
    "event",
    "classification_result",
    "anomaly_result",
    "indicator_match",
    "web_payload_result",
)
FEEDBACK_TARGETS = ("event", "classification_result", "anomaly_result", "indicator_match", "alert")


def _in(column: str, values: tuple[str, ...]) -> str:
    return f"{column} IN ({', '.join(repr(v) for v in values)})"


class TiFeed(Base):
    __tablename__ = "ti_feed"
    __table_args__ = (
        CheckConstraint(_in("feed_type", FEED_TYPES), name="feed_type"),
        CheckConstraint("reliability IN ('A','B','C','D','E','F')", name="reliability"),
        CheckConstraint("default_confidence BETWEEN 0 AND 100", name="default_confidence"),
    )

    feed_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    feed_key: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    feed_type: Mapped[str] = mapped_column(Text, nullable=False)
    url: Mapped[str | None] = mapped_column(Text)
    collection_id: Mapped[str | None] = mapped_column(Text)
    reliability: Mapped[str] = mapped_column(Text, nullable=False, server_default=text("'F'"))
    default_confidence: Mapped[int] = mapped_column(
        SmallInteger, nullable=False, server_default=text("50")
    )
    default_ttl_days: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default=text("90")
    )
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))
    poll_interval_minutes: Mapped[int | None] = mapped_column(Integer)
    credentials_ref: Mapped[str | None] = mapped_column(Text)
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)
    last_error_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = created_at_column()
    updated_at: Mapped[datetime] = updated_at_column()


class TiFeedRun(Base):
    __tablename__ = "ti_feed_run"

    feed_run_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    feed_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("ti_feed.feed_id"), nullable=False
    )
    job_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("job.job_id"))
    status: Mapped[str] = mapped_column(Text, nullable=False)
    source_description: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    indicators_received: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default=text("0")
    )
    indicators_created: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default=text("0")
    )
    indicators_updated: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default=text("0")
    )
    indicators_rejected: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default=text("0")
    )
    report: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )
    error: Mapped[str | None] = mapped_column(Text)


class TiIndicator(Base):
    __tablename__ = "ti_indicator"
    __table_args__ = (
        CheckConstraint(_in("indicator_type", INDICATOR_TYPES), name="indicator_type"),
        CheckConstraint("confidence BETWEEN 0 AND 100", name="confidence"),
        UniqueConstraint("feed_id", "indicator_type", "value_normalized"),
        Index(None, "indicator_type", "value_normalized"),
    )

    indicator_id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    feed_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("ti_feed.feed_id"), nullable=False
    )
    indicator_type: Mapped[str] = mapped_column(Text, nullable=False)
    value_raw: Mapped[str] = mapped_column(Text, nullable=False)
    value_normalized: Mapped[str] = mapped_column(Text, nullable=False)
    confidence: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    severity: Mapped[str | None] = mapped_column(Text)
    tlp: Mapped[str | None] = mapped_column(Text)
    description: Mapped[str | None] = mapped_column(Text)
    stix_id: Mapped[str | None] = mapped_column(Text)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    valid_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    technique_ids: Mapped[list[str]] = mapped_column(
        ARRAY(Text), nullable=False, server_default=text("'{}'::text[]")
    )
    last_feed_run_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("ti_feed_run.feed_run_id")
    )
    created_at: Mapped[datetime] = created_at_column()
    updated_at: Mapped[datetime] = updated_at_column()


class TiIndicatorVersion(Base):
    __tablename__ = "ti_indicator_version"
    __table_args__ = (UniqueConstraint("indicator_id", "version_no"),)

    version_id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    indicator_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("ti_indicator.indicator_id"), nullable=False
    )
    version_no: Mapped[int] = mapped_column(Integer, nullable=False)
    snapshot: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    changed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    feed_run_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("ti_feed_run.feed_run_id")
    )


class IndicatorMatch(Base):
    __tablename__ = "indicator_match"
    __table_args__ = (
        ForeignKeyConstraint(
            ["event_id", "event_time"],
            ["fact_security_event.event_id", "fact_security_event.event_time"],
            ondelete="CASCADE",
        ),
        UniqueConstraint("event_id", "event_time", "indicator_id", "matched_field"),
        CheckConstraint(
            "indicator_state_at_match IN ('active', 'expired', 'revoked')", name="state"
        ),
        Index(None, "indicator_id"),
        Index(None, "event_id", "event_time"),
    )

    match_id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    event_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    event_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    indicator_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("ti_indicator.indicator_id"), nullable=False
    )
    matched_field: Mapped[str] = mapped_column(Text, nullable=False)
    matched_value: Mapped[str] = mapped_column(Text, nullable=False)
    match_type: Mapped[str] = mapped_column(Text, nullable=False, server_default=text("'exact'"))
    indicator_confidence_at_match: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    indicator_state_at_match: Mapped[str] = mapped_column(Text, nullable=False)
    matcher_version: Mapped[str] = mapped_column(Text, nullable=False)
    matched_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    job_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("job.job_id"))


class AttackTechnique(Base):
    __tablename__ = "attack_technique"

    technique_id: Mapped[str] = mapped_column(Text, primary_key=True)
    stix_id: Mapped[str] = mapped_column(Text, nullable=False)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    tactics: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False)
    is_subtechnique: Mapped[bool] = mapped_column(Boolean, nullable=False)
    parent_technique_id: Mapped[str | None] = mapped_column(Text)
    attack_version: Mapped[str | None] = mapped_column(Text)
    deprecated: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    revoked: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    url: Mapped[str | None] = mapped_column(Text)
    imported_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class AttackCategoryTechnique(Base):
    __tablename__ = "attack_category_technique"
    __table_args__ = (
        CheckConstraint("mapping_confidence IN ('low', 'medium', 'high')", name="confidence"),
    )

    attack_category_id: Mapped[int] = mapped_column(
        SmallInteger, ForeignKey("dim_attack_category.attack_category_id"), primary_key=True
    )
    technique_id: Mapped[str] = mapped_column(
        Text, ForeignKey("attack_technique.technique_id"), primary_key=True
    )
    mapping_confidence: Mapped[str] = mapped_column(Text, nullable=False)
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    mapping_version: Mapped[str] = mapped_column(Text, nullable=False)


class CorrelationRule(Base):
    __tablename__ = "correlation_rule"
    __table_args__ = (
        UniqueConstraint("rule_key", "version"),
        CheckConstraint("base_severity IN ('low', 'medium', 'high', 'critical')", name="severity"),
    )

    rule_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    rule_key: Mapped[str] = mapped_column(Text, nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))
    definition: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    base_severity: Mapped[str] = mapped_column(Text, nullable=False)
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("app_user.user_id")
    )
    created_at: Mapped[datetime] = created_at_column()


class IncidentCase(Base):
    __tablename__ = "incident_case"
    __table_args__ = (
        CheckConstraint(_in("status", CASE_STATUSES), name="status"),
        CheckConstraint(
            f"disposition IS NULL OR {_in('disposition', DISPOSITIONS)}", name="disposition"
        ),
        CheckConstraint(
            "status <> 'closed' OR disposition IS NOT NULL", name="closed_needs_disposition"
        ),
        CheckConstraint("severity IN ('low', 'medium', 'high', 'critical')", name="severity"),
    )

    case_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default=text("'open'"))
    disposition: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(Text, nullable=False)
    assigned_to: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("app_user.user_id")
    )
    summary: Mapped[str | None] = mapped_column(Text)
    opened_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("app_user.user_id")
    )
    opened_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = updated_at_column()


class Alert(Base):
    """A correlation hypothesis for review, not a confirmed incident."""

    __tablename__ = "alert"
    __table_args__ = (
        CheckConstraint(_in("status", ALERT_STATUSES), name="status"),
        CheckConstraint("risk_score BETWEEN 0 AND 100", name="risk_score"),
        Index(
            "uq_alert_open_dedup_key",
            "dedup_key",
            unique=True,
            postgresql_where=text("status IN ('new', 'acknowledged', 'in_review')"),
        ),
        Index("ix_alert_status_risk", "status", text("risk_score DESC")),
        Index(None, "primary_entity_type", "primary_entity_value"),
    )

    alert_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    rule_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("correlation_rule.rule_id"), nullable=False
    )
    dedup_key: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default=text("'new'"))
    title: Mapped[str] = mapped_column(Text, nullable=False)
    primary_entity_type: Mapped[str] = mapped_column(Text, nullable=False)
    primary_entity_value: Mapped[str] = mapped_column(Text, nullable=False)
    risk_score: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    risk_breakdown: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    first_event_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_event_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    evidence_count: Mapped[int] = mapped_column(Integer, nullable=False)
    assigned_to: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("app_user.user_id")
    )
    case_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("incident_case.case_id")
    )
    related_alert_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("alert.alert_id")
    )
    dismiss_reason: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = created_at_column()
    updated_at: Mapped[datetime] = updated_at_column()


class AlertEvidence(Base):
    __tablename__ = "alert_evidence"
    __table_args__ = (CheckConstraint(_in("evidence_type", EVIDENCE_TYPES), name="evidence_type"),)

    alert_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("alert.alert_id"), primary_key=True
    )
    evidence_type: Mapped[str] = mapped_column(Text, primary_key=True)
    evidence_ref: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    event_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    step_id: Mapped[str | None] = mapped_column(Text)
    contribution: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )
    added_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class CaseAlert(Base):
    __tablename__ = "case_alert"

    case_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("incident_case.case_id"), primary_key=True
    )
    alert_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("alert.alert_id"), primary_key=True
    )
    linked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class CaseTimelineEntry(Base):
    """Append-only."""

    __tablename__ = "case_timeline_entry"
    __table_args__ = (
        CheckConstraint(
            "entry_type IN ('note', 'status_change', 'alert_linked', 'evidence')", name="entry_type"
        ),
        Index(None, "case_id", "entry_time"),
    )

    entry_id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    case_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("incident_case.case_id"), nullable=False
    )
    entry_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    entry_type: Mapped[str] = mapped_column(Text, nullable=False)
    author_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("app_user.user_id")
    )
    body: Mapped[str] = mapped_column(Text, nullable=False)
    ref: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )
    created_at: Mapped[datetime] = created_at_column()


class AnalystFeedback(Base):
    """Append-only analyst conclusions; never written into ground truth."""

    __tablename__ = "analyst_feedback"
    __table_args__ = (
        CheckConstraint(_in("target_type", FEEDBACK_TARGETS), name="target_type"),
        CheckConstraint(_in("verdict", VERDICTS), name="verdict"),
        Index(None, "target_type", "target_id"),
    )

    feedback_id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    target_type: Mapped[str] = mapped_column(Text, nullable=False)
    target_id: Mapped[str] = mapped_column(Text, nullable=False)
    verdict: Mapped[str] = mapped_column(Text, nullable=False)
    corrected_category_id: Mapped[int | None] = mapped_column(
        SmallInteger, ForeignKey("dim_attack_category.attack_category_id")
    )
    comment: Mapped[str | None] = mapped_column(Text)
    analyst_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("app_user.user_id")
    )
    created_at: Mapped[datetime] = created_at_column()
