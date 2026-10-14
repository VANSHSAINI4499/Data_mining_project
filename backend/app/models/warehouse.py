"""Raw ingestion, dimensions, facts, and data quality (DATABASE_DESIGN.md §3.1-§3.3, §3.6).

Field semantics are defined in DATA_DICTIONARY.md. ``fact_security_event`` is range-partitioned
by month on ``event_time``; partitions are created by the ``ensure_event_partitions`` SQL
function (see the migration), never by application DDL.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from decimal import Decimal
from typing import Any

from sqlalchemy import (
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
    Numeric,
    Sequence,
    SmallInteger,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import INET, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, created_at_column, updated_at_column

SOURCE_TYPES = ("dataset", "network_sensor", "ids", "auth", "endpoint", "ti_feed", "other")
RELIABILITY = ("A", "B", "C", "D", "E", "F")
CRITICALITY = ("low", "medium", "high", "critical", "unknown")
BATCH_STATUSES = (
    "pending",
    "processing",
    "completed",
    "completed_with_errors",
    "failed",
    "duplicate",
)
EVENT_TYPES = (
    "network_flow",
    "ids_alert",
    "auth",
    "endpoint_process",
    "endpoint_file",
    "endpoint_network",
    "dns",
    "http",
    "other",
)
TIME_QUALITY = ("exact", "second", "assumed")
MAPPING_STATUS = ("mapped", "unmapped", "ambiguous")
DQ_STATUSES = ("pass", "warn", "fail")

event_id_seq = Sequence("fact_security_event_event_id_seq", metadata=Base.metadata)


def _in(column: str, values: tuple[str, ...]) -> str:
    return f"{column} IN ({', '.join(repr(v) for v in values)})"


# --- dimensions ------------------------------------------------------------------------------


class DimSource(Base):
    __tablename__ = "dim_source"
    __table_args__ = (
        CheckConstraint(_in("source_type", SOURCE_TYPES), name="source_type"),
        CheckConstraint(_in("reliability", RELIABILITY), name="reliability"),
        CheckConstraint("source_key ~ '^[a-z0-9][a-z0-9._-]{1,63}$'", name="source_key_format"),
    )

    source_id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    source_key: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    source_type: Mapped[str] = mapped_column(Text, nullable=False)
    default_adapter: Mapped[str | None] = mapped_column(Text)
    # NULL means "never configured": adapters with naive local timestamps refuse to run.
    default_timezone: Mapped[str | None] = mapped_column(Text)
    reliability: Mapped[str] = mapped_column(Text, nullable=False, server_default=text("'F'"))
    description: Mapped[str | None] = mapped_column(Text)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))
    created_at: Mapped[datetime] = created_at_column()
    updated_at: Mapped[datetime] = updated_at_column()


class DimAsset(Base):
    """SCD Type 2: a change closes the current row (``valid_to``) and inserts a new one."""

    __tablename__ = "dim_asset"
    __table_args__ = (
        CheckConstraint(_in("criticality", CRITICALITY), name="criticality"),
        CheckConstraint("valid_to IS NULL OR valid_to > valid_from", name="validity"),
        Index(
            "uq_dim_asset_current_asset_id",
            "asset_id",
            unique=True,
            postgresql_where=text("is_current"),
        ),
        Index(None, "ip_address"),
        Index(None, "hostname"),
    )

    asset_key: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    asset_id: Mapped[str] = mapped_column(Text, nullable=False)
    hostname: Mapped[str | None] = mapped_column(Text)
    ip_address: Mapped[str | None] = mapped_column(INET)
    criticality: Mapped[str] = mapped_column(Text, nullable=False, server_default=text("'unknown'"))
    owner: Mapped[str | None] = mapped_column(Text)
    environment: Mapped[str | None] = mapped_column(Text)
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    valid_to: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    is_current: Mapped[bool] = mapped_column(Boolean, nullable=False)
    created_at: Mapped[datetime] = created_at_column()


class DimAttackCategory(Base):
    __tablename__ = "dim_attack_category"
    __table_args__ = (
        CheckConstraint("severity_weight >= 0 AND severity_weight <= 1", name="severity_weight"),
    )

    attack_category_id: Mapped[int] = mapped_column(
        SmallInteger, primary_key=True, autoincrement=False
    )
    code: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    is_benign: Mapped[bool] = mapped_column(Boolean, nullable=False)
    severity_weight: Mapped[Decimal] = mapped_column(Numeric(3, 2), nullable=False)


# --- raw ingestion ---------------------------------------------------------------------------


class IngestionBatch(Base):
    __tablename__ = "ingestion_batch"
    __table_args__ = (
        CheckConstraint(_in("status", BATCH_STATUSES), name="status"),
        CheckConstraint(
            "records_total >= 0 AND records_loaded >= 0 AND records_rejected >= 0 "
            "AND records_duplicate >= 0",
            name="counters",
        ),
        # File-level idempotency; duplicate batches are recorded but excluded from the key.
        Index(
            "uq_ingestion_batch_file",
            "source_id",
            "file_sha256",
            "adapter",
            "adapter_version",
            unique=True,
            postgresql_where=text("status <> 'duplicate'"),
        ),
        Index(None, "source_id", "created_at"),
        Index(None, "status"),
    )

    batch_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    source_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("dim_source.source_id"), nullable=False
    )
    adapter: Mapped[str] = mapped_column(Text, nullable=False)
    adapter_version: Mapped[str] = mapped_column(Text, nullable=False)
    original_filename: Mapped[str] = mapped_column(Text, nullable=False)
    stored_path: Mapped[str] = mapped_column(Text, nullable=False)
    file_sha256: Mapped[str] = mapped_column(Text, nullable=False)
    file_size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default=text("'pending'"))
    records_total: Mapped[int] = mapped_column(BigInteger, nullable=False, server_default=text("0"))
    records_loaded: Mapped[int] = mapped_column(
        BigInteger, nullable=False, server_default=text("0")
    )
    records_rejected: Mapped[int] = mapped_column(
        BigInteger, nullable=False, server_default=text("0")
    )
    records_duplicate: Mapped[int] = mapped_column(
        BigInteger, nullable=False, server_default=text("0")
    )
    last_committed_record: Mapped[int] = mapped_column(
        BigInteger, nullable=False, server_default=text("0")
    )
    timezone_assumption: Mapped[str | None] = mapped_column(Text)
    label_mapping_version: Mapped[str | None] = mapped_column(Text)
    # Variant, encoding counts, header map, per-field warning counters, options.
    batch_metadata: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )
    error_summary: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    duplicate_of: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("ingestion_batch.batch_id")
    )
    job_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("job.job_id"))
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("app_user.user_id")
    )
    created_at: Mapped[datetime] = created_at_column()
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = updated_at_column()


class RawRecord(Base):
    __tablename__ = "raw_record"
    __table_args__ = (
        UniqueConstraint("batch_id", "record_number"),
        CheckConstraint("record_number >= 1", name="record_number"),
        CheckConstraint("record_sha256 ~ '^[0-9a-f]{64}$'", name="record_sha256"),
    )

    raw_record_id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    batch_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("ingestion_batch.batch_id"), nullable=False
    )
    record_number: Mapped[int] = mapped_column(BigInteger, nullable=False)
    raw_payload: Mapped[Any | None] = mapped_column(JSONB)
    raw_text: Mapped[str | None] = mapped_column(Text)
    raw_truncated: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("false")
    )
    # NUL bytes cannot be stored in PostgreSQL text/jsonb; they are escaped as "\x00".
    raw_nul_escaped: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("false")
    )
    record_sha256: Mapped[str] = mapped_column(Text, nullable=False)
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class RejectedRecord(Base):
    __tablename__ = "rejected_record"
    __table_args__ = (Index(None, "batch_id", "record_number"),)

    rejected_record_id: Mapped[int] = mapped_column(
        BigInteger, Identity(always=True), primary_key=True
    )
    batch_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("ingestion_batch.batch_id"), nullable=False
    )
    raw_record_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("raw_record.raw_record_id")
    )
    record_number: Mapped[int] = mapped_column(BigInteger, nullable=False)
    error_code: Mapped[str] = mapped_column(Text, nullable=False)
    field_name: Mapped[str | None] = mapped_column(Text)
    error_detail: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = created_at_column()


# --- facts -----------------------------------------------------------------------------------


class FactSecurityEvent(Base):
    __tablename__ = "fact_security_event"
    __table_args__ = (
        CheckConstraint(_in("event_type", EVENT_TYPES), name="event_type"),
        CheckConstraint(_in("time_quality", TIME_QUALITY), name="time_quality"),
        CheckConstraint(
            "(src_port IS NULL OR src_port BETWEEN 0 AND 65535) "
            "AND (dst_port IS NULL OR dst_port BETWEEN 0 AND 65535)",
            name="ports",
        ),
        CheckConstraint(
            "coalesce(bytes_out, 0) >= 0 AND coalesce(bytes_in, 0) >= 0 "
            "AND coalesce(packets_out, 0) >= 0 AND coalesce(packets_in, 0) >= 0 "
            "AND coalesce(duration_s, 0) >= 0",
            name="counters",
        ),
        CheckConstraint("event_hour BETWEEN 0 AND 23", name="event_hour"),
        CheckConstraint("event_fingerprint ~ '^[0-9a-f]{64}$'", name="event_fingerprint"),
        UniqueConstraint("source_id", "event_fingerprint", "event_time"),
        Index("ix_fact_security_event_event_time", text("event_time DESC")),
        Index(None, "source_id", "event_time"),
        Index(None, "src_ip", "event_time"),
        Index(None, "dst_ip", "event_time"),
        Index(None, "dst_port", "event_time"),
        Index(None, "event_type", "event_time"),
        Index(None, "batch_id"),
        Index(
            "ix_fact_security_event_user_name_normalized_event_time",
            "user_name_normalized",
            "event_time",
            postgresql_where=text("user_name_normalized IS NOT NULL"),
        ),
        Index(
            "ix_fact_security_event_host_name_event_time",
            "host_name",
            "event_time",
            postgresql_where=text("host_name IS NOT NULL"),
        ),
        {"postgresql_partition_by": "RANGE (event_time)"},
    )

    event_id: Mapped[int] = mapped_column(
        BigInteger, event_id_seq, primary_key=True, server_default=event_id_seq.next_value()
    )
    event_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), primary_key=True)
    event_end_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    time_quality: Mapped[str] = mapped_column(Text, nullable=False)
    date_key: Mapped[int] = mapped_column(Integer, ForeignKey("dim_date.date_key"), nullable=False)
    event_hour: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    source_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("dim_source.source_id"), nullable=False
    )
    batch_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("ingestion_batch.batch_id"), nullable=False
    )
    raw_record_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("raw_record.raw_record_id"), nullable=False
    )
    source_event_id: Mapped[str | None] = mapped_column(Text)
    event_fingerprint: Mapped[str] = mapped_column(Text, nullable=False)
    adapter_version: Mapped[str] = mapped_column(Text, nullable=False)
    normalizer_version: Mapped[str] = mapped_column(Text, nullable=False)
    ingested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    event_type: Mapped[str] = mapped_column(Text, nullable=False)
    # network
    src_ip: Mapped[str | None] = mapped_column(INET)
    src_port: Mapped[int | None] = mapped_column(Integer)
    dst_ip: Mapped[str | None] = mapped_column(INET)
    dst_port: Mapped[int | None] = mapped_column(Integer)
    protocol: Mapped[str | None] = mapped_column(Text)
    ip_proto: Mapped[int | None] = mapped_column(SmallInteger)
    app_protocol: Mapped[str | None] = mapped_column(Text)
    direction: Mapped[str | None] = mapped_column(Text)
    conn_state: Mapped[str | None] = mapped_column(Text)
    # flow metrics
    duration_s: Mapped[float | None] = mapped_column(Double)
    bytes_out: Mapped[int | None] = mapped_column(BigInteger)
    bytes_in: Mapped[int | None] = mapped_column(BigInteger)
    packets_out: Mapped[int | None] = mapped_column(BigInteger)
    packets_in: Mapped[int | None] = mapped_column(BigInteger)
    # authentication
    user_name: Mapped[str | None] = mapped_column(Text)
    user_name_normalized: Mapped[str | None] = mapped_column(Text)
    auth_result: Mapped[str | None] = mapped_column(Text)
    auth_method: Mapped[str | None] = mapped_column(Text)
    service: Mapped[str | None] = mapped_column(Text)
    # endpoint
    host_name: Mapped[str | None] = mapped_column(Text)
    process_name: Mapped[str | None] = mapped_column(Text)
    process_command_line: Mapped[str | None] = mapped_column(Text)
    parent_process_name: Mapped[str | None] = mapped_column(Text)
    file_path: Mapped[str | None] = mapped_column(Text)
    file_sha256: Mapped[str | None] = mapped_column(Text)
    # application
    dns_query: Mapped[str | None] = mapped_column(Text)
    http_host: Mapped[str | None] = mapped_column(Text)
    url: Mapped[str | None] = mapped_column(Text)
    # IDS
    signature_id: Mapped[int | None] = mapped_column(BigInteger)
    signature: Mapped[str | None] = mapped_column(Text)
    alert_category: Mapped[str | None] = mapped_column(Text)
    source_severity: Mapped[int | None] = mapped_column(SmallInteger)
    # enrichment keys
    src_asset_key: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("dim_asset.asset_key"))
    dst_asset_key: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("dim_asset.asset_key"))
    attributes: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )


class EventGroundTruth(Base):
    """Dataset-provided labels. Immutable after load; never written by models or analysts."""

    __tablename__ = "event_ground_truth"
    __table_args__ = (
        ForeignKeyConstraint(
            ["event_id", "event_time"],
            ["fact_security_event.event_id", "fact_security_event.event_time"],
            ondelete="CASCADE",
        ),
        CheckConstraint(_in("mapping_status", MAPPING_STATUS), name="mapping_status"),
        CheckConstraint("label_origin = 'dataset'", name="label_origin"),
        Index(None, "attack_category_id"),
    )

    event_id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    event_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), primary_key=True)
    label_raw: Mapped[str] = mapped_column(Text, nullable=False)
    attack_category_id: Mapped[int | None] = mapped_column(
        SmallInteger, ForeignKey("dim_attack_category.attack_category_id")
    )
    is_attack: Mapped[bool | None] = mapped_column(Boolean)
    mapping_status: Mapped[str] = mapped_column(Text, nullable=False)
    label_mapping_version: Mapped[str] = mapped_column(Text, nullable=False)
    label_origin: Mapped[str] = mapped_column(
        Text, nullable=False, server_default=text("'dataset'")
    )
    created_at: Mapped[datetime] = created_at_column()


class DataQualityResult(Base):
    __tablename__ = "data_quality_result"
    __table_args__ = (
        CheckConstraint(_in("status", DQ_STATUSES), name="status"),
        Index(None, "batch_id"),
        Index(None, "status", "checked_at"),
    )

    dq_result_id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    batch_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("ingestion_batch.batch_id"), nullable=False
    )
    check_name: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False)
    metric_value: Mapped[float | None] = mapped_column(Double)
    threshold: Mapped[float | None] = mapped_column(Double)
    details: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )
    checked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
