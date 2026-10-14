"""Queries for ingestion batches, raw/rejected records, events, and ground truth."""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import datetime
from typing import Any

from sqlalchemy import and_, func, insert, or_, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.models import (
    DimAsset,
    DimSource,
    EventGroundTruth,
    FactSecurityEvent,
    IngestionBatch,
    RawRecord,
    RejectedRecord,
)

# --- sources -----------------------------------------------------------------------------------


def get_source(session: Session, source_id: int) -> DimSource | None:
    return session.get(DimSource, source_id)


def get_source_by_key(session: Session, source_key: str) -> DimSource | None:
    return session.scalar(select(DimSource).where(DimSource.source_key == source_key))


# --- batches -----------------------------------------------------------------------------------


def find_ingested_file(
    session: Session, source_id: int, file_sha256: str, adapter: str, adapter_version: str
) -> IngestionBatch | None:
    return session.scalar(
        select(IngestionBatch).where(
            IngestionBatch.source_id == source_id,
            IngestionBatch.file_sha256 == file_sha256,
            IngestionBatch.adapter == adapter,
            IngestionBatch.adapter_version == adapter_version,
            IngestionBatch.status != "duplicate",
        )
    )


def get_batch(
    session: Session, batch_id: uuid.UUID, *, for_update: bool = False
) -> IngestionBatch | None:
    stmt = select(IngestionBatch).where(IngestionBatch.batch_id == batch_id)
    if for_update:
        stmt = stmt.with_for_update()
    return session.scalar(stmt)


def list_batches(
    session: Session,
    *,
    source_id: int | None,
    statuses: list[str] | None,
    created_after: datetime | None,
    created_before: datetime | None,
    after: tuple[datetime, uuid.UUID] | None,
    limit: int,
) -> list[IngestionBatch]:
    stmt = (
        select(IngestionBatch)
        .order_by(IngestionBatch.created_at.desc(), IngestionBatch.batch_id.desc())
        .limit(limit)
    )
    if source_id is not None:
        stmt = stmt.where(IngestionBatch.source_id == source_id)
    if statuses:
        stmt = stmt.where(IngestionBatch.status.in_(statuses))
    if created_after is not None:
        stmt = stmt.where(IngestionBatch.created_at >= created_after)
    if created_before is not None:
        stmt = stmt.where(IngestionBatch.created_at < created_before)
    if after is not None:
        created, batch_id = after
        stmt = stmt.where(
            or_(
                IngestionBatch.created_at < created,
                and_(IngestionBatch.created_at == created, IngestionBatch.batch_id < batch_id),
            )
        )
    return list(session.scalars(stmt))


def add_progress(
    session: Session,
    batch_id: uuid.UUID,
    *,
    total: int,
    loaded: int,
    rejected: int,
    duplicate: int,
    last_record: int,
    metadata: dict[str, Any],
    now: datetime,
) -> None:
    session.execute(
        update(IngestionBatch)
        .where(IngestionBatch.batch_id == batch_id)
        .values(
            records_total=IngestionBatch.records_total + total,
            records_loaded=IngestionBatch.records_loaded + loaded,
            records_rejected=IngestionBatch.records_rejected + rejected,
            records_duplicate=IngestionBatch.records_duplicate + duplicate,
            last_committed_record=last_record,
            batch_metadata=metadata,
            updated_at=now,
        )
    )


# --- records and events ------------------------------------------------------------------------


def ensure_partitions(session: Session, start: datetime, end: datetime) -> int:
    return int(session.scalar(select(func.ensure_event_partitions(start, end))) or 0)


def insert_raw_records(session: Session, rows: list[dict[str, Any]]) -> list[int]:
    if not rows:
        return []
    result = session.execute(
        insert(RawRecord).returning(RawRecord.raw_record_id, sort_by_parameter_order=True), rows
    )
    return [r[0] for r in result]


def insert_events(session: Session, rows: list[dict[str, Any]]) -> list[tuple[int, datetime, str]]:
    """Insert, skipping duplicates. Returns (event_id, event_time, fingerprint) of new rows."""
    if not rows:
        return []
    stmt = (
        pg_insert(FactSecurityEvent)
        .on_conflict_do_nothing(index_elements=["source_id", "event_fingerprint", "event_time"])
        .returning(
            FactSecurityEvent.event_id,
            FactSecurityEvent.event_time,
            FactSecurityEvent.event_fingerprint,
        )
    )
    return [(r[0], r[1], r[2]) for r in session.execute(stmt, rows)]


def insert_ground_truth(session: Session, rows: list[dict[str, Any]]) -> None:
    if rows:
        session.execute(insert(EventGroundTruth), rows)


def insert_rejections(session: Session, rows: list[dict[str, Any]]) -> None:
    if rows:
        session.execute(insert(RejectedRecord), rows)


def list_rejections(
    session: Session, batch_id: uuid.UUID, after: tuple[int, int] | None, limit: int
) -> list[RejectedRecord]:
    stmt = (
        select(RejectedRecord)
        .where(RejectedRecord.batch_id == batch_id)
        .order_by(RejectedRecord.record_number, RejectedRecord.rejected_record_id)
        .limit(limit)
    )
    if after is not None:
        number, rid = after
        stmt = stmt.where(
            or_(
                RejectedRecord.record_number > number,
                and_(
                    RejectedRecord.record_number == number,
                    RejectedRecord.rejected_record_id > rid,
                ),
            )
        )
    return list(session.scalars(stmt))


def count_rejections(session: Session, batch_id: uuid.UUID) -> int:
    return int(
        session.scalar(
            select(func.count())
            .select_from(RejectedRecord)
            .where(RejectedRecord.batch_id == batch_id)
        )
        or 0
    )


# --- assets ------------------------------------------------------------------------------------


def find_asset_versions(
    session: Session, ips: Sequence[str], hostnames: Sequence[str]
) -> list[DimAsset]:
    conditions = []
    if ips:
        conditions.append(func.host(DimAsset.ip_address).in_(list(ips)))
    if hostnames:
        conditions.append(func.lower(DimAsset.hostname).in_([h.lower() for h in hostnames]))
    if not conditions:
        return []
    return list(session.scalars(select(DimAsset).where(or_(*conditions))))
