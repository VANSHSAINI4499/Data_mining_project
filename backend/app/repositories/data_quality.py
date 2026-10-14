"""Queries behind data-quality checks and results."""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import datetime
from typing import Any

from sqlalchemy import delete, func, insert, select, text
from sqlalchemy.orm import Session

from app.models import (
    DataQualityResult,
    DimSource,
    EventGroundTruth,
    FactSecurityEvent,
    IngestionBatch,
    RejectedRecord,
)

# Only canonical columns may be null-checked; names come from adapter class metadata, never
# from user input, and are validated against the table here as defence in depth.
_EVENT_COLUMNS = frozenset(FactSecurityEvent.__table__.columns.keys())


def null_counts(session: Session, batch_id: uuid.UUID, fields: Sequence[str]) -> dict[str, int]:
    for name in fields:
        if name not in _EVENT_COLUMNS:
            raise ValueError(f"not an event column: {name}")
    columns = [
        func.count().filter(getattr(FactSecurityEvent, name).is_(None)).label(name)
        for name in fields
    ]
    row = session.execute(select(*columns).where(FactSecurityEvent.batch_id == batch_id)).one()
    return {name: int(row._mapping[name]) for name in fields}


def rejection_counts(session: Session, batch_id: uuid.UUID) -> dict[str, int]:
    rows = session.execute(
        select(RejectedRecord.error_code, func.count())
        .where(RejectedRecord.batch_id == batch_id)
        .group_by(RejectedRecord.error_code)
    )
    return {code: int(n) for code, n in rows}


def future_event_count(session: Session, batch_id: uuid.UUID, now: datetime) -> int:
    return int(
        session.scalar(
            select(func.count())
            .select_from(FactSecurityEvent)
            .where(FactSecurityEvent.batch_id == batch_id, FactSecurityEvent.event_time > now)
        )
        or 0
    )


def assumed_time_count(session: Session, batch_id: uuid.UUID) -> int:
    return int(
        session.scalar(
            select(func.count())
            .select_from(FactSecurityEvent)
            .where(
                FactSecurityEvent.batch_id == batch_id, FactSecurityEvent.time_quality == "assumed"
            )
        )
        or 0
    )


def default_partition_count(session: Session) -> int:
    return int(session.scalar(text("SELECT count(*) FROM fact_security_event_default")) or 0)


def label_status_counts(session: Session, batch_id: uuid.UUID) -> dict[str, int]:
    rows = session.execute(
        select(EventGroundTruth.mapping_status, func.count())
        .join(
            FactSecurityEvent,
            (FactSecurityEvent.event_id == EventGroundTruth.event_id)
            & (FactSecurityEvent.event_time == EventGroundTruth.event_time),
        )
        .where(FactSecurityEvent.batch_id == batch_id)
        .group_by(EventGroundTruth.mapping_status)
    )
    return {status: int(n) for status, n in rows}


def replace_results(
    session: Session, batch_id: uuid.UUID, rows: list[dict[str, Any]]
) -> list[DataQualityResult]:
    session.execute(delete(DataQualityResult).where(DataQualityResult.batch_id == batch_id))
    if rows:
        session.execute(insert(DataQualityResult), [{**r, "batch_id": batch_id} for r in rows])
    return results_for_batch(session, batch_id)


def results_for_batch(session: Session, batch_id: uuid.UUID) -> list[DataQualityResult]:
    return list(
        session.scalars(
            select(DataQualityResult)
            .where(DataQualityResult.batch_id == batch_id)
            .order_by(DataQualityResult.dq_result_id)
        )
    )


def status_counts_by_source(
    session: Session, start: datetime, end: datetime
) -> list[dict[str, Any]]:
    rows = session.execute(
        select(DimSource.source_id, DimSource.source_key, DataQualityResult.status, func.count())
        .join(IngestionBatch, IngestionBatch.batch_id == DataQualityResult.batch_id)
        .join(DimSource, DimSource.source_id == IngestionBatch.source_id)
        .where(DataQualityResult.checked_at >= start, DataQualityResult.checked_at < end)
        .group_by(DimSource.source_id, DimSource.source_key, DataQualityResult.status)
        .order_by(DimSource.source_key)
    )
    result: dict[int, dict[str, Any]] = {}
    for source_id, key, status, n in rows:
        entry = result.setdefault(
            source_id, {"source_id": source_id, "source_key": key, "pass": 0, "warn": 0, "fail": 0}
        )
        entry[status] = int(n)
    return list(result.values())


def latest_problems(
    session: Session, start: datetime, end: datetime, limit: int
) -> list[DataQualityResult]:
    return list(
        session.scalars(
            select(DataQualityResult)
            .where(
                DataQualityResult.status.in_(("warn", "fail")),
                DataQualityResult.checked_at >= start,
                DataQualityResult.checked_at < end,
            )
            .order_by(DataQualityResult.checked_at.desc(), DataQualityResult.dq_result_id.desc())
            .limit(limit)
        )
    )
