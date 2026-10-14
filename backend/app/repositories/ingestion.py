"""Queries for ingestion batches, raw/rejected records, events, and ground truth."""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import datetime
from typing import Any

import psycopg
from psycopg import sql
from psycopg.types.json import Jsonb
from sqlalchemy import and_, func, insert, or_, select, text, update
from sqlalchemy.orm import Session

from app.models import (
    DimAsset,
    DimSource,
    FactSecurityEvent,
    IngestionBatch,
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


# Bulk loading uses COPY into a temporary table followed by INSERT ... SELECT, which avoids
# building very large multi-row INSERT statements (measured in Phase 7, NFR-03).
JSON_COLUMNS = frozenset({"raw_payload", "attributes"})


def _copy_rows(
    session: Session, table: str, columns: list[str], rows: list[dict[str, Any]]
) -> None:
    conn = session.connection().connection.driver_connection
    assert isinstance(conn, psycopg.Connection)
    statement = sql.SQL("COPY {} ({}) FROM STDIN").format(
        sql.Identifier(table), sql.SQL(", ").join(map(sql.Identifier, columns))
    )
    with conn.cursor() as cur, cur.copy(statement) as copy:
        for row in rows:
            copy.write_row(
                [Jsonb(row.get(c)) if c in JSON_COLUMNS else row.get(c) for c in columns]
            )


def _cols(columns: list[str]) -> str:
    """Quoted identifiers. Callers pass fixed lists or names checked against the model."""
    bad = [c for c in columns if not c.replace("_", "").isalnum()]
    if bad:
        raise ValueError(f"invalid column names {bad}")
    return ", ".join(f'"{c}"' for c in columns)


def _temp_like(session: Session, name: str, source: str, columns: list[str]) -> None:
    # CREATE TABLE AS copies column types but not NOT NULL constraints or defaults.
    session.execute(
        text(
            f"CREATE TEMP TABLE {name} ON COMMIT DROP AS "  # noqa: S608 - fixed identifiers
            f"SELECT {_cols(columns)} FROM {source} WITH NO DATA"
        )
    )


RAW_COLUMNS = [
    "batch_id",
    "record_number",
    "raw_payload",
    "raw_text",
    "raw_truncated",
    "raw_nul_escaped",
    "record_sha256",
]


def insert_raw_records(session: Session, rows: list[dict[str, Any]]) -> list[int]:
    """Insert raw records; returns their IDs in the order of ``rows``."""
    if not rows:
        return []
    _temp_like(session, "tmp_raw_record", "raw_record", RAW_COLUMNS)
    _copy_rows(session, "tmp_raw_record", RAW_COLUMNS, rows)
    cols = _cols(RAW_COLUMNS)
    result = session.execute(
        text(
            f"INSERT INTO raw_record ({cols}) SELECT {cols} FROM tmp_raw_record "  # noqa: S608
            "RETURNING raw_record_id, record_number"
        )
    )
    by_number = {number: rid for rid, number in result}
    session.execute(text("DROP TABLE tmp_raw_record"))
    return [by_number[r["record_number"]] for r in rows]


def insert_events(session: Session, rows: list[dict[str, Any]]) -> list[tuple[int, datetime, str]]:
    """Insert, skipping duplicates. Returns (event_id, event_time, fingerprint) of new rows."""
    if not rows:
        return []
    columns = sorted({key for row in rows for key in row} - {"event_id"})
    valid = set(FactSecurityEvent.__table__.columns.keys())
    unknown = set(columns) - valid
    if unknown:
        raise ValueError(f"unknown event columns {sorted(unknown)}")
    _temp_like(session, "tmp_event", "fact_security_event", columns)
    _copy_rows(session, "tmp_event", columns, rows)
    cols = _cols(columns)
    result = session.execute(
        text(
            f"INSERT INTO fact_security_event ({cols}) SELECT {cols} FROM tmp_event "  # noqa: S608
            "ON CONFLICT (source_id, event_fingerprint, event_time) DO NOTHING "
            "RETURNING event_id, event_time, event_fingerprint"
        )
    )
    inserted = [(r[0], r[1], r[2]) for r in result]
    session.execute(text("DROP TABLE tmp_event"))
    return inserted


GT_COLUMNS = [
    "event_id",
    "event_time",
    "label_raw",
    "attack_category_id",
    "is_attack",
    "mapping_status",
    "label_mapping_version",
]


def insert_ground_truth(session: Session, rows: list[dict[str, Any]]) -> None:
    if rows:
        _copy_rows(session, "event_ground_truth", GT_COLUMNS, rows)


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
