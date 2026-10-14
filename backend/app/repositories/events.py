"""Event queries and aggregations. Dimensions/metrics are allow-listed column objects."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import and_, cast, func, literal, or_, select
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.orm import Session
from sqlalchemy.sql.elements import ColumnElement

from app.models import (
    ClassificationResult,
    DimAttackCategory,
    DimSource,
    EventGroundTruth,
    FactSecurityEvent,
    IngestionBatch,
    RawRecord,
)

F = FactSecurityEvent
GT = EventGroundTruth
CAT = DimAttackCategory
R = ClassificationResult
PCAT = DimAttackCategory.__table__.alias("pred_cat")


@dataclass
class EventFilters:
    start: datetime
    end: datetime
    source_ids: list[int] = field(default_factory=list)
    batch_id: uuid.UUID | None = None
    event_types: list[str] = field(default_factory=list)
    src_ip: str | None = None
    dst_ip: str | None = None
    ip: str | None = None
    dst_port: int | None = None
    protocol: str | None = None
    user_name: str | None = None
    host_name: str | None = None
    signature_id: int | None = None
    ground_truth_categories: list[str] = field(default_factory=list)
    time_quality: str | None = None
    # Prediction filters apply to one model (the active classifier, resolved by the service).
    prediction_model_id: uuid.UUID | None = None
    predicted_categories: list[str] = field(default_factory=list)
    min_predicted_score: float | None = None


def _gt_join(stmt: Any) -> Any:
    return stmt.outerjoin(
        GT, and_(GT.event_id == F.event_id, GT.event_time == F.event_time)
    ).outerjoin(CAT, CAT.attack_category_id == GT.attack_category_id)


def _prediction_join(stmt: Any, f: EventFilters) -> Any:
    """Outer-join the chosen model's prediction (at most one row per event and model)."""
    if f.prediction_model_id is None:
        return stmt
    return stmt.outerjoin(
        R,
        and_(
            R.event_id == F.event_id,
            R.event_time == F.event_time,
            R.model_id == f.prediction_model_id,
        ),
    ).outerjoin(PCAT, PCAT.c.attack_category_id == R.predicted_category_id)


def _prediction_conditions(f: EventFilters) -> list[ColumnElement[bool]]:
    conds: list[ColumnElement[bool]] = []
    if f.predicted_categories:
        conds.append(PCAT.c.code.in_(f.predicted_categories))
    if f.min_predicted_score is not None:
        conds.append(R.predicted_score >= f.min_predicted_score)
    return conds


def _all_conditions(f: EventFilters) -> list[ColumnElement[bool]]:
    conds = [*_conditions(f), *_prediction_conditions(f)]
    if f.ground_truth_categories:
        conds.append(CAT.code.in_(f.ground_truth_categories))
    return conds


def _conditions(f: EventFilters) -> list[ColumnElement[bool]]:
    conds: list[ColumnElement[bool]] = [F.event_time >= f.start, F.event_time < f.end]
    if f.source_ids:
        conds.append(F.source_id.in_(f.source_ids))
    if f.batch_id is not None:
        conds.append(F.batch_id == f.batch_id)
    if f.event_types:
        conds.append(F.event_type.in_(f.event_types))
    if f.src_ip:
        conds.append(F.src_ip == cast(f.src_ip, INET))
    if f.dst_ip:
        conds.append(F.dst_ip == cast(f.dst_ip, INET))
    if f.ip:
        ip = cast(f.ip, INET)
        conds.append(or_(F.src_ip == ip, F.dst_ip == ip))
    if f.dst_port is not None:
        conds.append(F.dst_port == f.dst_port)
    if f.protocol:
        conds.append(F.protocol == f.protocol)
    if f.user_name:
        conds.append(F.user_name_normalized == f.user_name.strip().lower())
    if f.host_name:
        conds.append(func.lower(F.host_name) == f.host_name.strip().lower())
    if f.signature_id is not None:
        conds.append(F.signature_id == f.signature_id)
    if f.time_quality:
        conds.append(F.time_quality == f.time_quality)
    return conds


SUMMARY_COLUMNS = (
    F.event_id,
    F.event_time,
    F.event_type,
    F.source_id,
    F.batch_id,
    F.src_ip,
    F.src_port,
    F.dst_ip,
    F.dst_port,
    F.protocol,
    F.user_name,
    F.host_name,
    F.signature,
    F.bytes_out,
    F.bytes_in,
    F.time_quality,
)


def search_events(
    session: Session, f: EventFilters, after: tuple[datetime, int] | None, limit: int
) -> list[dict[str, Any]]:
    columns: list[Any] = [*SUMMARY_COLUMNS, CAT.code.label("ground_truth_category")]
    if f.prediction_model_id is not None:
        columns += [
            PCAT.c.code.label("predicted_category"),
            R.predicted_score.label("predicted_score"),
        ]
    stmt = _prediction_join(_gt_join(select(*columns)), f)
    stmt = stmt.where(*_all_conditions(f))
    if after is not None:
        t, eid = after
        stmt = stmt.where(or_(F.event_time < t, and_(F.event_time == t, F.event_id < eid)))
    stmt = stmt.order_by(F.event_time.desc(), F.event_id.desc()).limit(limit)
    return [dict(r._mapping) for r in session.execute(stmt)]


def get_event(
    session: Session, event_id: int, event_time: datetime | None
) -> tuple[FactSecurityEvent, IngestionBatch, DimSource, RawRecord] | None:
    stmt = (
        select(F, IngestionBatch, DimSource, RawRecord)
        .join(IngestionBatch, IngestionBatch.batch_id == F.batch_id)
        .join(DimSource, DimSource.source_id == F.source_id)
        .join(RawRecord, RawRecord.raw_record_id == F.raw_record_id)
        .where(F.event_id == event_id)
    )
    if event_time is not None:
        stmt = stmt.where(F.event_time == event_time)
    row = session.execute(stmt).first()
    return None if row is None else (row[0], row[1], row[2], row[3])


def get_ground_truth(
    session: Session, event_id: int, event_time: datetime
) -> tuple[EventGroundTruth, str | None] | None:
    row = session.execute(
        select(GT, CAT.code)
        .outerjoin(CAT, CAT.attack_category_id == GT.attack_category_id)
        .where(GT.event_id == event_id, GT.event_time == event_time)
    ).first()
    return None if row is None else (row[0], row[1])


# --- aggregations ------------------------------------------------------------------------------

INTERVALS = {"hour": "hour", "day": "day", "week": "week"}


def _group_column(name: str) -> Any:
    if name == "event_type":
        return F.event_type
    if name == "source":
        return DimSource.source_key
    if name == "ground_truth_category":
        return func.coalesce(CAT.code, literal("(unlabelled)"))
    if name == "protocol":
        return func.coalesce(F.protocol, literal("(none)"))
    if name == "predicted_category":
        return func.coalesce(PCAT.c.code, literal("(not scored)"))
    raise ValueError(name)


def _needs(stmt: Any, name: str | None, f: EventFilters) -> Any:
    if name == "source":
        stmt = stmt.join(DimSource, DimSource.source_id == F.source_id)
    if name == "ground_truth_category" or f.ground_truth_categories:
        stmt = _gt_join(stmt)
    return _prediction_join(stmt, f)


def timeseries(
    session: Session, f: EventFilters, interval: str, metric: str, group_by: str | None
) -> list[tuple[datetime, str | None, float]]:
    bucket = func.date_trunc(INTERVALS[interval], F.event_time).label("bucket")
    value = (
        func.count()
        if metric == "event_count"
        else func.coalesce(
            func.sum(func.coalesce(F.bytes_out, 0) + func.coalesce(F.bytes_in, 0)), 0
        )
    ).label("value")
    if group_by:
        key = _group_column(group_by).label("key")
        stmt = _needs(select(bucket, key, value).select_from(F), group_by, f)
        stmt = stmt.where(*_all_conditions(f)).group_by(bucket, key).order_by(bucket)
        return [(r.bucket, str(r.key), float(r.value)) for r in session.execute(stmt)]
    stmt = _needs(select(bucket, value).select_from(F), None, f)
    stmt = stmt.where(*_all_conditions(f)).group_by(bucket).order_by(bucket)
    return [(r.bucket, None, float(r.value)) for r in session.execute(stmt)]


TOP_DIMENSIONS: dict[str, Any] = {
    "src_ip": func.host(F.src_ip),
    "dst_ip": func.host(F.dst_ip),
    "dst_port": F.dst_port,
    "user_name": F.user_name_normalized,
    "host_name": F.host_name,
    "signature": F.signature,
}


def top_entities(
    session: Session, f: EventFilters, dimension: str, limit: int
) -> list[tuple[Any, int]]:
    col = TOP_DIMENSIONS[dimension]
    n = func.count().label("n")
    stmt = (
        _needs(select(col.label("value"), n).select_from(F), None, f)
        .where(*_all_conditions(f), col.is_not(None))
        .group_by(col)
        .order_by(n.desc(), col)
        .limit(limit)
    )
    return [(r.value, int(r.n)) for r in session.execute(stmt)]


def distribution(session: Session, f: EventFilters, dimension: str) -> list[tuple[str, int]]:
    key = _group_column(dimension).label("key")
    n = func.count().label("n")
    stmt = _needs(select(key, n).select_from(F), dimension, f)
    stmt = stmt.where(*_all_conditions(f)).group_by(key).order_by(n.desc(), key)
    return [(str(r.key), int(r.n)) for r in session.execute(stmt)]
