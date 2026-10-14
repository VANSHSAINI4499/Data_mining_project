"""Queries for anomaly mining input and results."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import and_, or_, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.models import (
    AnomalyResult,
    DimAttackCategory,
    EventGroundTruth,
    FactSecurityEvent,
    MlModel,
)

F = FactSecurityEvent


def window_events(
    session: Session, start: datetime, end: datetime, source_id: int | None = None
) -> list[dict[str, Any]]:
    """Events for window features; assumed timestamps are excluded (§1)."""
    malicious = and_(
        EventGroundTruth.attack_category_id.is_not(None), DimAttackCategory.is_benign.is_(False)
    )
    stmt = (
        select(
            F.event_time,
            F.event_type,
            F.src_ip,
            F.dst_ip,
            F.dst_port,
            F.host_name,
            F.user_name_normalized,
            F.auth_result,
            F.bytes_out,
            F.bytes_in,
            F.duration_s,
            malicious.label("labelled_malicious"),
        )
        .outerjoin(
            EventGroundTruth,
            and_(
                EventGroundTruth.event_id == F.event_id, EventGroundTruth.event_time == F.event_time
            ),
        )
        .outerjoin(
            DimAttackCategory,
            DimAttackCategory.attack_category_id == EventGroundTruth.attack_category_id,
        )
        .where(F.event_time >= start, F.event_time < end, F.time_quality != "assumed")
    )
    if source_id is not None:
        stmt = stmt.where(F.source_id == source_id)
    rows = []
    for r in session.execute(stmt):
        d = dict(r._mapping)
        for key in ("src_ip", "dst_ip"):
            if d[key] is not None:
                d[key] = str(d[key]).split("/")[0]
        d["labelled_malicious"] = bool(d["labelled_malicious"])
        rows.append(d)
    return rows


def insert_results(session: Session, rows: list[dict[str, Any]]) -> int:
    if not rows:
        return 0
    stmt = (
        pg_insert(AnomalyResult)
        .on_conflict_do_nothing(
            index_elements=["model_id", "entity_type", "entity_value", "window_start"]
        )
        .returning(AnomalyResult.result_id)
    )
    return len(list(session.execute(stmt, rows)))


def list_results(
    session: Session,
    *,
    model_id: uuid.UUID | None,
    entity_type: str | None,
    entity_value: str | None,
    flagged: bool | None,
    min_percentile: float | None,
    start: datetime | None,
    end: datetime | None,
    after: tuple[float, int] | None,
    limit: int,
) -> list[AnomalyResult]:
    stmt = select(AnomalyResult)
    if model_id:
        stmt = stmt.where(AnomalyResult.model_id == model_id)
    if entity_type:
        stmt = stmt.where(AnomalyResult.entity_type == entity_type)
    if entity_value:
        stmt = stmt.where(AnomalyResult.entity_value == entity_value)
    if flagged is not None:
        stmt = stmt.where(AnomalyResult.is_flagged.is_(flagged))
    if min_percentile is not None:
        stmt = stmt.where(AnomalyResult.score_percentile >= min_percentile)
    if start:
        stmt = stmt.where(AnomalyResult.window_start >= start)
    if end:
        stmt = stmt.where(AnomalyResult.window_start < end)
    if after:
        stmt = stmt.where(
            or_(
                AnomalyResult.anomaly_score < after[0],
                and_(AnomalyResult.anomaly_score == after[0], AnomalyResult.result_id < after[1]),
            )
        )
    stmt = stmt.order_by(AnomalyResult.anomaly_score.desc(), AnomalyResult.result_id.desc())
    return list(session.scalars(stmt.limit(limit)))


def entity_history(
    session: Session,
    model_id: uuid.UUID,
    entity_type: str,
    entity_value: str,
    start: datetime,
    end: datetime,
) -> list[AnomalyResult]:
    return list(
        session.scalars(
            select(AnomalyResult)
            .where(
                AnomalyResult.model_id == model_id,
                AnomalyResult.entity_type == entity_type,
                AnomalyResult.entity_value == entity_value,
                AnomalyResult.window_start >= start,
                AnomalyResult.window_start <= end,
            )
            .order_by(AnomalyResult.window_start)
        )
    )


def model_names(session: Session, model_id: uuid.UUID) -> MlModel | None:
    return session.get(MlModel, model_id)
