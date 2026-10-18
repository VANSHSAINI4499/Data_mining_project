"""Queries for web payload scoring of stored HTTP events (``web_payload_result``)."""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from datetime import datetime
from typing import Any

from sqlalchemy import Text, and_, cast, func, or_, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.models import FactSecurityEvent, MlModel, WebPayloadResult

F = FactSecurityEvent
R = WebPayloadResult


def _scope_conditions(scope: dict[str, Any]) -> list[Any]:
    conds: list[Any] = [F.event_type == "http"]
    if scope.get("batch_ids"):
        conds.append(F.batch_id.in_([uuid.UUID(b) for b in scope["batch_ids"]]))
    if scope.get("from"):
        conds.append(F.event_time >= datetime.fromisoformat(scope["from"]))
    if scope.get("to"):
        conds.append(F.event_time < datetime.fromisoformat(scope["to"]))
    if scope.get("source_id"):
        conds.append(F.source_id == int(scope["source_id"]))
    return conds


def http_events(
    session: Session, scope: dict[str, Any], chunk: int
) -> Iterator[list[dict[str, Any]]]:
    """HTTP events in scope with their decoded query parameters, in keyset-paginated chunks."""
    conds = _scope_conditions(scope)
    params = F.attributes["query_params"]
    after: tuple[datetime, int] | None = None
    while True:
        stmt = select(F.event_id, F.event_time, params.label("query_params")).where(*conds)
        if after is not None:
            stmt = stmt.where(
                or_(F.event_time > after[0], and_(F.event_time == after[0], F.event_id > after[1]))
            )
        rows = [
            dict(r._mapping)
            for r in session.execute(stmt.order_by(F.event_time, F.event_id).limit(chunk))
        ]
        if not rows:
            return
        yield rows
        after = (rows[-1]["event_time"], rows[-1]["event_id"])


def insert_results(session: Session, rows: list[dict[str, Any]]) -> int:
    """Insert predictions; rows already scored by the same model are left untouched."""
    if not rows:
        return 0
    stmt = (
        pg_insert(R)
        .on_conflict_do_nothing(
            index_elements=["event_id", "event_time", "model_id", "param_index"]
        )
        .returning(R.result_id)
    )
    return len(list(session.execute(stmt, rows)))


def _param_value() -> Any:
    # The observed value lives in the event (attributes.query_params[i][1]); it is not copied.
    return func.jsonb_extract_path_text(
        F.attributes, "query_params", cast(R.param_index, Text), "1"
    )


def list_results(
    session: Session,
    model_id: uuid.UUID,
    *,
    predicted_class: str | None,
    attack_like_only: bool,
    start: datetime | None,
    end: datetime | None,
    after: tuple[datetime, int] | None,
    limit: int,
) -> list[dict[str, Any]]:
    stmt = (
        select(
            R.result_id,
            R.event_id,
            R.event_time,
            R.param_index,
            R.param_name,
            _param_value().label("param_value"),
            R.predicted_class,
            R.is_attack_like,
            R.score,
            R.score_kind,
            R.truncated,
            F.src_ip,
            F.url,
        )
        .join(F, and_(F.event_id == R.event_id, F.event_time == R.event_time))
        .where(R.model_id == model_id)
    )
    if predicted_class:
        stmt = stmt.where(R.predicted_class == predicted_class)
    if attack_like_only:
        stmt = stmt.where(R.is_attack_like.is_(True))
    if start:
        stmt = stmt.where(R.event_time >= start)
    if end:
        stmt = stmt.where(R.event_time < end)
    if after:
        stmt = stmt.where(
            or_(R.event_time < after[0], and_(R.event_time == after[0], R.result_id < after[1]))
        )
    stmt = stmt.order_by(R.event_time.desc(), R.result_id.desc()).limit(limit)
    out = []
    for r in session.execute(stmt):
        d = dict(r._mapping)
        if d["src_ip"] is not None:
            d["src_ip"] = str(d["src_ip"]).split("/")[0]
        out.append(d)
    return out


def class_counts(
    session: Session, model_id: uuid.UUID, start: datetime | None, end: datetime | None
) -> list[tuple[str, int, int]]:
    """(predicted_class, parameters, distinct events) for the model's stored predictions."""
    stmt = select(
        R.predicted_class,
        func.count(),
        func.count(func.distinct(R.event_id)),
    ).where(R.model_id == model_id)
    if start:
        stmt = stmt.where(R.event_time >= start)
    if end:
        stmt = stmt.where(R.event_time < end)
    stmt = stmt.group_by(R.predicted_class).order_by(func.count().desc(), R.predicted_class)
    return [(str(c), int(n), int(e)) for c, n, e in session.execute(stmt)]


def results_for_event(session: Session, event_id: int, event_time: datetime) -> list[Any]:
    return list(
        session.execute(
            select(R, MlModel.name, MlModel.version, MlModel.status)
            .join(MlModel, MlModel.model_id == R.model_id)
            .where(R.event_id == event_id, R.event_time == event_time)
            .order_by(MlModel.name, MlModel.version.desc(), R.param_index)
        )
    )
