"""Queries for training snapshots, scoring input, the model registry, and results."""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from datetime import datetime
from typing import Any

from sqlalchemy import and_, func, or_, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.models import (
    ClassificationResult,
    DimAttackCategory,
    EventGroundTruth,
    FactSecurityEvent,
    IngestionBatch,
    MlModel,
    MlScoringRun,
    MlTrainingRun,
)

F = FactSecurityEvent
GT = EventGroundTruth
CAT = DimAttackCategory

EVENT_COLUMNS = (
    F.event_id,
    F.event_time,
    F.time_quality,
    F.event_type,
    F.batch_id,
    F.src_ip,
    F.dst_ip,
    F.dst_port,
    F.protocol,
    F.duration_s,
    F.bytes_out,
    F.bytes_in,
    F.packets_out,
    F.packets_in,
    F.attributes,
)


def _row(r: Any) -> dict[str, Any]:
    d = dict(r._mapping)
    for key in ("src_ip", "dst_ip"):
        if d.get(key) is not None:
            d[key] = str(d[key]).split("/")[0]
    return d


def training_snapshot(
    session: Session, batch_ids: list[uuid.UUID], event_types: list[str], label_level: str
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Labelled events of the given batches. Returns (rows, excluded counts by reason)."""
    partition = IngestionBatch.batch_metadata["options"]["dataset_partition"].astext
    label = CAT.code if label_level == "canonical" else GT.label_raw
    stmt = (
        select(
            *EVENT_COLUMNS,
            label.label("label"),
            GT.mapping_status,
            GT.label_mapping_version,
            partition.label("dataset_partition"),
        )
        .join(GT, and_(GT.event_id == F.event_id, GT.event_time == F.event_time))
        .outerjoin(CAT, CAT.attack_category_id == GT.attack_category_id)
        .join(IngestionBatch, IngestionBatch.batch_id == F.batch_id)
        .where(F.batch_id.in_(batch_ids), F.event_type.in_(event_types))
        .order_by(F.event_time, F.event_id)
    )
    rows: list[dict[str, Any]] = []
    excluded: dict[str, int] = {}
    for r in session.execute(stmt):
        d = _row(r)
        if label_level == "canonical" and d["mapping_status"] != "mapped":
            excluded[d["mapping_status"]] = excluded.get(d["mapping_status"], 0) + 1
            continue
        rows.append(d)
    unlabelled = session.scalar(
        select(func.count())
        .select_from(F)
        .outerjoin(GT, and_(GT.event_id == F.event_id, GT.event_time == F.event_time))
        .where(F.batch_id.in_(batch_ids), F.event_type.in_(event_types), GT.event_id.is_(None))
    )
    if unlabelled:
        excluded["no_label"] = int(unlabelled)
    return rows, excluded


def scoring_events(
    session: Session, scope: dict[str, Any], chunk: int
) -> Iterator[list[dict[str, Any]]]:
    """Events in scope, in keyset-paginated chunks (each chunk in its own short query)."""
    conds: list[Any] = []
    if scope.get("batch_ids"):
        conds.append(F.batch_id.in_([uuid.UUID(b) for b in scope["batch_ids"]]))
    if scope.get("from"):
        conds.append(F.event_time >= datetime.fromisoformat(scope["from"]))
    if scope.get("to"):
        conds.append(F.event_time < datetime.fromisoformat(scope["to"]))
    if scope.get("source_id"):
        conds.append(F.source_id == int(scope["source_id"]))
    after: tuple[datetime, int] | None = None
    while True:
        stmt = select(*EVENT_COLUMNS).where(*conds)
        if after is not None:
            stmt = stmt.where(
                or_(F.event_time > after[0], and_(F.event_time == after[0], F.event_id > after[1]))
            )
        rows = [
            _row(r) for r in session.execute(stmt.order_by(F.event_time, F.event_id).limit(chunk))
        ]
        if not rows:
            return
        yield rows
        after = (rows[-1]["event_time"], rows[-1]["event_id"])


# --- registry ----------------------------------------------------------------------------------


def next_version(session: Session, name: str) -> int:
    return (
        int(
            session.scalar(
                select(func.coalesce(func.max(MlModel.version), 0)).where(MlModel.name == name)
            )
            or 0
        )
        + 1
    )


def get_model(session: Session, model_id: uuid.UUID, *, for_update: bool = False) -> MlModel | None:
    stmt = select(MlModel).where(MlModel.model_id == model_id)
    return session.scalar(stmt.with_for_update() if for_update else stmt)


def active_model(session: Session, name: str, *, for_update: bool = False) -> MlModel | None:
    stmt = select(MlModel).where(MlModel.name == name, MlModel.status == "active")
    return session.scalar(stmt.with_for_update() if for_update else stmt)


def list_models(
    session: Session, task: str | None, name: str | None, status: str | None
) -> list[MlModel]:
    stmt = select(MlModel).order_by(MlModel.name, MlModel.version.desc())
    if task:
        stmt = stmt.where(MlModel.task == task)
    if name:
        stmt = stmt.where(MlModel.name == name)
    if status:
        stmt = stmt.where(MlModel.status == status)
    return list(session.scalars(stmt))


def get_run(
    session: Session, run_id: uuid.UUID, *, for_update: bool = False
) -> MlTrainingRun | None:
    stmt = select(MlTrainingRun).where(MlTrainingRun.run_id == run_id)
    return session.scalar(stmt.with_for_update() if for_update else stmt)


def list_runs(session: Session, task: str, limit: int) -> list[MlTrainingRun]:
    return list(
        session.scalars(
            select(MlTrainingRun)
            .where(MlTrainingRun.task == task)
            .order_by(MlTrainingRun.created_at.desc())
            .limit(limit)
        )
    )


def get_scoring_run(session: Session, run_id: uuid.UUID) -> MlScoringRun | None:
    return session.get(MlScoringRun, run_id)


def all_artifact_paths(session: Session) -> set[str]:
    return set(session.scalars(select(MlModel.artifact_path)))


# --- classification results -----------------------------------------------------------------


def insert_classifications(session: Session, rows: list[dict[str, Any]]) -> int:
    if not rows:
        return 0
    stmt = (
        pg_insert(ClassificationResult)
        .on_conflict_do_nothing(index_elements=["event_id", "event_time", "model_id"])
        .returning(ClassificationResult.result_id)
    )
    return len(list(session.execute(stmt, rows)))


def classification_for_event(session: Session, event_id: int, event_time: datetime) -> list[Any]:
    return list(
        session.execute(
            select(ClassificationResult, MlModel.name, MlModel.version, MlModel.status, CAT.code)
            .join(MlModel, MlModel.model_id == ClassificationResult.model_id)
            .join(CAT, CAT.attack_category_id == ClassificationResult.predicted_category_id)
            .where(
                ClassificationResult.event_id == event_id,
                ClassificationResult.event_time == event_time,
            )
            .order_by(MlModel.name, MlModel.version.desc())
        )
    )


def list_classifications(
    session: Session,
    model_id: uuid.UUID,
    *,
    category: str | None,
    min_score: float | None,
    start: datetime | None,
    end: datetime | None,
    disagrees: bool,
    after: tuple[datetime, int] | None,
    limit: int,
) -> list[dict[str, Any]]:
    R = ClassificationResult
    gt_cat = CAT.__table__.alias("gt_cat")
    stmt = (
        select(
            R.result_id,
            R.event_id,
            R.event_time,
            R.predicted_score,
            R.class_scores,
            CAT.code.label("predicted_category"),
            gt_cat.c.code.label("ground_truth_category"),
        )
        .join(CAT, CAT.attack_category_id == R.predicted_category_id)
        .outerjoin(GT, and_(GT.event_id == R.event_id, GT.event_time == R.event_time))
        .outerjoin(gt_cat, gt_cat.c.attack_category_id == GT.attack_category_id)
        .where(R.model_id == model_id)
    )
    if category:
        stmt = stmt.where(CAT.code == category)
    if min_score is not None:
        stmt = stmt.where(R.predicted_score >= min_score)
    if start:
        stmt = stmt.where(R.event_time >= start)
    if end:
        stmt = stmt.where(R.event_time < end)
    if disagrees:
        stmt = stmt.where(gt_cat.c.code.is_not(None), gt_cat.c.code != CAT.code)
    if after:
        stmt = stmt.where(
            or_(R.event_time < after[0], and_(R.event_time == after[0], R.result_id < after[1]))
        )
    stmt = stmt.order_by(R.event_time.desc(), R.result_id.desc()).limit(limit)
    return [dict(r._mapping) for r in session.execute(stmt)]


def classification_summary(
    session: Session, model_id: uuid.UUID, start: datetime | None, end: datetime | None
) -> tuple[list[tuple[str, int]], list[tuple[str, str, int]]]:
    R = ClassificationResult
    gt_cat = CAT.__table__.alias("gt_cat")
    conds = [R.model_id == model_id]
    if start:
        conds.append(R.event_time >= start)
    if end:
        conds.append(R.event_time < end)
    counts = session.execute(
        select(CAT.code, func.count())
        .select_from(R)
        .join(CAT, CAT.attack_category_id == R.predicted_category_id)
        .where(*conds)
        .group_by(CAT.code)
        .order_by(CAT.code)
    ).all()
    pairs = session.execute(
        select(gt_cat.c.code, CAT.code, func.count())
        .select_from(R)
        .join(CAT, CAT.attack_category_id == R.predicted_category_id)
        .join(GT, and_(GT.event_id == R.event_id, GT.event_time == R.event_time))
        .join(gt_cat, gt_cat.c.attack_category_id == GT.attack_category_id)
        .where(*conds)
        .group_by(gt_cat.c.code, CAT.code)
    ).all()
    return [(c, int(n)) for c, n in counts], [(t, p, int(n)) for t, p, n in pairs]
