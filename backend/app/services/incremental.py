"""Incremental downstream processing driven by watermarks (ARCHITECTURE.md §7, Phase 8).

Each consumer remembers the newest ingestion batch it has processed (completion time plus
the batch IDs completed at that instant). A run handles only batches completed after the
watermark, so a second run with no new data does nothing. Consumers run in dependency order:
indicator matching and classifier scoring before correlation, which re-evaluates the event
time span of the new batches plus each rule's window (look-back for late evidence).
"""

from __future__ import annotations

import contextlib
import uuid
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import Engine, func, or_, select
from sqlalchemy.orm import Session, sessionmaker

from app.core import clock
from app.core.config import Settings
from app.core.errors import NotFoundError
from app.models import FactSecurityEvent, IngestionBatch, MlModel, ProcessingWatermark
from app.services import anomaly, audit, classification, correlation, threat_intel, web_payload
from app.services.actors import Actor

CONSUMERS = (
    "indicator_matching",
    "classifier_scoring",
    "anomaly_scoring",
    "web_payload_scoring",
    "correlation",
)
# Consumers that need an active model of this name; without one they wait (no advance).
NEEDS_MODEL = {
    "classifier_scoring": "attack_classifier",
    "web_payload_scoring": "web_attack_classifier",
}
SCHEDULE_LOCK = "cti.incremental_processing"
DONE_STATUSES = ("completed", "completed_with_errors")
WINDOW = {"15m": timedelta(minutes=15), "1h": timedelta(hours=1), "1d": timedelta(days=1)}


def _pending(session: Session, consumer: str) -> tuple[list[IngestionBatch], ProcessingWatermark]:
    mark = session.get(ProcessingWatermark, consumer, with_for_update=True)
    if mark is None:
        mark = ProcessingWatermark(consumer=consumer, details={})
        session.add(mark)
        session.flush()
    stmt = select(IngestionBatch).where(
        IngestionBatch.status.in_(DONE_STATUSES), IngestionBatch.finished_at.is_not(None)
    )
    if mark.last_ingested_at is not None:
        seen = [uuid.UUID(b) for b in mark.details.get("batch_ids_at_watermark", [])]
        stmt = stmt.where(
            or_(
                IngestionBatch.finished_at > mark.last_ingested_at,
                (IngestionBatch.finished_at == mark.last_ingested_at)
                & IngestionBatch.batch_id.not_in(seen or [uuid.UUID(int=0)]),
            )
        )
    batches = list(
        session.scalars(stmt.order_by(IngestionBatch.finished_at, IngestionBatch.batch_id))
    )
    return batches, mark


def _advance(
    mark: ProcessingWatermark, batches: list[IngestionBatch], extra: dict[str, Any]
) -> None:
    latest = max(b.finished_at for b in batches if b.finished_at is not None)
    same = [str(b.batch_id) for b in batches if b.finished_at == latest]
    if mark.last_ingested_at == latest:
        same = sorted(set(same) | set(mark.details.get("batch_ids_at_watermark", [])))
    mark.last_ingested_at = latest
    mark.details = {
        "batch_ids_at_watermark": same,
        "last_run": extra,
        "batches_processed_total": int(mark.details.get("batches_processed_total", 0))
        + len(batches),
    }
    mark.updated_at = clock.now()


def _event_span(session: Session, batch_ids: list[uuid.UUID]) -> tuple[datetime, datetime] | None:
    F = FactSecurityEvent
    lo, hi = session.execute(
        select(func.min(F.event_time), func.max(F.event_time)).where(F.batch_id.in_(batch_ids))
    ).one()
    return (lo, hi) if lo is not None else None


def run_consumer(
    factory: sessionmaker[Session], settings: Settings, actor: Actor, consumer: str
) -> dict[str, Any]:
    if consumer not in CONSUMERS:
        raise NotFoundError(f"unknown consumer {consumer!r}")
    with factory() as session, session.begin():
        batches, _ = _pending(session, consumer)
        batch_ids = [b.batch_id for b in batches]
        span = _event_span(session, batch_ids) if batch_ids else None
    result: dict[str, Any] = {"consumer": consumer, "new_batches": len(batch_ids)}
    if not batch_ids:
        result["status"] = "up_to_date"
        return result

    if span is None:
        result["status"] = "no_events_in_new_batches"
    elif consumer == "indicator_matching":
        out = threat_intel.run_match(
            factory, {"batch_ids": [str(b) for b in batch_ids], "include_expired": False}, None
        )
        result |= {"status": "processed", "matches_created": out["matches_created"]}
    elif consumer == "classifier_scoring":
        with factory() as session:
            active = session.scalar(
                select(MlModel.model_id).where(
                    MlModel.name == "attack_classifier", MlModel.status == "active"
                )
            )
        if active is None:
            # Nothing can be scored; do not advance, so the batches are scored once a model
            # is promoted.
            result["status"] = "skipped_no_active_classifier"
            return result
        with factory() as session:
            run = classification.start_scoring(
                session, actor, {"batch_ids": [str(b) for b in batch_ids]}, None, enqueue=False
            )
        done = classification.run_scoring(factory, settings, run.scoring_run_id)
        result |= {"status": "processed", "rows_scored": done.rows_scored}
    elif consumer == "web_payload_scoring":
        with factory() as session:
            active = session.scalar(
                select(MlModel.model_id).where(
                    MlModel.name == web_payload.MODEL_NAME, MlModel.status == "active"
                )
            )
        if active is None:
            result["status"] = "skipped_no_active_web_payload_model"
            return result
        with factory() as session:
            run = web_payload.start_scoring(
                session, actor, {"batch_ids": [str(b) for b in batch_ids]}, None, enqueue=False
            )
        done = web_payload.run_scoring(factory, settings, run.scoring_run_id)
        result |= {"status": "processed", "parameters_scored": done.rows_scored}
    elif consumer == "anomaly_scoring":
        with factory() as session:
            models = list(
                session.execute(
                    select(MlModel.model_id, MlModel.name).where(
                        MlModel.task == "anomaly", MlModel.status == "active"
                    )
                )
            )
        scored = {}
        start, end = span
        for model_id, name in models:
            with factory() as session:
                run = anomaly.start_scoring(
                    session,
                    actor,
                    start=start - timedelta(days=1),
                    end=end + timedelta(seconds=1),
                    model_id=model_id,
                    name=None,
                    enqueue=False,
                )
            done = anomaly.run_scoring(factory, settings, run.scoring_run_id)
            scored[name] = done.rows_scored
        result |= {"status": "processed", "windows_scored": scored}
    else:  # correlation
        start, end = span
        with factory() as session:
            summary = correlation.run_correlation(session, actor, start, end + timedelta(seconds=1))
        result |= {
            "status": "processed",
            "alerts_created": summary["alerts_created"],
            "alerts_updated": summary["alerts_updated"],
        }

    with factory() as session, session.begin():
        batches, mark = _pending(session, consumer)
        processed = [b for b in batches if b.batch_id in set(batch_ids)]
        if processed:
            _advance(mark, processed, {k: v for k, v in result.items() if k != "consumer"})
        audit.record(
            session,
            actor,
            "incremental.processed",
            target_type="processing_watermark",
            target_id=consumer,
            details=result,
        )
    return result


def run_all(
    factory: sessionmaker[Session], settings: Settings, actor: Actor
) -> list[dict[str, Any]]:
    return [run_consumer(factory, settings, actor, c) for c in CONSUMERS]


def has_actionable_work(session: Session) -> bool:
    """True if some consumer has new batches it can process now (used by the scheduler).

    Consumers waiting for a model that is not active do not count, so an idle system does
    not queue a no-op job every interval.
    """
    with session.begin():
        active = set(session.scalars(select(MlModel.name).where(MlModel.status == "active")))
        for consumer in CONSUMERS:
            needed = NEEDS_MODEL.get(consumer)
            if needed is not None and needed not in active:
                continue
            batches, _ = _pending(session, consumer)
            if batches:
                return True
    return False


def run_exclusive(
    factory: sessionmaker[Session], settings: Settings, actor: Actor
) -> dict[str, Any]:
    """``run_all`` under a session-level advisory lock: concurrent runs (several workers,
    or a scheduled run next to ``cti process``) never process the same batches twice.

    The lock is held on one dedicated connection in autocommit mode for the whole run, so
    no transaction stays open while the consumers work.
    """
    bind = factory.kw["bind"]
    with contextlib.ExitStack() as stack:
        if isinstance(bind, Engine):
            conn = stack.enter_context(
                bind.connect().execution_options(isolation_level="AUTOCOMMIT")
            )
        else:  # a single shared connection (test harness)
            conn = bind
        key = func.hashtext(SCHEDULE_LOCK)
        if not conn.scalar(select(func.pg_try_advisory_lock(key))):
            return {"status": "already_running"}
        try:
            return {"status": "processed", "consumers": run_all(factory, settings, actor)}
        finally:
            conn.scalar(select(func.pg_advisory_unlock(key)))


def watermarks(session: Session) -> list[dict[str, Any]]:
    with session.begin():
        rows = {w.consumer: w for w in session.scalars(select(ProcessingWatermark))}
        return [
            {
                "consumer": c,
                "last_ingested_at": rows[c].last_ingested_at if c in rows else None,
                "details": rows[c].details if c in rows else {},
                "updated_at": rows[c].updated_at if c in rows else None,
            }
            for c in CONSUMERS
        ]
