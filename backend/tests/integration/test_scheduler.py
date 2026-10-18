"""Worker scheduler for incremental processing, and the web payload consumer."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import Engine, func, select, text
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings
from app.jobs.registry import HANDLERS
from app.jobs.worker import SCHEDULED_JOB, Worker
from app.models import Alert, Job, WebPayloadResult
from app.services import incremental
from app.services import models as models_service
from app.services.actors import CLI_ACTOR
from tests.integration.test_web_payload_scoring import access_log, trained  # noqa: F401

pytestmark = pytest.mark.integration


def _jobs(db: Session) -> list[Job]:
    with db.begin():
        rows = list(db.scalars(select(Job).where(Job.job_type == SCHEDULED_JOB)))
        for job in rows:
            db.expunge(job)
        return rows


def test_scheduler_queues_one_job_only_when_there_is_work(
    session_factory: sessionmaker[Session],
    db: Session,
    trained: uuid.UUID,  # noqa: F811
    access_log: None,  # noqa: F811
) -> None:
    worker = Worker(session_factory, get_settings(), HANDLERS)
    # A batch is waiting for matching and correlation.
    assert worker.schedule_processing() is True
    assert worker.schedule_processing() is False  # one open job is enough
    assert [j.status for j in _jobs(db)] == ["queued"]

    while worker.run_once():
        pass
    job = _jobs(db)[0]
    assert job.status == "succeeded" and job.result is not None
    steps = {c["consumer"]: c for c in job.result["consumers"]}
    # No active web payload model yet: that consumer waits instead of advancing.
    assert steps["web_payload_scoring"]["status"] == "skipped_no_active_web_payload_model"
    assert steps["correlation"]["status"] == "processed"
    # Consumers waiting for a model do not count as work, so nothing new is queued.
    assert worker.schedule_processing() is False

    # Promoting the model makes the waiting batch actionable again.
    with session_factory() as session:
        models_service.promote(session, CLI_ACTOR, trained)
    assert worker.schedule_processing() is True
    while worker.run_once():
        pass
    # Same test transaction, so created_at is equal: pick the job that is not the first.
    (latest,) = [j for j in _jobs(db) if j.job_id != job.job_id]
    assert latest.result is not None
    steps = {c["consumer"]: c for c in latest.result["consumers"]}
    assert steps["web_payload_scoring"] == {
        "consumer": "web_payload_scoring",
        "new_batches": 1,
        "status": "processed",
        "parameters_scored": 7,
    }
    with db.begin():
        assert db.scalar(select(func.count()).select_from(WebPayloadResult)) == 7
    assert worker.schedule_processing() is False


def test_uploaded_access_log_is_scored_and_correlated_without_manual_steps(
    session_factory: sessionmaker[Session],
    db: Session,
    trained: uuid.UUID,  # noqa: F811
    access_log: None,  # noqa: F811
) -> None:
    with session_factory() as session:
        models_service.promote(session, CLI_ACTOR, trained)
    out = incremental.run_exclusive(session_factory, get_settings(), CLI_ACTOR)
    assert out["status"] == "processed"
    steps = {c["consumer"]: c for c in out["consumers"]}
    assert steps["web_payload_scoring"]["parameters_scored"] == 7
    # Correlation runs after scoring in the same pass, so the web rule sees the evidence.
    assert steps["correlation"]["status"] == "processed"
    with db.begin():
        titles = list(db.scalars(select(Alert.title)))
    assert any(t.startswith("Repeated attack-like web request parameters") for t in titles)


def test_concurrent_run_reports_already_running(
    engine: Engine, committed_db: sessionmaker[Session]
) -> None:
    with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as holder:
        key = func.hashtext(incremental.SCHEDULE_LOCK)
        assert holder.scalar(select(func.pg_try_advisory_lock(key))) is True
        try:
            out = incremental.run_exclusive(committed_db, get_settings(), CLI_ACTOR)
            assert out == {"status": "already_running"}
        finally:
            holder.execute(
                text("SELECT pg_advisory_unlock(hashtext(:k))"), {"k": incremental.SCHEDULE_LOCK}
            )


def test_idle_system_queues_nothing(session_factory: sessionmaker[Session], db: Session) -> None:
    worker = Worker(session_factory, get_settings(), HANDLERS)
    assert worker.schedule_processing() is False
    assert _jobs(db) == []
