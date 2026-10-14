"""Job queue and worker tests (ARCHITECTURE.md §7, AC-1.7)."""

from __future__ import annotations

import threading
import uuid
from collections.abc import Callable
from datetime import timedelta

import pytest
from sqlalchemy import select, update
from sqlalchemy.orm import Session, sessionmaker

from app.core import clock
from app.core.config import get_settings
from app.core.security import Role
from app.jobs.registry import HANDLERS
from app.jobs.runtime import JobContext
from app.jobs.worker import Worker
from app.models import AuditLog, Job
from app.services import jobs as jobs_service
from app.services.actors import CLI_ACTOR
from tests.conftest import LoggedIn

pytestmark = pytest.mark.integration


def _worker(factory: sessionmaker[Session]) -> Worker:
    return Worker(factory, get_settings(), HANDLERS)


def _enqueue(
    factory: sessionmaker[Session],
    params: dict[str, object] | None = None,
    job_type: str = "diagnostic",
    max_attempts: int = 3,
) -> uuid.UUID:
    with factory() as session:
        job = jobs_service.enqueue(
            session, CLI_ACTOR, job_type, params or {"steps": 3}, max_attempts=max_attempts
        )
        return job.job_id


def _job(factory: sessionmaker[Session], job_id: uuid.UUID) -> Job:
    with factory() as session:
        job = session.get(Job, job_id)
        assert job is not None
        return job


def test_diagnostic_job_succeeds_with_progress(session_factory: sessionmaker[Session]) -> None:
    job_id = _enqueue(session_factory)
    assert _worker(session_factory).run_once() is True
    job = _job(session_factory, job_id)
    assert job.status == "succeeded"
    assert job.result == {"steps_completed": 3, "attempt": 1}
    assert job.progress == {"done": 3, "total": 3, "unit": "steps"}
    assert job.attempts == 1 and job.started_at and job.finished_at


def test_no_runnable_job_returns_false(session_factory: sessionmaker[Session]) -> None:
    assert _worker(session_factory).run_once() is False


def test_failing_job_records_error(session_factory: sessionmaker[Session]) -> None:
    job_id = _enqueue(session_factory, {"fail": True})
    _worker(session_factory).run_once()
    job = _job(session_factory, job_id)
    assert job.status == "failed"
    assert job.error is not None
    assert job.error["code"] == "handler_error"
    assert job.error["type"] == "DiagnosticFailureError"


def test_unknown_job_type_fails(session_factory: sessionmaker[Session]) -> None:
    job_id = _enqueue(session_factory, job_type="no_such_type")
    _worker(session_factory).run_once()
    job = _job(session_factory, job_id)
    assert job.status == "failed"
    assert job.error is not None and job.error["code"] == "unknown_job_type"


def test_transient_failure_is_retried_with_backoff(session_factory: sessionmaker[Session]) -> None:
    job_id = _enqueue(session_factory, {"transient_failures": 1, "steps": 1})
    worker = _worker(session_factory)
    start = clock.now()
    clock.set_clock(lambda: start)
    worker.run_once()
    job = _job(session_factory, job_id)
    assert job.status == "queued"
    assert job.run_after == start + timedelta(seconds=10)
    assert worker.run_once() is False  # back-off not yet elapsed
    clock.set_clock(lambda: start + timedelta(seconds=11))
    assert worker.run_once() is True
    job = _job(session_factory, job_id)
    assert job.status == "succeeded"
    assert job.attempts == 2


def test_transient_failures_exhaust_attempts(session_factory: sessionmaker[Session]) -> None:
    job_id = _enqueue(session_factory, {"transient_failures": 5}, max_attempts=2)
    worker = _worker(session_factory)
    start = clock.now()
    for offset in (0, 20):
        clock.set_clock(lambda o=offset: start + timedelta(seconds=o))
        worker.run_once()
    job = _job(session_factory, job_id)
    assert job.status == "failed"
    assert job.error is not None and job.error["code"] == "transient_error"
    assert job.attempts == 2


def test_cancel_queued_job(session_factory: sessionmaker[Session], db: Session) -> None:
    job_id = _enqueue(session_factory)
    job = jobs_service.cancel_job(db, CLI_ACTOR, job_id)
    assert job.status == "cancelled"
    assert _worker(session_factory).run_once() is False
    with pytest.raises(Exception, match="already cancelled"):
        jobs_service.cancel_job(db, CLI_ACTOR, job_id)


def test_running_job_observes_cancellation(session_factory: sessionmaker[Session]) -> None:
    job_id = _enqueue(session_factory, {"steps": 2})
    with session_factory() as session:
        claimed = jobs_service.claim_next(session)
    assert claimed is not None and claimed.job_id == job_id
    with session_factory() as session:
        jobs_service.cancel_job(session, CLI_ACTOR, job_id)
        assert jobs_service.heartbeat(session, job_id) is True  # heartbeat reports the request
    ctx = JobContext(job_id, "diagnostic", {"steps": 2}, 1, session_factory)
    ctx.cancel_event.set()
    from app.jobs.runtime import JobCancelledError

    with pytest.raises(JobCancelledError):
        HANDLERS["diagnostic"](ctx)
    with session_factory() as session:
        jobs_service.mark_cancelled(session, job_id)
    assert _job(session_factory, job_id).status == "cancelled"


def test_stale_running_job_is_failed_with_worker_timeout(
    session_factory: sessionmaker[Session],
) -> None:
    job_id = _enqueue(session_factory)
    with session_factory() as session:
        jobs_service.claim_next(session)
    later = clock.now() + timedelta(seconds=get_settings().job_timeout_seconds + 1)
    clock.set_clock(lambda: later)
    _worker(session_factory).reap_stale()
    job = _job(session_factory, job_id)
    assert job.status == "failed"
    assert job.error is not None and job.error["code"] == "worker_timeout"


def test_concurrent_workers_never_claim_the_same_job(
    committed_db: sessionmaker[Session],
) -> None:
    job_ids = {_enqueue(committed_db, {"steps": 1}) for _ in range(20)}
    claimed: list[uuid.UUID] = []
    lock = threading.Lock()
    barrier = threading.Barrier(4)

    def claim_all() -> None:
        barrier.wait()
        while True:
            with committed_db() as session:
                job = jobs_service.claim_next(session)
            if job is None:
                return
            with lock:
                claimed.append(job.job_id)

    threads = [threading.Thread(target=claim_all) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(claimed) == sorted(job_ids)  # every job exactly once
    assert len(set(claimed)) == len(claimed)


def test_enqueue_is_audited(session_factory: sessionmaker[Session], db: Session) -> None:
    job_id = _enqueue(session_factory)
    rows = db.scalars(select(AuditLog).where(AuditLog.action == "job.enqueue")).all()
    assert [r.target_id for r in rows] == [str(job_id)]
    assert rows[0].actor_type == "cli"


# --- API -------------------------------------------------------------------------------------


def test_get_job_via_api(
    session_factory: sessionmaker[Session], login: Callable[..., LoggedIn]
) -> None:
    job_id = _enqueue(session_factory)
    _worker(session_factory).run_once()
    viewer = login("vic")
    resp = viewer.client.get(f"/api/v1/jobs/{job_id}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "succeeded"
    assert body["progress"] == {"done": 3, "total": 3, "unit": "steps"}
    assert viewer.client.get(f"/api/v1/jobs/{uuid.uuid4()}").status_code == 404


def test_list_jobs_filters_and_pagination(
    session_factory: sessionmaker[Session], login: Callable[..., LoggedIn]
) -> None:
    ids = [_enqueue(session_factory) for _ in range(5)]
    _worker(session_factory).run_once()  # oldest job succeeds
    viewer = login("vic")
    queued = viewer.client.get("/api/v1/jobs", params={"status": "queued"}).json()["items"]
    assert {j["job_id"] for j in queued} == {str(i) for i in ids[1:]}
    seen: list[str] = []
    cursor = None
    while True:
        params: dict[str, object] = {"limit": 2}
        if cursor:
            params["cursor"] = cursor
        page = viewer.client.get("/api/v1/jobs", params=params).json()
        seen += [j["job_id"] for j in page["items"]]
        cursor = page["next_cursor"]
        if not cursor:
            break
    assert sorted(seen) == sorted(str(i) for i in ids) and len(seen) == len(set(seen))
    assert viewer.client.get("/api/v1/jobs", params={"status": "bogus"}).status_code == 422
    assert viewer.client.get("/api/v1/jobs", params={"order": "x"}).status_code == 422


def test_cancel_via_api(
    session_factory: sessionmaker[Session], login: Callable[..., LoggedIn]
) -> None:
    job_id = _enqueue(session_factory)
    admin = login("root", Role.ADMIN)
    resp = admin.client.post(f"/api/v1/jobs/{job_id}/cancel", headers=admin.headers())
    assert resp.status_code == 200 and resp.json()["status"] == "cancelled"
    again = admin.client.post(f"/api/v1/jobs/{job_id}/cancel", headers=admin.headers())
    assert again.status_code == 409


def test_progress_is_not_written_after_job_finished(
    session_factory: sessionmaker[Session],
) -> None:
    job_id = _enqueue(session_factory)
    _worker(session_factory).run_once()
    with session_factory() as session:
        session.execute(update(Job).where(Job.job_id == job_id).values(progress=None))
        session.commit()
    ctx = JobContext(job_id, "diagnostic", {}, 1, session_factory)
    ctx.report_progress(1, 1, "steps")
    assert _job(session_factory, job_id).progress is None


def test_transient_failure_after_cancel_request_is_not_retried(
    session_factory: sessionmaker[Session],
) -> None:
    job_id = _enqueue(session_factory, {"transient_failures": 5})
    with session_factory() as session:
        claimed = jobs_service.claim_next(session)
        assert claimed is not None
        jobs_service.cancel_job(session, CLI_ACTOR, job_id)  # sets cancel_requested
        outcome = jobs_service.retry_or_fail(
            session, claimed, {"code": "transient_error", "message": "x"}
        )
    assert outcome == "cancelled"
    assert _job(session_factory, job_id).status == "cancelled"
    assert _worker(session_factory).run_once() is False
