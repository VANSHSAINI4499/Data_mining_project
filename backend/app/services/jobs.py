"""Job queue use cases: enqueueing, querying, cancelling, and the worker-facing transitions."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy.orm import Session

from app.core import clock
from app.core.errors import ConflictError, FieldError, NotFoundError, ValidationFailedError
from app.core.pagination import DEFAULT_LIMIT, decode_cursor, encode_cursor
from app.models import Job
from app.repositories import jobs as jobs_repo
from app.services import audit
from app.services.actors import Actor

TERMINAL_STATUSES = frozenset({"succeeded", "failed", "cancelled"})
# Back-off before attempt 2, 3, ... (DATA_INGESTION.md §8).
RETRY_BACKOFF = (timedelta(seconds=10), timedelta(seconds=60), timedelta(seconds=300))


@dataclass(frozen=True)
class ClaimedJob:
    """Snapshot of a job claimed by a worker (decoupled from the ORM session)."""

    job_id: uuid.UUID
    job_type: str
    params: dict[str, Any]
    attempts: int
    max_attempts: int


@dataclass(frozen=True)
class JobPage:
    items: list[Job]
    next_cursor: str | None
    limit: int


def enqueue_in_transaction(
    session: Session,
    actor: Actor,
    job_type: str,
    params: dict[str, Any],
    *,
    max_attempts: int = 3,
) -> Job:
    """Create a queued job inside the caller's open transaction (with its audit row)."""
    job = Job(
        job_id=uuid.uuid4(),
        job_type=job_type,
        status="queued",
        params=params,
        max_attempts=max_attempts,
        run_after=clock.now(),
        created_by=actor.user_id,
    )
    session.add(job)
    session.flush()
    audit.record(
        session,
        actor,
        "job.enqueue",
        target_type="job",
        target_id=job.job_id,
        details={"job_type": job_type},
    )
    return job


def enqueue(
    session: Session, actor: Actor, job_type: str, params: dict[str, Any], *, max_attempts: int = 3
) -> Job:
    with session.begin():
        return enqueue_in_transaction(session, actor, job_type, params, max_attempts=max_attempts)


def get_job(session: Session, job_id: uuid.UUID) -> Job:
    with session.begin():
        job = jobs_repo.get_job(session, job_id)
    if job is None:
        raise NotFoundError(f"job {job_id} not found")
    return job


def list_jobs(
    session: Session,
    *,
    statuses: list[str] | None = None,
    job_type: str | None = None,
    created_after: datetime | None = None,
    cursor: str | None = None,
    limit: int = DEFAULT_LIMIT,
) -> JobPage:
    key = decode_cursor(cursor, frozenset({"created_at", "job_id"}))
    after = None
    if key is not None:
        try:
            after = (datetime.fromisoformat(key["created_at"]), uuid.UUID(key["job_id"]))
        except (TypeError, ValueError) as exc:
            raise ValidationFailedError(
                "invalid cursor",
                errors=[FieldError("cursor", "invalid_cursor", "malformed cursor")],
            ) from exc
    with session.begin():
        rows = jobs_repo.list_jobs(
            session,
            statuses=statuses,
            job_type=job_type,
            created_after=created_after,
            after=after,
            limit=limit + 1,
        )
    items = rows[:limit]
    next_cursor = None
    if len(rows) > limit:
        last = items[-1]
        next_cursor = encode_cursor(
            {"created_at": last.created_at.isoformat(), "job_id": str(last.job_id)}
        )
    return JobPage(items, next_cursor, limit)


def cancel_job(session: Session, actor: Actor, job_id: uuid.UUID) -> Job:
    """Queued jobs are cancelled immediately; running jobs are asked to stop cooperatively."""
    with session.begin():
        job = jobs_repo.get_job(session, job_id, for_update=True)
        if job is None:
            raise NotFoundError(f"job {job_id} not found")
        if job.status in TERMINAL_STATUSES:
            raise ConflictError(f"job is already {job.status}")
        now = clock.now()
        previous_status = job.status
        if job.status == "queued":
            job.status = "cancelled"
            job.finished_at = now
        else:
            job.cancel_requested = True
        job.updated_at = now
        audit.record(
            session,
            actor,
            "job.cancel",
            target_type="job",
            target_id=job.job_id,
            details={"status_at_request": previous_status},
        )
    return job


# --- worker-facing transitions (each in its own short transaction) -------------------------


def claim_next(session: Session) -> ClaimedJob | None:
    with session.begin():
        job = jobs_repo.claim_next_job(session, clock.now())
        if job is None:
            return None
        return ClaimedJob(
            job.job_id, job.job_type, dict(job.params), job.attempts, job.max_attempts
        )


def heartbeat(session: Session, job_id: uuid.UUID) -> bool | None:
    with session.begin():
        return jobs_repo.heartbeat(session, job_id, clock.now())


def report_progress(session: Session, job_id: uuid.UUID, progress: dict[str, Any]) -> None:
    with session.begin():
        jobs_repo.set_progress(session, job_id, progress, clock.now())


def mark_succeeded(session: Session, job_id: uuid.UUID, result: dict[str, Any]) -> None:
    with session.begin():
        jobs_repo.finish_job(session, job_id, status="succeeded", now=clock.now(), result=result)


def mark_cancelled(session: Session, job_id: uuid.UUID) -> None:
    with session.begin():
        jobs_repo.finish_job(
            session,
            job_id,
            status="cancelled",
            now=clock.now(),
            error={"code": "cancelled", "message": "cancelled on request"},
        )


def mark_failed(session: Session, job_id: uuid.UUID, error: dict[str, Any]) -> None:
    with session.begin():
        jobs_repo.finish_job(session, job_id, status="failed", now=clock.now(), error=error)


def retry_or_fail(session: Session, job: ClaimedJob, error: dict[str, Any]) -> str:
    """Requeue a transient failure with back-off, or fail when attempts are exhausted."""
    if job.attempts >= job.max_attempts:
        mark_failed(session, job.job_id, {**error, "attempts": job.attempts})
        return "failed"
    delay = RETRY_BACKOFF[min(job.attempts, len(RETRY_BACKOFF)) - 1]
    now = clock.now()
    with session.begin():
        requeued = jobs_repo.requeue_job(
            session,
            job.job_id,
            run_after=now + delay,
            error={**error, "attempts": job.attempts},
            now=now,
        )
    if not requeued:  # cancellation was requested while it ran: honour it, don't retry
        mark_cancelled(session, job.job_id)
        return "cancelled"
    return "queued"


def fail_stale(session: Session, timeout: timedelta) -> list[uuid.UUID]:
    with session.begin():
        return jobs_repo.fail_stale_jobs(session, clock.now(), timeout)
