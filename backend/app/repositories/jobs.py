"""Queries for the PostgreSQL-backed job queue (ARCHITECTURE.md §7)."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import and_, or_, select, update
from sqlalchemy.orm import Session

from app.models import Job


def get_job(session: Session, job_id: uuid.UUID, *, for_update: bool = False) -> Job | None:
    stmt = select(Job).where(Job.job_id == job_id)
    if for_update:
        stmt = stmt.with_for_update()
    return session.scalar(stmt)


def list_jobs(
    session: Session,
    *,
    statuses: list[str] | None,
    job_type: str | None,
    created_after: datetime | None,
    after: tuple[datetime, uuid.UUID] | None,
    limit: int,
) -> list[Job]:
    stmt = select(Job).order_by(Job.created_at.desc(), Job.job_id.desc()).limit(limit)
    if statuses:
        stmt = stmt.where(Job.status.in_(statuses))
    if job_type is not None:
        stmt = stmt.where(Job.job_type == job_type)
    if created_after is not None:
        stmt = stmt.where(Job.created_at > created_after)
    if after is not None:
        created_at, job_id = after
        stmt = stmt.where(
            or_(
                Job.created_at < created_at, and_(Job.created_at == created_at, Job.job_id < job_id)
            )
        )
    return list(session.scalars(stmt))


def claim_next_job(session: Session, now: datetime) -> Job | None:
    """Atomically move the oldest runnable queued job to ``running``.

    ``FOR UPDATE SKIP LOCKED`` guarantees concurrent workers never claim the same job.
    """
    candidate = (
        select(Job.job_id)
        .where(Job.status == "queued", Job.run_after <= now)
        .order_by(Job.created_at)
        .limit(1)
        .with_for_update(skip_locked=True)
        .scalar_subquery()
    )
    stmt = (
        update(Job)
        .where(Job.job_id == candidate)
        .values(
            status="running",
            attempts=Job.attempts + 1,
            started_at=now,
            heartbeat_at=now,
            updated_at=now,
        )
        .returning(Job)
    )
    return session.scalars(stmt).one_or_none()


def heartbeat(session: Session, job_id: uuid.UUID, now: datetime) -> bool | None:
    """Refresh the heartbeat; returns ``cancel_requested`` or ``None`` if no longer running."""
    row = session.execute(
        update(Job)
        .where(Job.job_id == job_id, Job.status == "running")
        .values(heartbeat_at=now, updated_at=now)
        .returning(Job.cancel_requested)
    ).one_or_none()
    return None if row is None else bool(row[0])


def set_progress(
    session: Session, job_id: uuid.UUID, progress: dict[str, Any], now: datetime
) -> None:
    session.execute(
        update(Job)
        .where(Job.job_id == job_id, Job.status == "running")
        .values(progress=progress, heartbeat_at=now, updated_at=now)
    )


def finish_job(
    session: Session,
    job_id: uuid.UUID,
    *,
    status: str,
    now: datetime,
    result: dict[str, Any] | None = None,
    error: dict[str, Any] | None = None,
) -> None:
    session.execute(
        update(Job)
        .where(Job.job_id == job_id, Job.status == "running")
        .values(status=status, result=result, error=error, finished_at=now, updated_at=now)
    )


def requeue_job(
    session: Session,
    job_id: uuid.UUID,
    *,
    run_after: datetime,
    error: dict[str, Any],
    now: datetime,
) -> bool:
    """Requeue a running job unless cancellation was requested. Returns True if requeued."""
    result = session.execute(
        update(Job)
        .where(Job.job_id == job_id, Job.status == "running", Job.cancel_requested.is_(False))
        .values(
            status="queued", run_after=run_after, error=error, heartbeat_at=None, updated_at=now
        )
    )
    return bool(result.rowcount)  # type: ignore[attr-defined]


def fail_stale_jobs(session: Session, now: datetime, timeout: timedelta) -> list[uuid.UUID]:
    rows = session.execute(
        update(Job)
        .where(Job.status == "running", Job.heartbeat_at < now - timeout)
        .values(
            status="failed",
            error={"code": "worker_timeout", "message": "no heartbeat within the job timeout"},
            finished_at=now,
            updated_at=now,
        )
        .returning(Job.job_id)
    )
    return [r[0] for r in rows]
