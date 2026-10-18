"""The ``cti worker`` loop: claims queued jobs with SKIP LOCKED and runs their handlers."""

from __future__ import annotations

import logging
import threading
import time
from datetime import timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.exc import DBAPIError, OperationalError
from sqlalchemy.orm import Session, sessionmaker

from app.core import clock
from app.core.config import Settings
from app.core.logging import job_id_var, redact_text
from app.jobs.runtime import JobCancelledError, JobContext, JobHandler, TransientJobError
from app.services import jobs as jobs_service
from app.services.jobs import ClaimedJob

log = logging.getLogger(__name__)

ERROR_MESSAGE_MAX = 500
SCHEDULED_JOB = "incremental.process"
SCHEDULE_ENQUEUE_LOCK = "cti.schedule_processing"


def _error(code: str, exc: BaseException) -> dict[str, Any]:
    return {
        "code": code,
        "type": exc.__class__.__name__,
        "message": redact_text(str(exc))[:ERROR_MESSAGE_MAX],
    }


class Worker:
    def __init__(
        self,
        session_factory: sessionmaker[Session],
        settings: Settings,
        handlers: dict[str, JobHandler],
    ) -> None:
        self.session_factory = session_factory
        self.settings = settings
        self.handlers = handlers

    # -- single job ---------------------------------------------------------------------

    def run_once(self) -> bool:
        """Claim and execute one job. Returns False when nothing was runnable."""
        with self.session_factory() as session:
            job = jobs_service.claim_next(session)
        if job is None:
            return False
        token = job_id_var.set(str(job.job_id))
        try:
            self._execute(job)
        finally:
            job_id_var.reset(token)
        return True

    def _execute(self, job: ClaimedJob) -> None:
        handler = self.handlers.get(job.job_type)
        log.info("job started", extra={"job_type": job.job_type, "attempt": job.attempts})
        with self.session_factory() as session:
            if handler is None:
                jobs_service.mark_failed(
                    session,
                    job.job_id,
                    {"code": "unknown_job_type", "message": f"no handler for {job.job_type!r}"},
                )
                log.error("unknown job type", extra={"job_type": job.job_type})
                return

        ctx = JobContext(job.job_id, job.job_type, job.params, job.attempts, self.session_factory)
        stop_heartbeat = threading.Event()
        beat = threading.Thread(
            target=self._heartbeat_loop,
            args=(ctx, stop_heartbeat),
            name=f"heartbeat-{job.job_id}",
            daemon=True,
        )
        beat.start()
        try:
            result = handler(ctx)
        except JobCancelledError:
            outcome = "cancelled"
            with self.session_factory() as session:
                jobs_service.mark_cancelled(session, job.job_id)
        except (TransientJobError, OperationalError) as exc:
            with self.session_factory() as session:
                outcome = jobs_service.retry_or_fail(session, job, _error("transient_error", exc))
            log.warning("job transient failure", extra={"outcome": outcome})
        except DBAPIError as exc:
            outcome = "failed"
            with self.session_factory() as session:
                jobs_service.mark_failed(session, job.job_id, _error("database_error", exc))
            log.exception("job failed with database error")
        except Exception as exc:
            outcome = "failed"
            with self.session_factory() as session:
                jobs_service.mark_failed(session, job.job_id, _error("handler_error", exc))
            log.exception("job failed")
        else:
            outcome = "succeeded"
            with self.session_factory() as session:
                jobs_service.mark_succeeded(session, job.job_id, result)
        finally:
            stop_heartbeat.set()
            beat.join(timeout=5)
        log.info("job finished", extra={"job_type": job.job_type, "outcome": outcome})

    def _heartbeat_loop(self, ctx: JobContext, stop: threading.Event) -> None:
        while not stop.wait(self.settings.job_heartbeat_seconds):
            try:
                with self.session_factory() as session:
                    cancel = jobs_service.heartbeat(session, ctx.job_id)
            except Exception:
                log.exception("heartbeat failed")
                continue
            if cancel:
                ctx.cancel_event.set()

    # -- loop ---------------------------------------------------------------------------

    def reap_stale(self) -> None:
        with self.session_factory() as session:
            failed = jobs_service.fail_stale(
                session, timedelta(seconds=self.settings.job_timeout_seconds)
            )
        for job_id in failed:
            log.error("job marked failed: worker_timeout", extra={"stale_job_id": str(job_id)})

    def schedule_processing(self) -> bool:
        """Queue one ``incremental.process`` job if there is work and none is pending.

        Serialised across workers by a transaction-scoped advisory lock. Returns True if a
        job was queued.
        """
        from app.services import incremental
        from app.services.actors import SYSTEM_ACTOR

        with self.session_factory() as session:
            if not incremental.has_actionable_work(session):
                return False
            with session.begin():
                session.execute(
                    select(func.pg_advisory_xact_lock(func.hashtext(SCHEDULE_ENQUEUE_LOCK)))
                )
                if jobs_service.has_open_job(session, SCHEDULED_JOB):
                    return False
                jobs_service.enqueue_in_transaction(
                    session, SYSTEM_ACTOR, SCHEDULED_JOB, {"trigger": "schedule"}, max_attempts=1
                )
        return True

    def _slot_loop(self, stop: threading.Event) -> None:
        while not stop.is_set():
            try:
                worked = self.run_once()
            except Exception:
                log.exception("worker slot error")
                worked = False
            if not worked:
                stop.wait(self.settings.worker_poll_seconds)

    def run_forever(self, stop: threading.Event, heartbeat_file: Path | None = None) -> None:
        slots = [
            threading.Thread(target=self._slot_loop, args=(stop,), name=f"worker-slot-{i}")
            for i in range(self.settings.max_concurrent_jobs)
        ]
        for slot in slots:
            slot.start()
        log.info("worker started", extra={"slots": len(slots)})
        interval = self.settings.schedule_processing_seconds
        next_schedule = time.monotonic() + min(interval, 10)
        try:
            while not stop.is_set():
                try:
                    self.reap_stale()
                except Exception:
                    log.exception("stale-job reaper failed")
                if interval and time.monotonic() >= next_schedule:
                    next_schedule = time.monotonic() + interval
                    try:
                        if self.schedule_processing():
                            log.info("scheduled incremental processing queued")
                    except Exception:
                        log.exception("processing scheduler failed")
                if heartbeat_file is not None:
                    heartbeat_file.write_text(clock.now().isoformat(), encoding="utf-8")
                stop.wait(self.settings.worker_poll_seconds)
        finally:
            stop.set()
            for slot in slots:
                slot.join()
            log.info("worker stopped")


def heartbeat_is_fresh(path: Path, max_age_seconds: float) -> bool:
    try:
        return time.time() - path.stat().st_mtime <= max_age_seconds
    except OSError:
        return False
