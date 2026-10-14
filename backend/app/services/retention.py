"""Retention policy (DATABASE_DESIGN.md §9), executed only by ``cti retention apply``.

``dry_run`` counts what would be removed without changing anything. Every execution (dry run
or not) is audited with its counts. Events, raw records, ground truth, feedback, and alert
evidence are never deleted here; model artifacts are handled by ``cti artifacts gc``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import Select, delete, exists, func, or_, select
from sqlalchemy.orm import Session

from app.core import clock
from app.core.config import Settings
from app.models import (
    AuditLog,
    AuthSession,
    IndicatorMatch,
    IngestionBatch,
    Job,
    MlScoringRun,
    MlTrainingRun,
    RejectedRecord,
    TiFeedRun,
)
from app.services import audit
from app.services.actors import Actor

FINISHED_BATCH_STATUSES = ("completed", "completed_with_errors", "duplicate")
JOB_REFERENCES = (
    IngestionBatch.job_id,
    MlTrainingRun.job_id,
    MlScoringRun.job_id,
    TiFeedRun.job_id,
    IndicatorMatch.job_id,
)


@dataclass
class RetentionReport:
    dry_run: bool
    cutoffs: dict[str, str] = field(default_factory=dict)
    counts: dict[str, int] = field(default_factory=dict)
    skipped: dict[str, str] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "dry_run": self.dry_run,
            "cutoffs": self.cutoffs,
            "counts": self.counts,
            "skipped": self.skipped,
        }


def _count(session: Session, stmt: Select[Any]) -> int:
    return int(session.scalar(select(func.count()).select_from(stmt.subquery())) or 0)


def _unreferenced_job(*conds: Any) -> list[Any]:
    out = list(conds)
    for column in JOB_REFERENCES:
        out.append(~exists().where(column == Job.job_id))
    return out


def apply(session: Session, settings: Settings, actor: Actor, *, dry_run: bool) -> RetentionReport:
    now = clock.now()
    report = RetentionReport(dry_run=dry_run)
    cut: dict[str, datetime] = {
        "uploaded_files": now - timedelta(days=settings.retention_upload_days),
        "rejected_records": now - timedelta(days=settings.retention_rejected_days),
        "succeeded_jobs": now - timedelta(days=settings.retention_job_succeeded_days),
        "failed_jobs": now - timedelta(days=settings.retention_job_failed_days),
        "expired_sessions": now - timedelta(days=settings.retention_session_days),
        "audit_records": now - timedelta(days=settings.retention_audit_days),
    }
    report.cutoffs = {k: v.isoformat() for k, v in cut.items()}
    upload_root = settings.upload_dir.resolve()

    with session.begin():
        # Uploaded files: only server-stored files under the upload directory; CLI imports
        # point into the import root and are never touched.
        batches = session.scalars(
            select(IngestionBatch).where(
                IngestionBatch.status.in_(FINISHED_BATCH_STATUSES),
                IngestionBatch.finished_at < cut["uploaded_files"],
            )
        ).all()
        files: list[tuple[IngestionBatch, Path]] = []
        for batch in batches:
            path = Path(batch.stored_path).resolve()
            if path.is_relative_to(upload_root) and path.is_file():
                files.append((batch, path))
        report.counts["uploaded_files"] = len(files)

        rejected = select(RejectedRecord.rejected_record_id).where(
            RejectedRecord.created_at < cut["rejected_records"]
        )
        report.counts["rejected_records"] = _count(session, rejected)

        job_conds = _unreferenced_job(
            or_(
                (Job.status == "succeeded") & (Job.finished_at < cut["succeeded_jobs"]),
                (Job.status.in_(("failed", "cancelled"))) & (Job.finished_at < cut["failed_jobs"]),
            )
        )
        report.counts["jobs"] = _count(session, select(Job.job_id).where(*job_conds))
        report.counts["jobs_kept_because_referenced"] = (
            _count(
                session,
                select(Job.job_id).where(
                    or_(
                        (Job.status == "succeeded") & (Job.finished_at < cut["succeeded_jobs"]),
                        (Job.status.in_(("failed", "cancelled")))
                        & (Job.finished_at < cut["failed_jobs"]),
                    )
                ),
            )
            - report.counts["jobs"]
        )

        sessions_cond = AuthSession.expires_at < cut["expired_sessions"]
        report.counts["expired_sessions"] = _count(
            session, select(AuthSession.session_id).where(sessions_cond)
        )
        audit_cond = AuditLog.occurred_at < cut["audit_records"]
        report.counts["audit_records"] = _count(
            session, select(AuditLog.audit_id).where(audit_cond)
        )
        report.skipped = {
            "events_and_raw_records": "kept indefinitely (policy decided per deployment)",
            "model_artifacts": "use `cti artifacts gc`",
        }

        if not dry_run:
            for batch, path in files:
                path.unlink(missing_ok=True)
                batch.batch_metadata = {
                    **batch.batch_metadata,
                    "upload_file_removed_at": now.isoformat(),
                }
            session.execute(
                delete(RejectedRecord).where(RejectedRecord.created_at < cut["rejected_records"])
            )
            session.execute(delete(Job).where(*job_conds))
            session.execute(delete(AuthSession).where(sessions_cond))
            session.execute(delete(AuditLog).where(audit_cond))
        audit.record(
            session,
            actor,
            "retention.dry_run" if dry_run else "retention.applied",
            details=report.as_dict(),
        )
    return report
