"""The ``ingestion.process_batch`` job: loads one ingestion batch in the worker."""

from __future__ import annotations

import uuid
from typing import Any

from app.core.config import get_settings
from app.jobs.runtime import JobContext
from app.services import data_quality
from app.services.ingestion import BatchFailedError, process_batch


def run_ingestion(ctx: JobContext) -> dict[str, Any]:
    batch_id = uuid.UUID(str(ctx.params["batch_id"]))
    outcome = process_batch(
        ctx.session_factory,
        get_settings(),
        batch_id,
        progress=ctx.report_progress,
        check_cancel=ctx.check_cancelled,
        on_complete=data_quality.run_checks,
    )
    summary = {
        "batch_id": str(outcome.batch_id),
        "status": outcome.status,
        "records_total": outcome.records_total,
        "records_loaded": outcome.records_loaded,
        "records_rejected": outcome.records_rejected,
        "records_duplicate": outcome.records_duplicate,
    }
    if outcome.status == "failed":
        # Deterministic batch failures are not retried; the batch row holds the details.
        raise BatchFailedError(f"batch failed: {outcome.error}")
    return summary
