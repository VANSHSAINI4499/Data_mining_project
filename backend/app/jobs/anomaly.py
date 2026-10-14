"""ML jobs for anomaly mining."""

from __future__ import annotations

import uuid
from typing import Any

from app.core.config import get_settings
from app.jobs.runtime import JobContext
from app.services import anomaly


def run_train_anomaly(ctx: JobContext) -> dict[str, Any]:
    run = anomaly.run_training(
        ctx.session_factory, get_settings(), uuid.UUID(str(ctx.params["run_id"]))
    )
    return {"run_id": str(run.run_id), "status": run.status}


def run_score_anomaly(ctx: JobContext) -> dict[str, Any]:
    run = anomaly.run_scoring(
        ctx.session_factory, get_settings(), uuid.UUID(str(ctx.params["scoring_run_id"]))
    )
    return {
        "scoring_run_id": str(run.scoring_run_id),
        "rows_scored": run.rows_scored,
        "rows_skipped": run.rows_skipped,
    }
