"""ML jobs: classifier training and scoring (anomaly jobs are added in Phase 4)."""

from __future__ import annotations

import uuid
from typing import Any

from app.core.config import get_settings
from app.jobs.runtime import JobContext
from app.services import classification


def run_train_classifier(ctx: JobContext) -> dict[str, Any]:
    run_id = uuid.UUID(str(ctx.params["run_id"]))
    steps = {"n": 0}

    def progress(message: str) -> None:
        steps["n"] += 1
        ctx.check_cancelled()
        ctx.report_progress(steps["n"], None, f"step: {message}")

    run = classification.run_training(ctx.session_factory, get_settings(), run_id, progress)
    return {"run_id": str(run.run_id), "status": run.status}


def run_score_classifier(ctx: JobContext) -> dict[str, Any]:
    run_id = uuid.UUID(str(ctx.params["scoring_run_id"]))
    run = classification.run_scoring(
        ctx.session_factory, get_settings(), run_id, ctx.report_progress
    )
    return {
        "scoring_run_id": str(run.scoring_run_id),
        "rows_scored": run.rows_scored,
        "rows_skipped": run.rows_skipped,
    }
