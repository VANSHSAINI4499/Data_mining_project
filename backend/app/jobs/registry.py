"""Mapping of job_type to handler. Later phases register ingestion, training, etc."""

from __future__ import annotations

from app.jobs.diagnostic import run_diagnostic
from app.jobs.ingestion import run_ingestion
from app.jobs.ml import run_score_classifier, run_train_classifier
from app.jobs.runtime import JobHandler

HANDLERS: dict[str, JobHandler] = {
    "diagnostic": run_diagnostic,
    "ingestion.process_batch": run_ingestion,
    "ml.train_classifier": run_train_classifier,
    "ml.score_classifier": run_score_classifier,
}
