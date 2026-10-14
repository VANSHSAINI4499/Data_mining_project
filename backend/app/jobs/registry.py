"""Mapping of job_type to handler. Later phases register ingestion, training, etc."""

from __future__ import annotations

from app.jobs.diagnostic import run_diagnostic
from app.jobs.runtime import JobHandler

HANDLERS: dict[str, JobHandler] = {
    "diagnostic": run_diagnostic,
}
