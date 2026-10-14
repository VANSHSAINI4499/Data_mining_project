"""The ``diagnostic`` job: exercises the queue end-to-end (AC-1.7).

It does no data processing. Parameters let tests and operators exercise success, failure,
transient-retry, progress, and cancellation paths.
"""

from __future__ import annotations

import time
from typing import Any

from app.jobs.runtime import JobContext, TransientJobError

MAX_SLEEP_SECONDS = 60.0


class DiagnosticFailureError(Exception):
    pass


def run_diagnostic(ctx: JobContext) -> dict[str, Any]:
    params = ctx.params
    sleep_seconds = min(float(params.get("sleep_seconds", 0.0)), MAX_SLEEP_SECONDS)
    steps = max(1, min(int(params.get("steps", 1)), 100))
    transient_failures = int(params.get("transient_failures", 0))

    if ctx.attempt <= transient_failures:
        raise TransientJobError(f"simulated transient failure on attempt {ctx.attempt}")
    if params.get("fail"):
        raise DiagnosticFailureError("simulated failure requested by job parameters")

    for step in range(1, steps + 1):
        ctx.check_cancelled()
        if sleep_seconds:
            time.sleep(sleep_seconds / steps)
        ctx.report_progress(step, steps, "steps")
    return {"steps_completed": steps, "attempt": ctx.attempt}
