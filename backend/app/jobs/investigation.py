"""Threat-intelligence and correlation jobs."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from app.core.config import get_settings
from app.jobs.runtime import JobContext
from app.services import correlation, patterns, threat_intel
from app.services.actors import SYSTEM_ACTOR


def run_ti_import(ctx: JobContext) -> dict[str, Any]:
    run = threat_intel.run_import(
        ctx.session_factory, get_settings(), uuid.UUID(str(ctx.params["feed_run_id"]))
    )
    return {
        "feed_run_id": str(run.feed_run_id),
        "status": run.status,
        "indicators_created": run.indicators_created,
        "indicators_updated": run.indicators_updated,
        "indicators_rejected": run.indicators_rejected,
    }


def run_ti_match(ctx: JobContext) -> dict[str, Any]:
    return threat_intel.run_match(ctx.session_factory, ctx.params, ctx.job_id)


def run_correlation(ctx: JobContext) -> dict[str, Any]:
    with ctx.session_factory() as session:
        return correlation.run_correlation(
            session,
            SYSTEM_ACTOR,
            datetime.fromisoformat(ctx.params["from"]),
            datetime.fromisoformat(ctx.params["to"]),
            ctx.params.get("rule_keys") or None,
        )


def run_mine_patterns(ctx: JobContext) -> dict[str, Any]:
    return patterns.run_job(ctx.session_factory, SYSTEM_ACTOR, ctx.params)


def run_ti_sync(ctx: JobContext) -> dict[str, Any]:
    run = threat_intel.run_sync(ctx.session_factory, uuid.UUID(str(ctx.params["feed_run_id"])))
    return {
        "feed_run_id": str(run.feed_run_id),
        "status": run.status,
        "indicators_created": run.indicators_created,
        "indicators_updated": run.indicators_updated,
        "pages": run.report.get("pages"),
    }
