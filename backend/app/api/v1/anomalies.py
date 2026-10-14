"""Anomaly detection endpoints (API_SPECIFICATION.md §5.10)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, status
from pydantic import Field

from app.api.deps import Admin, Analyst, Viewer, allow_query_params
from app.api.v1.router_prefix import API_PREFIX
from app.core.db import DbSession
from app.core.pagination import DEFAULT_LIMIT, MAX_LIMIT
from app.schemas.common import RequestModel
from app.services import anomaly, classification

router = APIRouter(prefix="/anomalies", tags=["anomalies"])


class ScoringBody(RequestModel):
    from_: datetime = Field(alias="from")
    to: datetime
    model_id: uuid.UUID | None = None
    name: str | None = Field(default=None, max_length=64)


@router.post("/training-runs", status_code=status.HTTP_202_ACCEPTED)
def start_training(body: dict[str, Any], principal: Admin, session: DbSession) -> dict[str, Any]:
    run = anomaly.start_training(session, principal.actor, anomaly.parse_config(body))
    return {
        "id": str(run.run_id),
        "job_id": str(run.job_id),
        "status": "queued",
        "links": {
            "training-run": f"{API_PREFIX}/anomalies/training-runs/{run.run_id}",
            "job": f"{API_PREFIX}/jobs/{run.job_id}",
        },
    }


@router.get("/training-runs/{run_id}")
def get_training_run(run_id: uuid.UUID, principal: Viewer, session: DbSession) -> dict[str, Any]:
    run = classification.get_run(session, run_id)
    return {
        "run_id": run.run_id,
        "task": run.task,
        "name": run.name,
        "status": run.status,
        "config": run.config,
        "metrics": run.metrics,
        "dataset_snapshot": run.dataset_snapshot,
        "environment": run.environment,
        "created_at": run.created_at,
        "finished_at": run.finished_at,
        "error": run.error,
    }


@router.post("/scoring-runs", status_code=status.HTTP_202_ACCEPTED)
def start_scoring(body: ScoringBody, principal: Analyst, session: DbSession) -> dict[str, Any]:
    run = anomaly.start_scoring(
        session,
        principal.actor,
        start=body.from_,
        end=body.to,
        model_id=body.model_id,
        name=body.name,
    )
    return {
        "id": str(run.scoring_run_id),
        "job_id": str(run.job_id),
        "status": "queued",
        "links": {"job": f"{API_PREFIX}/jobs/{run.job_id}"},
    }


@router.get(
    "",
    dependencies=[
        Depends(
            allow_query_params(
                "model_id",
                "entity_type",
                "entity_value",
                "is_flagged",
                "min_percentile",
                "from",
                "to",
                "cursor",
                "limit",
            )
        )
    ],
)
def list_anomalies(
    principal: Viewer,
    session: DbSession,
    model_id: uuid.UUID | None = None,
    entity_type: Annotated[str | None, Query(pattern="^(host|account|src_ip)$")] = None,
    entity_value: Annotated[str | None, Query(max_length=256)] = None,
    is_flagged: bool | None = True,
    min_percentile: Annotated[float | None, Query(ge=0, le=100)] = None,
    start: Annotated[datetime | None, Query(alias="from")] = None,
    end: Annotated[datetime | None, Query(alias="to")] = None,
    cursor: str | None = None,
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = DEFAULT_LIMIT,
) -> dict[str, Any]:
    return anomaly.list_results(
        session,
        model_id=model_id,
        entity_type=entity_type,
        entity_value=entity_value,
        flagged=is_flagged,
        min_percentile=min_percentile,
        start=start,
        end=end,
        cursor=cursor,
        limit=limit,
    )


@router.get("/{result_id}")
def get_anomaly(result_id: int, principal: Viewer, session: DbSession) -> dict[str, Any]:
    return anomaly.detail(session, result_id)
