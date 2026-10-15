"""Classification and model registry endpoints (API_SPECIFICATION.md §5.9, §5.11)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, status
from pydantic import BaseModel, ConfigDict, Field

from app.api.deps import Admin, Analyst, SettingsDep, Viewer, allow_query_params
from app.api.v1.router_prefix import API_PREFIX
from app.core.db import DbSession
from app.core.pagination import DEFAULT_LIMIT, MAX_LIMIT
from app.schemas.common import RequestModel
from app.services import classification, drift
from app.services import models as models_service

router = APIRouter(tags=["ml"])


class RunOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    run_id: uuid.UUID
    task: str
    name: str
    status: str
    config: dict[str, Any]
    random_seed: int
    dataset_snapshot: dict[str, Any] | None
    feature_set_version: str
    label_mapping_version: str | None
    split_strategy: str | None
    metrics: dict[str, Any] | None
    leakage_checks: dict[str, Any] | None
    warnings_acknowledged: dict[str, Any] | None
    environment: dict[str, Any] | None
    job_id: uuid.UUID | None
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    error: dict[str, Any] | None


class RunSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    run_id: uuid.UUID
    name: str
    status: str
    feature_set_version: str
    split_strategy: str | None
    created_at: datetime
    finished_at: datetime | None
    error: dict[str, Any] | None


class ScoringRunOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    scoring_run_id: uuid.UUID
    model_id: uuid.UUID
    scope: dict[str, Any]
    status: str
    evaluation_only: bool
    rows_scored: int
    rows_skipped: dict[str, Any]
    job_id: uuid.UUID | None
    created_at: datetime
    finished_at: datetime | None
    error: dict[str, Any] | None


class AcknowledgeBody(RequestModel):
    note: str = Field(min_length=10, max_length=2000)


class ScoringBody(RequestModel):
    batch_ids: list[uuid.UUID] | None = None
    from_: datetime | None = Field(default=None, alias="from")
    to: datetime | None = None
    source_id: int | None = None
    model_id: uuid.UUID | None = None


class RejectBody(RequestModel):
    reason: str = Field(min_length=3, max_length=500)


def _accepted(run_id: uuid.UUID, job_id: uuid.UUID | None, kind: str) -> dict[str, Any]:
    links = {kind: f"{API_PREFIX}/classification/{kind}s/{run_id}"}
    if job_id:
        links["job"] = f"{API_PREFIX}/jobs/{job_id}"
    return {
        "id": str(run_id),
        "job_id": str(job_id) if job_id else None,
        "status": "queued",
        "links": links,
    }


@router.post("/classification/training-runs", status_code=status.HTTP_202_ACCEPTED)
def start_training(body: dict[str, Any], principal: Admin, session: DbSession) -> dict[str, Any]:
    config = classification.parse_config(body)
    run = classification.start_training(session, principal.actor, config)
    return _accepted(run.run_id, run.job_id, "training-run")


@router.get(
    "/classification/training-runs",
    response_model=list[RunSummary],
    dependencies=[Depends(allow_query_params("limit"))],
)
def list_runs(
    principal: Viewer, session: DbSession, limit: Annotated[int, Query(ge=1, le=200)] = 50
) -> list[RunSummary]:
    return [RunSummary.model_validate(r) for r in classification.list_runs(session, limit=limit)]


@router.get("/classification/training-runs/{run_id}", response_model=RunOut)
def get_run(run_id: uuid.UUID, principal: Viewer, session: DbSession) -> RunOut:
    return RunOut.model_validate(classification.get_run(session, run_id))


@router.post("/classification/training-runs/{run_id}/acknowledge-warnings", response_model=RunOut)
def acknowledge(
    run_id: uuid.UUID, body: AcknowledgeBody, principal: Admin, session: DbSession
) -> RunOut:
    return RunOut.model_validate(
        classification.acknowledge_warnings(session, principal.actor, run_id, body.note)
    )


@router.post("/classification/scoring-runs", status_code=status.HTTP_202_ACCEPTED)
def start_scoring(body: ScoringBody, principal: Analyst, session: DbSession) -> dict[str, Any]:
    scope: dict[str, Any] = {}
    if body.batch_ids:
        scope["batch_ids"] = [str(b) for b in body.batch_ids]
    if body.from_ is not None:
        scope["from"] = body.from_.isoformat()
    if body.to is not None:
        scope["to"] = body.to.isoformat()
    if body.source_id is not None:
        scope["source_id"] = body.source_id
    run = classification.start_scoring(session, principal.actor, scope, body.model_id)
    return _accepted(run.scoring_run_id, run.job_id, "scoring-run")


@router.get("/classification/scoring-runs/{run_id}", response_model=ScoringRunOut)
def get_scoring_run(run_id: uuid.UUID, principal: Viewer, session: DbSession) -> ScoringRunOut:
    return ScoringRunOut.model_validate(classification.get_scoring_run(session, run_id))


@router.get(
    "/classification/results",
    dependencies=[
        Depends(
            allow_query_params(
                "model_id",
                "predicted_category",
                "min_score",
                "from",
                "to",
                "disagrees_with_ground_truth",
                "cursor",
                "limit",
            )
        )
    ],
)
def list_results(
    principal: Viewer,
    session: DbSession,
    model_id: uuid.UUID | None = None,
    predicted_category: str | None = None,
    min_score: Annotated[float | None, Query(ge=0, le=1)] = None,
    start: Annotated[datetime | None, Query(alias="from")] = None,
    end: Annotated[datetime | None, Query(alias="to")] = None,
    disagrees_with_ground_truth: bool = False,
    cursor: str | None = None,
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = DEFAULT_LIMIT,
) -> dict[str, Any]:
    return classification.list_results(
        session,
        model_id=model_id,
        category=predicted_category.upper() if predicted_category else None,
        min_score=min_score,
        start=start,
        end=end,
        disagrees=disagrees_with_ground_truth,
        cursor=cursor,
        limit=limit,
    )


@router.get(
    "/classification/summary", dependencies=[Depends(allow_query_params("model_id", "from", "to"))]
)
def summary(
    principal: Viewer,
    session: DbSession,
    model_id: uuid.UUID | None = None,
    start: Annotated[datetime | None, Query(alias="from")] = None,
    end: Annotated[datetime | None, Query(alias="to")] = None,
) -> dict[str, Any]:
    return classification.summary(session, model_id, start, end)


@router.get("/models", dependencies=[Depends(allow_query_params("task", "name", "status"))])
def list_models(
    principal: Viewer,
    session: DbSession,
    task: str | None = None,
    name: str | None = None,
    status: str | None = None,
) -> list[dict[str, Any]]:
    return models_service.list_models(session, task, name, status)


@router.get("/models/{model_id}")
def get_model(
    model_id: uuid.UUID, principal: Viewer, session: DbSession, settings: SettingsDep
) -> dict[str, Any]:
    return models_service.get_model(session, settings, model_id)


@router.post("/models/{model_id}/promote")
def promote(model_id: uuid.UUID, principal: Admin, session: DbSession) -> dict[str, Any]:
    return models_service.promote(session, principal.actor, model_id)


@router.post("/models/{model_id}/archive")
def archive(model_id: uuid.UUID, principal: Admin, session: DbSession) -> dict[str, Any]:
    return models_service.archive(session, principal.actor, model_id)


@router.post("/models/{model_id}/reject")
def reject(
    model_id: uuid.UUID, body: RejectBody, principal: Admin, session: DbSession
) -> dict[str, Any]:
    return models_service.reject(session, principal.actor, model_id, body.reason)


class DriftBody(RequestModel):
    from_: datetime = Field(alias="from")
    to: datetime


@router.post("/models/{model_id}/drift-reports", status_code=status.HTTP_202_ACCEPTED)
def start_drift_report(
    model_id: uuid.UUID, body: DriftBody, principal: Analyst, session: DbSession
) -> dict[str, Any]:
    job_id = drift.start(session, principal.actor, model_id, body.from_, body.to)
    return {
        "job_id": str(job_id),
        "status": "queued",
        "links": {"job": f"{API_PREFIX}/jobs/{job_id}"},
    }


@router.get("/models/{model_id}/drift-reports")
def list_drift_reports(
    model_id: uuid.UUID, principal: Viewer, session: DbSession
) -> list[dict[str, Any]]:
    return drift.list_reports(session, model_id)
