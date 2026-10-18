"""Web payload classification (HTTP parameter values): bounded inference, and background
scoring of the decoded query parameters of stored HTTP events."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, status
from pydantic import Field

from app.api.deps import Analyst, SettingsDep, Viewer, allow_query_params
from app.api.v1.ml import ScoringBody, ScoringRunOut
from app.api.v1.router_prefix import API_PREFIX
from app.core.db import DbSession
from app.core.pagination import DEFAULT_LIMIT, MAX_LIMIT
from app.schemas.common import RequestModel
from app.services import web_payload

router = APIRouter(prefix="/web-payloads", tags=["web-payloads"])


class ClassifyBody(RequestModel):
    payloads: list[Annotated[str, Field(max_length=web_payload.wp.MAX_PAYLOAD_CHARS)]] = Field(
        min_length=1, max_length=web_payload.MAX_BATCH
    )
    model_id: uuid.UUID | None = None


@router.post("/classify")
def classify(
    body: ClassifyBody, principal: Analyst, session: DbSession, settings: SettingsDep
) -> dict[str, Any]:
    # Small synchronous batch (<= 100 values of <= 8 KB); nothing is stored or blocked.
    return web_payload.classify(session, settings, body.payloads, body.model_id)


@router.post("/scoring-runs", status_code=status.HTTP_202_ACCEPTED)
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
    run = web_payload.start_scoring(session, principal.actor, scope, body.model_id)
    links = {"scoring-run": f"{API_PREFIX}/web-payloads/scoring-runs/{run.scoring_run_id}"}
    if run.job_id:
        links["job"] = f"{API_PREFIX}/jobs/{run.job_id}"
    return {
        "id": str(run.scoring_run_id),
        "job_id": str(run.job_id) if run.job_id else None,
        "status": "queued",
        "links": links,
    }


@router.get("/scoring-runs/{run_id}", response_model=ScoringRunOut)
def get_scoring_run(run_id: uuid.UUID, principal: Viewer, session: DbSession) -> ScoringRunOut:
    return ScoringRunOut.model_validate(web_payload.get_scoring_run(session, run_id))


@router.get(
    "/results",
    dependencies=[
        Depends(
            allow_query_params(
                "model_id", "predicted_class", "attack_like_only", "from", "to", "cursor", "limit"
            )
        )
    ],
)
def list_results(
    principal: Viewer,
    session: DbSession,
    model_id: uuid.UUID | None = None,
    predicted_class: Annotated[str | None, Query(max_length=40)] = None,
    attack_like_only: bool = False,
    start: Annotated[datetime | None, Query(alias="from")] = None,
    end: Annotated[datetime | None, Query(alias="to")] = None,
    cursor: str | None = None,
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = DEFAULT_LIMIT,
) -> dict[str, Any]:
    return web_payload.list_results(
        session,
        model_id=model_id,
        predicted_class=predicted_class.upper() if predicted_class else None,
        attack_like_only=attack_like_only,
        start=start,
        end=end,
        cursor=cursor,
        limit=limit,
    )


@router.get("/summary", dependencies=[Depends(allow_query_params("model_id", "from", "to"))])
def summary(
    principal: Viewer,
    session: DbSession,
    model_id: uuid.UUID | None = None,
    start: Annotated[datetime | None, Query(alias="from")] = None,
    end: Annotated[datetime | None, Query(alias="to")] = None,
) -> dict[str, Any]:
    return web_payload.summary(session, model_id, start, end)
