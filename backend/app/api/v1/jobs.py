"""Background job status (API_SPECIFICATION.md §5.3)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query

from app.api.deps import Admin, Viewer, allow_query_params
from app.core.db import DbSession
from app.core.pagination import DEFAULT_LIMIT, MAX_LIMIT
from app.schemas.common import Page
from app.schemas.jobs import JobOut, JobStatus
from app.services import jobs as jobs_service

router = APIRouter(prefix="/jobs", tags=["jobs"])


@router.get(
    "",
    response_model=Page[JobOut],
    dependencies=[
        Depends(allow_query_params("status", "job_type", "created_after", "cursor", "limit"))
    ],
)
def list_jobs(
    principal: Viewer,
    session: DbSession,
    status: Annotated[list[JobStatus] | None, Query()] = None,
    job_type: Annotated[str | None, Query(max_length=64)] = None,
    created_after: datetime | None = None,
    cursor: str | None = None,
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = DEFAULT_LIMIT,
) -> Page[JobOut]:
    page = jobs_service.list_jobs(
        session,
        statuses=list(status) if status else None,
        job_type=job_type,
        created_after=created_after,
        cursor=cursor,
        limit=limit,
    )
    return Page(
        items=[JobOut.model_validate(j) for j in page.items],
        next_cursor=page.next_cursor,
        limit=page.limit,
    )


@router.get("/{job_id}", response_model=JobOut)
def get_job(job_id: uuid.UUID, principal: Viewer, session: DbSession) -> JobOut:
    return JobOut.model_validate(jobs_service.get_job(session, job_id))


@router.post("/{job_id}/cancel", response_model=JobOut)
def cancel_job(job_id: uuid.UUID, principal: Admin, session: DbSession) -> JobOut:
    return JobOut.model_validate(jobs_service.cancel_job(session, principal.actor, job_id))
