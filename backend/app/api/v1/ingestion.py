"""Uploads and ingestion batches (API_SPECIFICATION.md §5.6)."""

from __future__ import annotations

import uuid
from datetime import date, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, File, Form, Query, UploadFile, status
from fastapi.responses import JSONResponse

from app.api.deps import Analyst, SettingsDep, Viewer, allow_query_params
from app.api.v1.router_prefix import API_PREFIX
from app.core.db import DbSession
from app.core.pagination import DEFAULT_LIMIT, MAX_LIMIT
from app.schemas.common import Page
from app.schemas.ingestion import BatchOut, RejectionOut, RejectionPage, UploadAccepted
from app.services import ingestion as ingestion_service
from app.services.ingestion import BatchOptions

router = APIRouter(prefix="/ingestion", tags=["ingestion"])


@router.post(
    "/uploads",
    response_model=UploadAccepted,
    status_code=status.HTTP_202_ACCEPTED,
    responses={200: {"model": UploadAccepted, "description": "duplicate of an earlier upload"}},
)
def upload(
    principal: Analyst,
    session: DbSession,
    settings: SettingsDep,
    file: Annotated[UploadFile, File()],
    source_id: Annotated[int, Form()],
    adapter: Annotated[str | None, Form(max_length=64)] = None,
    variant: Annotated[str | None, Form(max_length=64)] = None,
    assume_event_date: Annotated[date | None, Form()] = None,
    timezone: Annotated[str | None, Form(max_length=64)] = None,
    date_order: Annotated[str | None, Form(max_length=3)] = None,
    dataset_partition: Annotated[str | None, Form(max_length=16)] = None,
) -> JSONResponse:
    options = BatchOptions(
        variant=variant,
        assume_event_date=assume_event_date,
        timezone=timezone,
        date_order=date_order,
        dataset_partition=dataset_partition,
    )
    batch, duplicate = ingestion_service.create_upload_batch(
        session,
        settings,
        principal.actor,
        source_id=source_id,
        adapter_name=adapter,
        filename=file.filename or "upload",
        fileobj=file.file,
        options=options,
    )
    links = {"batch": f"{API_PREFIX}/ingestion/batches/{batch.batch_id}"}
    if batch.job_id:
        links["job"] = f"{API_PREFIX}/jobs/{batch.job_id}"
    body = UploadAccepted(
        batch_id=batch.batch_id,
        status=batch.status,
        job_id=batch.job_id,
        duplicate_of=batch.duplicate_of,
        links=links,
    )
    return JSONResponse(
        body.model_dump(mode="json"),
        status_code=status.HTTP_200_OK if duplicate else status.HTTP_202_ACCEPTED,
    )


@router.get(
    "/batches",
    response_model=Page[BatchOut],
    dependencies=[
        Depends(
            allow_query_params(
                "source_id", "status", "created_after", "created_before", "cursor", "limit"
            )
        )
    ],
)
def list_batches(
    principal: Viewer,
    session: DbSession,
    source_id: int | None = None,
    status_: Annotated[list[str] | None, Query(alias="status")] = None,
    created_after: datetime | None = None,
    created_before: datetime | None = None,
    cursor: str | None = None,
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = DEFAULT_LIMIT,
) -> Page[BatchOut]:
    page = ingestion_service.list_batches(
        session,
        source_id=source_id,
        statuses=status_,
        created_after=created_after,
        created_before=created_before,
        cursor=cursor,
        limit=limit,
    )
    return Page(
        items=[BatchOut.model_validate(b) for b in page.items],
        next_cursor=page.next_cursor,
        limit=page.limit,
    )


@router.get("/batches/{batch_id}", response_model=BatchOut)
def get_batch(batch_id: uuid.UUID, principal: Viewer, session: DbSession) -> BatchOut:
    return BatchOut.model_validate(ingestion_service.get_batch(session, batch_id))


@router.get(
    "/batches/{batch_id}/rejections",
    response_model=RejectionPage,
    dependencies=[Depends(allow_query_params("cursor", "limit"))],
)
def list_rejections(
    batch_id: uuid.UUID,
    principal: Analyst,
    session: DbSession,
    cursor: str | None = None,
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = DEFAULT_LIMIT,
) -> RejectionPage:
    page, total = ingestion_service.list_rejections(session, batch_id, cursor, limit)
    return RejectionPage(
        items=[RejectionOut.model_validate(r) for r in page.items],
        next_cursor=page.next_cursor,
        limit=page.limit,
        total=total,
    )


@router.post("/batches/{batch_id}/retry", response_model=BatchOut)
def retry_batch(batch_id: uuid.UUID, principal: Analyst, session: DbSession) -> BatchOut:
    return BatchOut.model_validate(
        ingestion_service.retry_batch(session, principal.actor, batch_id)
    )
