"""Adapters, sources, and assets (API_SPECIFICATION.md §5.4, §5.5)."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, File, Query, UploadFile, status

from app.api.deps import Admin, Viewer, allow_query_params
from app.core.db import DbSession
from app.core.errors import FieldError, PayloadTooLargeError, ValidationFailedError
from app.core.pagination import DEFAULT_LIMIT, MAX_LIMIT
from app.schemas.common import Page
from app.schemas.ingestion import (
    AdapterOut,
    AssetImportOut,
    AssetOut,
    SourceCreate,
    SourceDetail,
    SourceOut,
    SourceUpdate,
)
from app.services import assets as assets_service
from app.services import sources as sources_service
from app.services.ingestion import adapter_catalog

router = APIRouter(tags=["sources"])

MAX_ASSET_FILE_BYTES = 10 * 1024 * 1024


@router.get("/adapters", response_model=list[AdapterOut])
def list_adapters(principal: Viewer) -> list[AdapterOut]:
    return [AdapterOut(**a) for a in adapter_catalog()]


@router.get("/sources", response_model=list[SourceOut])
def list_sources(principal: Viewer, session: DbSession) -> list[SourceOut]:
    return [SourceOut.model_validate(s) for s in sources_service.list_sources(session)]


@router.post("/sources", response_model=SourceOut, status_code=status.HTTP_201_CREATED)
def create_source(body: SourceCreate, principal: Admin, session: DbSession) -> SourceOut:
    source = sources_service.create_source(session, principal.actor, body.model_dump())
    return SourceOut.model_validate(source)


@router.get("/sources/{source_id}", response_model=SourceDetail)
def get_source(source_id: int, principal: Viewer, session: DbSession) -> SourceDetail:
    source, counts = sources_service.get_source(session, source_id)
    return SourceDetail(**SourceOut.model_validate(source).model_dump(), counts=counts)


@router.patch("/sources/{source_id}", response_model=SourceOut)
def update_source(
    source_id: int, body: SourceUpdate, principal: Admin, session: DbSession
) -> SourceOut:
    source = sources_service.update_source(
        session, principal.actor, source_id, body.model_dump(exclude_unset=True)
    )
    return SourceOut.model_validate(source)


@router.get(
    "/assets",
    response_model=Page[AssetOut],
    dependencies=[Depends(allow_query_params("criticality", "q", "cursor", "limit"))],
)
def list_assets(
    principal: Viewer,
    session: DbSession,
    criticality: str | None = None,
    q: Annotated[str | None, Query(max_length=128)] = None,
    cursor: str | None = None,
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = DEFAULT_LIMIT,
) -> Page[AssetOut]:
    items, next_cursor = assets_service.list_assets(
        session, criticality=criticality, q=q, cursor=cursor, limit=limit
    )
    return Page(
        items=[AssetOut.model_validate(a) for a in items], next_cursor=next_cursor, limit=limit
    )


@router.post("/assets/import", response_model=AssetImportOut)
def import_assets(
    principal: Admin, session: DbSession, file: Annotated[UploadFile, File()]
) -> AssetImportOut:
    if not (file.filename or "").lower().endswith(".csv"):
        raise ValidationFailedError(
            "asset inventory must be a .csv file",
            errors=[FieldError("file", "invalid_extension", ".csv")],
        )
    data = file.file.read(MAX_ASSET_FILE_BYTES + 1)
    if len(data) > MAX_ASSET_FILE_BYTES:
        raise PayloadTooLargeError("asset inventory files are limited to 10 MB")
    result = assets_service.import_assets_csv(session, principal.actor, data)
    return AssetImportOut(
        created=result.created,
        updated=result.updated,
        unchanged=result.unchanged,
        rejected=result.rejected,
        note="first versions are assumed valid from 2000-01-01 so past events can link to them",
    )
