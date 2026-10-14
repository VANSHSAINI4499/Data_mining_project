"""Dashboard analytics endpoint (API_SPECIFICATION.md §5.16)."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query

from app.api.deps import Viewer, allow_query_params
from app.core.db import DbSession
from app.services import dashboard

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/overview", dependencies=[Depends(allow_query_params("from", "to"))])
def overview(
    principal: Viewer,
    session: DbSession,
    start: Annotated[datetime, Query(alias="from")],
    end: Annotated[datetime, Query(alias="to")],
) -> dict[str, Any]:
    return dashboard.overview(session, start, end)
