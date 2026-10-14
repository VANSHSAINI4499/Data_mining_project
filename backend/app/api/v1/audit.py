"""Audit history (API_SPECIFICATION.md §5.18). Read-only: no write or delete endpoints exist."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Query

from app.api.deps import Admin, allow_query_params
from app.core.db import DbSession
from app.core.pagination import DEFAULT_LIMIT, MAX_LIMIT
from app.services import audit_records

router = APIRouter(tags=["audit"])


@router.get(
    "/audit-records",
    dependencies=[
        Depends(
            allow_query_params(
                "actor_user_id",
                "action",
                "target_type",
                "target_id",
                "outcome",
                "from",
                "to",
                "cursor",
                "limit",
            )
        )
    ],
)
def list_audit_records(
    principal: Admin,
    session: DbSession,
    actor_user_id: uuid.UUID | None = None,
    action: Annotated[str | None, Query(max_length=100)] = None,
    target_type: Annotated[str | None, Query(max_length=64)] = None,
    target_id: Annotated[str | None, Query(max_length=128)] = None,
    outcome: Literal["success", "denied", "error"] | None = None,
    start: Annotated[datetime | None, Query(alias="from")] = None,
    end: Annotated[datetime | None, Query(alias="to")] = None,
    cursor: Annotated[str | None, Query(max_length=200)] = None,
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = DEFAULT_LIMIT,
) -> dict[str, Any]:
    return audit_records.list_records(
        session,
        actor_user_id=actor_user_id,
        action=action,
        target_type=target_type,
        target_id=target_id,
        outcome=outcome,
        start=start,
        end=end,
        cursor=cursor,
        limit=limit,
    )
