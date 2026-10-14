"""User management (admin only)."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query, status

from app.api.deps import Admin, allow_query_params
from app.core.db import DbSession
from app.core.pagination import DEFAULT_LIMIT, MAX_LIMIT
from app.schemas.auth import UserCreate, UserOut, UserUpdate
from app.schemas.common import Page
from app.services import users as users_service

router = APIRouter(prefix="/users", tags=["users"])


@router.get(
    "",
    response_model=Page[UserOut],
    dependencies=[Depends(allow_query_params("cursor", "limit"))],
)
def list_users(
    principal: Admin,
    session: DbSession,
    cursor: str | None = None,
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = DEFAULT_LIMIT,
) -> Page[UserOut]:
    page = users_service.list_users(session, cursor, limit)
    return Page(
        items=[UserOut.model_validate(u) for u in page.items],
        next_cursor=page.next_cursor,
        limit=page.limit,
    )


@router.post("", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def create_user(body: UserCreate, principal: Admin, session: DbSession) -> UserOut:
    user = users_service.create_user(
        session, principal.actor, body.username, body.password, body.role
    )
    return UserOut.model_validate(user)


@router.patch("/{user_id}", response_model=UserOut)
def update_user(
    user_id: uuid.UUID, body: UserUpdate, principal: Admin, session: DbSession
) -> UserOut:
    user = users_service.update_user(
        session,
        principal.actor,
        user_id,
        role=body.role,
        is_active=body.is_active,
        password=body.password,
    )
    return UserOut.model_validate(user)
