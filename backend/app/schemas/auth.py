"""Auth and user schemas."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.core.security import Role
from app.schemas.common import RequestModel


class LoginRequest(RequestModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    user_id: uuid.UUID
    username: str
    role: Role
    is_active: bool
    created_at: datetime
    last_login_at: datetime | None


class SessionInfo(BaseModel):
    user: UserOut
    csrf_token: str


class UserCreate(RequestModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)
    role: Role


class UserUpdate(RequestModel):
    role: Role | None = None
    is_active: bool | None = None
    password: str | None = Field(default=None, min_length=1, max_length=256)
