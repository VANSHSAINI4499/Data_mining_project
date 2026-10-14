"""Shared API schemas."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class RequestModel(BaseModel):
    """Base for request bodies: unknown fields are rejected (422)."""

    model_config = ConfigDict(extra="forbid")


class Page[T](BaseModel):
    """Cursor-paginated list envelope (API_SPECIFICATION.md §6)."""

    items: list[T]
    next_cursor: str | None
    limit: int


class JobAccepted(BaseModel):
    job_id: str
    status: str
    links: dict[str, str]
