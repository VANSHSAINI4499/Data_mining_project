"""Job schemas (API_SPECIFICATION.md §5.3)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

JobStatus = Literal["queued", "running", "succeeded", "failed", "cancelled"]


class JobProgress(BaseModel):
    done: int
    total: int | None
    unit: str


class JobOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    job_id: uuid.UUID
    job_type: str
    status: JobStatus
    progress: JobProgress | None
    result: dict[str, Any] | None
    error: dict[str, Any] | None
    attempts: int
    max_attempts: int
    cancel_requested: bool
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
