"""Health schemas."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel


class HealthOut(BaseModel):
    status: Literal["ok"]
    version: str


class ReadinessOut(BaseModel):
    status: Literal["ready"]
    checks: dict[str, dict[str, Any]]
