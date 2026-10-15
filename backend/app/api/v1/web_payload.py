"""Web payload classification (HTTP parameter values). Bounded, read-only inference."""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter
from pydantic import Field

from app.api.deps import Analyst, SettingsDep
from app.core.db import DbSession
from app.schemas.common import RequestModel
from app.services import web_payload

router = APIRouter(prefix="/web-payloads", tags=["web-payloads"])


class ClassifyBody(RequestModel):
    payloads: list[Annotated[str, Field(max_length=web_payload.wp.MAX_PAYLOAD_CHARS)]] = Field(
        min_length=1, max_length=web_payload.MAX_BATCH
    )
    model_id: uuid.UUID | None = None


@router.post("/classify")
def classify(
    body: ClassifyBody, principal: Analyst, session: DbSession, settings: SettingsDep
) -> dict[str, Any]:
    # Small synchronous batch (<= 100 values of <= 8 KB); nothing is stored or blocked.
    return web_payload.classify(session, settings, body.payloads, body.model_id)
