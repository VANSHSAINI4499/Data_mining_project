"""Health and readiness (unauthenticated)."""

from __future__ import annotations

from fastapi import APIRouter

from app import __version__
from app.api.deps import SettingsDep
from app.core.db import DbSession
from app.core.errors import NotReadyError
from app.schemas.health import HealthOut, ReadinessOut
from app.services import health as health_service

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthOut)
def liveness() -> HealthOut:
    """Liveness only: no database access."""
    return HealthOut(status="ok", version=__version__)


@router.get(
    "/health/ready", response_model=ReadinessOut, responses={503: {"description": "Not ready"}}
)
def readiness(session: DbSession, settings: SettingsDep) -> ReadinessOut:
    result = health_service.check_readiness(session, settings)
    if not result.ready:
        failing = sorted(name for name, check in result.checks.items() if check["status"] != "ok")
        raise NotReadyError(
            f"failing checks: {', '.join(failing)}", extra={"checks": result.checks}
        )
    return ReadinessOut(status="ready", checks=result.checks)
