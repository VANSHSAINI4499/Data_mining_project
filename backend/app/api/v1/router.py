"""Aggregates all /api/v1 routers."""

from __future__ import annotations

from fastapi import APIRouter

from app.api.v1 import (
    anomalies,
    auth,
    correlation,
    dashboard,
    events,
    health,
    ingestion,
    investigations,
    jobs,
    ml,
    sources,
    threat_intel,
    users,
)
from app.api.v1.router_prefix import API_PREFIX

__all__ = ["API_PREFIX", "ROUTERS", "api_router"]

# Every endpoint router, in registration order. The authorization test enumerates these
# (and cross-checks them against the generated OpenAPI paths).
ROUTERS = (
    health.router,
    auth.router,
    users.router,
    jobs.router,
    sources.router,
    ingestion.router,
    events.router,
    ml.router,
    anomalies.router,
    threat_intel.router,
    correlation.router,
    investigations.router,
    dashboard.router,
)

api_router = APIRouter(prefix=API_PREFIX)
for _router in ROUTERS:
    api_router.include_router(_router)
