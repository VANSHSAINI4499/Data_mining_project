"""Aggregates all /api/v1 routers."""

from __future__ import annotations

from fastapi import APIRouter

from app.api.v1 import auth, health, jobs, users

API_PREFIX = "/api/v1"

# Every endpoint router, in registration order. The authorization test enumerates these
# (and cross-checks them against the generated OpenAPI paths).
ROUTERS = (health.router, auth.router, users.router, jobs.router)

api_router = APIRouter(prefix=API_PREFIX)
for _router in ROUTERS:
    api_router.include_router(_router)
