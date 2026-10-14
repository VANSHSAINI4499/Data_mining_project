"""Route-enumeration authorization tests (TESTING_STRATEGY.md §10).

Every registered route must declare a minimum role, except the explicit public allowlist.
For each protected route: no session -> 401; lower role -> 403; minimum role -> neither.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Callable
from typing import Any

import pytest
from fastapi.dependencies.models import Dependant
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import MIN_ROLE_ATTR
from app.api.v1.router import API_PREFIX, ROUTERS
from app.core.security import Role
from app.models import AuditLog
from tests.conftest import LoggedIn

pytestmark = pytest.mark.integration

PUBLIC = {("GET", "/health"), ("GET", "/health/ready"), ("POST", "/auth/login")}
ROLES = [Role.VIEWER, Role.ANALYST, Role.ADMIN]


def _min_role(dependant: Dependant) -> Role | None:
    for dep in dependant.dependencies:
        role = getattr(dep.call, MIN_ROLE_ATTR, None)
        if role is not None:
            return Role(role)
        nested = _min_role(dep)
        if nested is not None:
            return nested
    return None


def _routes() -> list[tuple[str, str, Role | None]]:
    found = []
    for router in ROUTERS:
        for route in router.routes:
            assert isinstance(route, APIRoute)
            for method in sorted(route.methods):
                found.append((method, route.path, _min_role(route.dependant)))
    return found


ROUTES = _routes()
PROTECTED = [(m, p, r) for m, p, r in ROUTES if (m, p) not in PUBLIC]


def _concrete(path: str) -> str:
    return API_PREFIX + re.sub(r"\{[^}]+\}", str(uuid.uuid4()), path)


def _call(client: TestClient, method: str, path: str, headers: dict[str, str]) -> Any:
    kwargs: dict[str, Any] = {"headers": headers}
    if method in {"POST", "PUT", "PATCH"}:
        kwargs["json"] = {}
    return client.request(method, _concrete(path), **kwargs)


def test_router_list_matches_openapi(client: TestClient) -> None:
    openapi_paths = set(client.get(f"{API_PREFIX}/openapi.json").json()["paths"])
    assert {API_PREFIX + p for _, p, _ in ROUTES} == openapi_paths


def test_every_route_declares_a_minimum_role_or_is_public() -> None:
    undeclared = [(m, p) for m, p, r in ROUTES if r is None and (m, p) not in PUBLIC]
    assert undeclared == []
    public_with_role = [(m, p) for m, p, r in ROUTES if r is not None and (m, p) in PUBLIC]
    assert public_with_role == []


@pytest.mark.parametrize(("method", "path", "role"), PROTECTED)
def test_unauthenticated_is_401(client: TestClient, method: str, path: str, role: Role) -> None:
    assert _call(client, method, path, {}).status_code == 401


@pytest.mark.parametrize(("method", "path", "role"), PROTECTED)
def test_role_enforcement(
    login: Callable[..., LoggedIn], db: Session, method: str, path: str, role: Role
) -> None:
    for i, user_role in enumerate(ROLES):
        session = login(f"user-{user_role.value}-{i}", user_role)
        resp = _call(session.client, method, path, session.headers())
        if user_role.includes(role):
            assert resp.status_code not in (401, 403), (user_role, resp.text)
        else:
            assert resp.status_code == 403, (user_role, resp.text)
            assert resp.json()["type"].endswith("/forbidden")
    if method != "GET" and role is not Role.VIEWER:
        denied = db.scalars(select(AuditLog).where(AuditLog.action == "authz.denied")).all()
        assert denied, "state-changing denials must be audited"
