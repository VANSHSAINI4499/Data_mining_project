"""API dependencies: settings, authentication, CSRF, role checks, query-parameter guards."""

from __future__ import annotations

from collections.abc import Callable
from typing import Annotated

from fastapi import Depends, Request

from app.core.config import Settings, get_settings
from app.core.db import DbSession
from app.core.errors import FieldError, PermissionDeniedError, ValidationFailedError
from app.core.logging import user_id_var
from app.core.security import Role
from app.services import audit
from app.services import auth as auth_service
from app.services.actors import Principal

SESSION_COOKIE = "cti_session"
CSRF_HEADER = "X-CSRF-Token"
UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
# Attribute the route-enumeration test looks for (TESTING_STRATEGY.md §10).
MIN_ROLE_ATTR = "cti_min_role"


def settings_dependency() -> Settings:
    return get_settings()


SettingsDep = Annotated[Settings, Depends(settings_dependency)]


def get_principal(request: Request, session: DbSession, settings: SettingsDep) -> Principal:
    principal = auth_service.authenticate(session, settings, request.cookies.get(SESSION_COOKIE))
    user_id_var.set(str(principal.user_id))
    return principal


def require_role(min_role: Role) -> Callable[..., Principal]:
    def dependency(
        request: Request,
        session: DbSession,
        settings: SettingsDep,
        principal: Annotated[Principal, Depends(get_principal)],
    ) -> Principal:
        unsafe = request.method in UNSAFE_METHODS
        if unsafe:
            auth_service.verify_csrf(session, settings, principal, request.headers.get(CSRF_HEADER))
        if not principal.role.includes(min_role):
            if unsafe:
                audit.record_standalone(
                    session,
                    principal.actor,
                    "authz.denied",
                    outcome="denied",
                    details={
                        "method": request.method,
                        "path": request.url.path,
                        "required_role": min_role.value,
                    },
                )
            raise PermissionDeniedError(f"This action requires the {min_role.value!r} role")
        return principal

    setattr(dependency, MIN_ROLE_ATTR, min_role)
    return dependency


Viewer = Annotated[Principal, Depends(require_role(Role.VIEWER))]
Analyst = Annotated[Principal, Depends(require_role(Role.ANALYST))]
Admin = Annotated[Principal, Depends(require_role(Role.ADMIN))]


def allow_query_params(*names: str) -> Callable[[Request], None]:
    """Reject unknown query parameters with 422 (API_SPECIFICATION.md §7)."""
    allowed = frozenset(names)

    def dependency(request: Request) -> None:
        unknown = sorted(set(request.query_params) - allowed)
        if unknown:
            raise ValidationFailedError(
                f"unknown query parameter(s): {', '.join(unknown)}",
                errors=[FieldError(n, "unknown_parameter", "not supported") for n in unknown],
            )

    return dependency
