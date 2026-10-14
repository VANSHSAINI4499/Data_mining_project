"""Login, logout, and current-session endpoints (API_SPECIFICATION.md §2, §5.2)."""

from __future__ import annotations

from fastapi import APIRouter, Request, Response, status

from app.api.deps import SESSION_COOKIE, SettingsDep, Viewer
from app.core.db import DbSession
from app.core.errors import RateLimitedError
from app.core.logging import client_ip_var
from app.core.ratelimit import LIMITS
from app.schemas.auth import LoginRequest, SessionInfo, UserOut
from app.services import auth as auth_service

router = APIRouter(prefix="/auth", tags=["auth"])

COOKIE_PATH = "/api"


@router.post("/login", response_model=SessionInfo)
def login(
    body: LoginRequest,
    request: Request,
    response: Response,
    session: DbSession,
    settings: SettingsDep,
) -> SessionInfo:
    limiter = request.app.state.rate_limiter
    wait = limiter.hit(f"login:{client_ip_var.get()}:{body.username.lower()}", LIMITS["login"])
    if wait is not None:
        raise RateLimitedError("too many login attempts; retry later", retry_after=wait)
    result = auth_service.login(
        session,
        settings,
        body.username,
        body.password,
        ip_address=client_ip_var.get(),
        user_agent=request.headers.get("user-agent"),
    )
    response.set_cookie(
        SESSION_COOKIE,
        result.session_token,
        max_age=settings.session_ttl_minutes * 60,
        path=COOKIE_PATH,
        httponly=True,
        samesite="strict",
        secure=settings.is_production,
    )
    return SessionInfo(user=UserOut.model_validate(result.user), csrf_token=result.csrf_token)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(principal: Viewer, session: DbSession, settings: SettingsDep) -> Response:
    auth_service.logout(session, principal)
    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    response.delete_cookie(
        SESSION_COOKIE,
        path=COOKIE_PATH,
        httponly=True,
        samesite="strict",
        secure=settings.is_production,
    )
    return response


@router.get("/me", response_model=SessionInfo)
def me(principal: Viewer, session: DbSession, settings: SettingsDep) -> SessionInfo:
    """Current user. Rotates and returns the CSRF token so the SPA can recover it after reload."""
    user = auth_service.get_current_user(session, principal)
    csrf = auth_service.rotate_csrf(session, settings, principal)
    return SessionInfo(user=UserOut.model_validate(user), csrf_token=csrf)
