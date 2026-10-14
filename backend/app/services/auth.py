"""Login, session validation, CSRF, and logout (SECURITY_REQUIREMENTS.md §1)."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from app.core import clock
from app.core.config import Settings
from app.core.errors import AuthenticationError, CsrfError
from app.core.security import (
    DUMMY_PASSWORD_HASH,
    Role,
    digests_equal,
    new_token,
    token_digest,
    verify_password,
)
from app.models import AppUser, AuthSession
from app.repositories import users as users_repo
from app.services import audit
from app.services.actors import Actor, Principal

MAX_FAILED_LOGINS = 10
LOCKOUT = timedelta(minutes=15)
# Avoid a write on every request: refresh last_seen_at at most this often.
LAST_SEEN_RESOLUTION = timedelta(seconds=60)
INVALID_CREDENTIALS = "Invalid username or password"
USER_AGENT_MAX = 256


@dataclass(frozen=True)
class LoginResult:
    user: AppUser
    session_token: str
    csrf_token: str
    expires_at: datetime


def login(
    session: Session,
    settings: Settings,
    username: str,
    password: str,
    *,
    ip_address: str | None,
    user_agent: str | None,
) -> LoginResult:
    key = settings.secret_key.get_secret_value()
    normalized = username.strip().lower()
    now = clock.now()
    failure_reason: str | None = None
    result: LoginResult | None = None

    with session.begin():
        # Row lock: concurrent attempts must not lose failed-login increments (lockout bypass).
        user = users_repo.get_user_by_username(session, normalized, for_update=True)
        if user is None:
            verify_password(DUMMY_PASSWORD_HASH, password)  # equalise timing
            failure_reason = "unknown_user"
        elif not user.is_active:
            verify_password(DUMMY_PASSWORD_HASH, password)
            failure_reason = "inactive"
        elif user.locked_until is not None and user.locked_until > now:
            verify_password(DUMMY_PASSWORD_HASH, password)
            failure_reason = "locked"
        elif not verify_password(user.password_hash, password):
            user.failed_login_count += 1
            failure_reason = "bad_password"
            if user.failed_login_count >= MAX_FAILED_LOGINS:
                user.locked_until = now + LOCKOUT
                user.failed_login_count = 0
                failure_reason = "bad_password_locked"
        else:
            user.failed_login_count = 0
            user.locked_until = None
            user.last_login_at = now
            token, csrf = new_token(), new_token()
            expires_at = now + timedelta(minutes=settings.session_ttl_minutes)
            session.add(
                AuthSession(
                    session_id=uuid.uuid4(),
                    user_id=user.user_id,
                    token_hash=token_digest(token, key),
                    csrf_token_hash=token_digest(csrf, key),
                    expires_at=expires_at,
                    last_seen_at=now,
                    ip_address=ip_address,
                    user_agent=(user_agent or "")[:USER_AGENT_MAX] or None,
                )
            )
            result = LoginResult(user, token, csrf, expires_at)

        actor = Actor("user", user_id=user.user_id if user else None, label=normalized[:64])
        audit.record(
            session,
            actor,
            "auth.login",
            outcome="success" if result else "denied",
            target_type="app_user",
            target_id=user.user_id if user else None,
            details={} if result else {"reason": failure_reason},
        )

    if result is None:
        # Generic message for every failure mode: no user enumeration (SECURITY §1).
        raise AuthenticationError(INVALID_CREDENTIALS)
    return result


def authenticate(session: Session, settings: Settings, token: str | None) -> Principal:
    if not token:
        raise AuthenticationError("Authentication required")
    key = settings.secret_key.get_secret_value()
    now = clock.now()
    with session.begin():
        auth = users_repo.get_session_by_token_hash(session, token_digest(token, key))
        if auth is None or auth.revoked_at is not None or auth.expires_at <= now:
            raise AuthenticationError("Session is invalid or expired")
        if auth.last_seen_at + timedelta(minutes=settings.session_idle_minutes) <= now:
            auth.revoked_at = now
            principal = None
        else:
            user = users_repo.get_user(session, auth.user_id)
            if user is None or not user.is_active:
                raise AuthenticationError("Session is invalid or expired")
            if now - auth.last_seen_at >= LAST_SEEN_RESOLUTION:
                auth.last_seen_at = now
            principal = Principal(user.user_id, user.username, Role(user.role), auth.session_id)
    if principal is None:
        raise AuthenticationError("Session expired due to inactivity")
    return principal


def verify_csrf(
    session: Session, settings: Settings, principal: Principal, csrf: str | None
) -> None:
    if not csrf:
        raise CsrfError("X-CSRF-Token header is required for state-changing requests")
    key = settings.secret_key.get_secret_value()
    with session.begin():
        auth = session.get(AuthSession, principal.session_id)
        expected = auth.csrf_token_hash if auth is not None else ""
    if not digests_equal(expected, token_digest(csrf, key)):
        raise CsrfError("X-CSRF-Token does not match the session")


def rotate_csrf(session: Session, settings: Settings, principal: Principal) -> str:
    """Issue a fresh CSRF token (returned by GET /auth/me after a page reload)."""
    csrf = new_token()
    with session.begin():
        auth = session.get(AuthSession, principal.session_id)
        if auth is None:
            raise AuthenticationError("Session is invalid or expired")
        auth.csrf_token_hash = token_digest(csrf, settings.secret_key.get_secret_value())
    return csrf


def logout(session: Session, principal: Principal) -> None:
    with session.begin():
        auth = session.get(AuthSession, principal.session_id)
        if auth is not None and auth.revoked_at is None:
            auth.revoked_at = clock.now()
        audit.record(
            session,
            principal.actor,
            "auth.logout",
            target_type="auth_session",
            target_id=principal.session_id,
        )


def get_current_user(session: Session, principal: Principal) -> AppUser:
    with session.begin():
        user = users_repo.get_user(session, principal.user_id)
    if user is None:
        raise AuthenticationError("Session is invalid or expired")
    return user
