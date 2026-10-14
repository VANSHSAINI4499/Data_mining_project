from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core import clock
from app.core.ratelimit import LIMITS
from app.core.security import Role
from app.models import AuditLog, AuthSession
from tests.conftest import DEFAULT_PASSWORD, LoggedIn

pytestmark = pytest.mark.integration

LOGIN = "/api/v1/auth/login"
ME = "/api/v1/auth/me"
LOGOUT = "/api/v1/auth/logout"


def _audit(db: Session, action: str) -> list[AuditLog]:
    return list(db.scalars(select(AuditLog).where(AuditLog.action == action)))


def test_login_sets_hardened_session_cookie(
    client: TestClient, make_user: Callable[..., str]
) -> None:
    make_user("alice")
    resp = client.post(LOGIN, json={"username": "Alice", "password": DEFAULT_PASSWORD})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["user"]["username"] == "alice"
    assert body["user"]["role"] == "viewer"
    assert body["csrf_token"]
    cookie = resp.headers["set-cookie"].lower()
    assert "cti_session=" in cookie
    assert "httponly" in cookie
    assert "samesite=strict" in cookie
    assert "path=/api" in cookie
    assert "secure" not in cookie  # test env is not production
    assert "password_hash" not in resp.text


def test_session_token_is_stored_hashed(
    client: TestClient, make_user: Callable[..., str], db: Session
) -> None:
    make_user("alice")
    resp = client.post(LOGIN, json={"username": "alice", "password": DEFAULT_PASSWORD})
    token = resp.cookies["cti_session"]
    stored = db.scalars(select(AuthSession.token_hash)).all()
    assert stored and token not in stored


@pytest.mark.parametrize(
    ("username", "password"),
    [("alice", "wrong-password-123"), ("nobody", DEFAULT_PASSWORD)],
)
def test_failed_login_is_generic_and_audited(
    client: TestClient, make_user: Callable[..., str], db: Session, username: str, password: str
) -> None:
    make_user("alice")
    resp = client.post(LOGIN, json={"username": username, "password": password})
    assert resp.status_code == 401
    assert resp.json()["detail"] == "Invalid username or password"
    denied = [a for a in _audit(db, "auth.login") if a.outcome == "denied"]
    assert len(denied) == 1
    assert "password" not in str(denied[0].details).replace("bad_password", "")


def test_lockout_after_ten_failures(
    client: TestClient, make_user: Callable[..., str], db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Isolate the account lockout from the per-IP login rate limit (tested separately).
    monkeypatch.setitem(LIMITS, "login", 1000)
    make_user("alice")
    for _ in range(10):
        assert (
            client.post(LOGIN, json={"username": "alice", "password": "nope-nope-nope"}).status_code
            == 401
        )
    # Correct password is refused while locked, with the same generic message.
    resp = client.post(LOGIN, json={"username": "alice", "password": DEFAULT_PASSWORD})
    assert resp.status_code == 401
    assert _audit(db, "auth.login")[-1].details == {"reason": "locked"}
    # After the lockout period the correct password works again.
    real_now = clock.now()
    clock.set_clock(lambda: real_now + timedelta(minutes=16))
    assert (
        client.post(LOGIN, json={"username": "alice", "password": DEFAULT_PASSWORD}).status_code
        == 200
    )


def test_inactive_user_cannot_log_in(
    client: TestClient, login: Callable[..., LoggedIn], make_user: Callable[..., str]
) -> None:
    admin = login("root", Role.ADMIN)
    make_user("bob")
    users = client.get("/api/v1/users").json()["items"]
    bob_id = next(u["user_id"] for u in users if u["username"] == "bob")
    assert (
        client.patch(
            f"/api/v1/users/{bob_id}", json={"is_active": False}, headers=admin.headers()
        ).status_code
        == 200
    )
    client.cookies.clear()
    assert (
        client.post(LOGIN, json={"username": "bob", "password": DEFAULT_PASSWORD}).status_code
        == 401
    )


def test_me_requires_session(client: TestClient) -> None:
    resp = client.get(ME)
    assert resp.status_code == 401
    assert resp.json()["type"].endswith("/unauthenticated")


def test_me_returns_user_and_rotates_csrf(login: Callable[..., LoggedIn]) -> None:
    session = login("alice")
    resp = session.client.get(ME)
    assert resp.status_code == 200
    new_csrf = resp.json()["csrf_token"]
    assert new_csrf != session.csrf
    # The old CSRF token no longer works; the new one does.
    assert session.client.post(LOGOUT, headers={"X-CSRF-Token": session.csrf}).status_code == 403
    assert session.client.post(LOGOUT, headers={"X-CSRF-Token": new_csrf}).status_code == 204


@pytest.mark.parametrize("csrf", [None, "wrong-token"])
def test_state_changing_request_requires_valid_csrf(
    login: Callable[..., LoggedIn], csrf: str | None
) -> None:
    session = login("alice")
    headers = {"X-CSRF-Token": csrf} if csrf else {}
    resp = session.client.post(LOGOUT, headers=headers)
    assert resp.status_code == 403
    assert resp.json()["type"].endswith("/csrf-failed")


def test_logout_revokes_session(login: Callable[..., LoggedIn], db: Session) -> None:
    session = login("alice")
    cookie = session.client.cookies["cti_session"]
    assert session.client.post(LOGOUT, headers=session.headers()).status_code == 204
    session.client.cookies.set("cti_session", cookie, path="/api")
    assert session.client.get(ME).status_code == 401
    assert len(_audit(db, "auth.logout")) == 1


def test_idle_timeout_expires_session(login: Callable[..., LoggedIn]) -> None:
    session = login("alice")
    real_now = clock.now()
    clock.set_clock(lambda: real_now + timedelta(minutes=61))
    resp = session.client.get(ME)
    assert resp.status_code == 401
    clock.set_clock(None)
    assert session.client.get(ME).status_code == 401  # revoked, not merely idle


def test_absolute_lifetime_expires_session(login: Callable[..., LoggedIn]) -> None:
    session = login("alice")
    start = clock.now()
    # Stay active every 50 minutes so the idle timeout never triggers.
    for minutes in range(50, 480, 50):
        clock.set_clock(lambda m=minutes: start + timedelta(minutes=m))
        assert session.client.get(ME).status_code == 200
    clock.set_clock(lambda: start + timedelta(minutes=481))
    assert session.client.get(ME).status_code == 401
