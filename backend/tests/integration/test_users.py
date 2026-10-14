from __future__ import annotations

from collections.abc import Callable

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import Role
from app.models import AuditLog
from tests.conftest import DEFAULT_PASSWORD, LoggedIn

pytestmark = pytest.mark.integration

USERS = "/api/v1/users"


def _user_id(admin: LoggedIn, username: str) -> str:
    items = admin.client.get(USERS, params={"limit": 500}).json()["items"]
    return str(next(u["user_id"] for u in items if u["username"] == username))


def test_admin_creates_user_and_it_is_audited(login: Callable[..., LoggedIn], db: Session) -> None:
    admin = login("root", Role.ADMIN)
    resp = admin.client.post(
        USERS,
        json={"username": "Analyst.One", "password": "another-long-passphrase", "role": "analyst"},
        headers=admin.headers(),
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["username"] == "analyst.one"
    audit = db.scalars(select(AuditLog).where(AuditLog.action == "user.create")).all()
    assert any(a.actor_label == "root" and a.details["username"] == "analyst.one" for a in audit)
    assert all("password" not in a.details for a in audit)


@pytest.mark.parametrize(
    ("payload", "field"),
    [
        ({"username": "ok-name", "password": "short", "role": "viewer"}, "password"),
        ({"username": "x", "password": "a-long-enough-passphrase", "role": "viewer"}, "username"),
        ({"username": "ok-name", "password": "a-long-enough-passphrase", "role": "root"}, "role"),
        (
            {
                "username": "ok-name",
                "password": "a-long-enough-passphrase",
                "role": "viewer",
                "is_superuser": True,
            },
            "is_superuser",
        ),
    ],
)
def test_create_user_validation(
    login: Callable[..., LoggedIn], payload: dict[str, object], field: str
) -> None:
    admin = login("root", Role.ADMIN)
    resp = admin.client.post(USERS, json=payload, headers=admin.headers())
    assert resp.status_code == 422
    assert field in {e["field"] for e in resp.json()["errors"]}


def test_duplicate_username_conflict(login: Callable[..., LoggedIn]) -> None:
    admin = login("root", Role.ADMIN)
    body = {"username": "dup", "password": "a-long-enough-passphrase", "role": "viewer"}
    assert admin.client.post(USERS, json=body, headers=admin.headers()).status_code == 201
    assert admin.client.post(USERS, json=body, headers=admin.headers()).status_code == 409


def test_last_admin_cannot_be_demoted_or_deactivated(login: Callable[..., LoggedIn]) -> None:
    admin = login("root", Role.ADMIN)
    root_id = _user_id(admin, "root")
    for change in ({"role": "analyst"}, {"is_active": False}):
        resp = admin.client.patch(f"{USERS}/{root_id}", json=change, headers=admin.headers())
        assert resp.status_code == 409, change


def test_admin_can_be_demoted_when_another_admin_exists(
    login: Callable[..., LoggedIn], make_user: Callable[..., str]
) -> None:
    make_user("second-admin", Role.ADMIN)
    admin = login("root", Role.ADMIN)
    second = _user_id(admin, "second-admin")
    resp = admin.client.patch(f"{USERS}/{second}", json={"role": "viewer"}, headers=admin.headers())
    assert resp.status_code == 200
    assert resp.json()["role"] == "viewer"


def test_role_change_revokes_target_sessions(login: Callable[..., LoggedIn]) -> None:
    viewer = login("vic")
    vic_cookie = viewer.client.cookies["cti_session"]
    admin = login("root", Role.ADMIN)
    vic_id = _user_id(admin, "vic")
    admin.client.patch(f"{USERS}/{vic_id}", json={"role": "analyst"}, headers=admin.headers())
    admin.client.cookies.clear()
    admin.client.cookies.set("cti_session", vic_cookie, path="/api")
    assert admin.client.get("/api/v1/auth/me").status_code == 401


def test_password_reset_applies_policy_and_allows_new_login(
    login: Callable[..., LoggedIn], make_user: Callable[..., str]
) -> None:
    make_user("bob")
    admin = login("root", Role.ADMIN)
    bob = _user_id(admin, "bob")
    bad = admin.client.patch(f"{USERS}/{bob}", json={"password": "short"}, headers=admin.headers())
    assert bad.status_code == 422
    ok = admin.client.patch(
        f"{USERS}/{bob}", json={"password": "a-brand-new-passphrase"}, headers=admin.headers()
    )
    assert ok.status_code == 200
    admin.client.cookies.clear()
    login_new = admin.client.post(
        "/api/v1/auth/login", json={"username": "bob", "password": "a-brand-new-passphrase"}
    )
    assert login_new.status_code == 200
    login_old = admin.client.post(
        "/api/v1/auth/login", json={"username": "bob", "password": DEFAULT_PASSWORD}
    )
    assert login_old.status_code == 401


def test_update_unknown_user_is_404(login: Callable[..., LoggedIn]) -> None:
    admin = login("root", Role.ADMIN)
    resp = admin.client.patch(
        f"{USERS}/00000000-0000-0000-0000-000000000000",
        json={"role": "viewer"},
        headers=admin.headers(),
    )
    assert resp.status_code == 404


def test_list_users_cursor_pagination(
    login: Callable[..., LoggedIn], make_user: Callable[..., str]
) -> None:
    for i in range(5):
        make_user(f"user{i}")
    admin = login("root", Role.ADMIN)
    seen: list[str] = []
    cursor = None
    while True:
        params: dict[str, str | int] = {"limit": 2}
        if cursor:
            params["cursor"] = cursor
        page = admin.client.get(USERS, params=params).json()
        assert page["limit"] == 2 and len(page["items"]) <= 2
        seen += [u["username"] for u in page["items"]]
        cursor = page["next_cursor"]
        if cursor is None:
            break
    assert seen == sorted(seen)
    assert set(seen) == {f"user{i}" for i in range(5)} | {"root"}


@pytest.mark.parametrize(
    "params", [{"limit": 0}, {"limit": 501}, {"sort": "username"}, {"cursor": "garbage"}]
)
def test_list_users_rejects_bad_query(
    login: Callable[..., LoggedIn], params: dict[str, object]
) -> None:
    admin = login("root", Role.ADMIN)
    assert admin.client.get(USERS, params=params).status_code == 422
