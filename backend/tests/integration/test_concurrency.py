"""Concurrency tests for security-relevant invariants (run against committed data)."""

from __future__ import annotations

import threading
from collections.abc import Callable
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings
from app.core.errors import AuthenticationError, ConflictError
from app.core.security import Role
from app.models import AppUser
from app.services import auth as auth_service
from app.services import users as users_service
from app.services.actors import CLI_ACTOR
from tests.conftest import DEFAULT_PASSWORD

pytestmark = pytest.mark.integration


def _run_concurrently(fns: list[Callable[[], Any]]) -> list[Any]:
    """Run callables in parallel threads, released together; return results or exceptions."""
    barrier = threading.Barrier(len(fns))
    results: list[Any] = [None] * len(fns)

    def runner(i: int, fn: Callable[[], Any]) -> None:
        barrier.wait()
        try:
            results[i] = fn()
        except Exception as exc:  # collected for assertions
            results[i] = exc

    threads = [threading.Thread(target=runner, args=(i, fn)) for i, fn in enumerate(fns)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return results


def test_parallel_failed_logins_are_all_counted(committed_db: sessionmaker[Session]) -> None:
    with committed_db() as session:
        users_service.create_user(session, CLI_ACTOR, "target", DEFAULT_PASSWORD, Role.VIEWER)

    def bad_login() -> None:
        with committed_db() as session:
            auth_service.login(
                session,
                get_settings(),
                "target",
                "wrong-password-xyz",
                ip_address=None,
                user_agent=None,
            )

    results = _run_concurrently([bad_login] * 8)
    assert all(isinstance(r, AuthenticationError) for r in results), results
    with committed_db() as session:
        user = session.scalar(select(AppUser).where(AppUser.username == "target"))
        assert user is not None
        assert user.failed_login_count == 8  # no lost updates


def test_concurrent_admin_demotions_keep_one_admin(committed_db: sessionmaker[Session]) -> None:
    with committed_db() as session:
        a = users_service.create_user(session, CLI_ACTOR, "admin-a", DEFAULT_PASSWORD, Role.ADMIN)
        b = users_service.create_user(session, CLI_ACTOR, "admin-b", DEFAULT_PASSWORD, Role.ADMIN)

    def demote(user_id: Any) -> Callable[[], Any]:
        def _run() -> Any:
            with committed_db() as session:
                return users_service.update_user(session, CLI_ACTOR, user_id, role=Role.VIEWER)

        return _run

    for _ in range(5):  # repeat to give a race a chance to show up
        results = _run_concurrently([demote(a.user_id), demote(b.user_id)])
        errors = [r for r in results if isinstance(r, Exception)]
        # Exactly one demotion may succeed; the other must be a clean 409, never a DB error.
        assert all(isinstance(e, ConflictError) for e in errors), errors
        with committed_db() as session:
            admins = session.scalars(
                select(AppUser).where(AppUser.role == "admin", AppUser.is_active.is_(True))
            ).all()
            assert len(admins) >= 1
            for user in session.scalars(select(AppUser)).all():
                user.role = "admin"
            session.commit()
