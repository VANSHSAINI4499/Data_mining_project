"""Queries for app_user and auth_session."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app.models import AppUser, AuthSession


def get_user(session: Session, user_id: uuid.UUID) -> AppUser | None:
    return session.get(AppUser, user_id)


def get_user_by_username(
    session: Session, username: str, *, for_update: bool = False
) -> AppUser | None:
    stmt = select(AppUser).where(AppUser.username == username)
    if for_update:
        stmt = stmt.with_for_update()
    return session.scalar(stmt)


def get_user_for_update(session: Session, user_id: uuid.UUID) -> AppUser | None:
    return session.scalar(select(AppUser).where(AppUser.user_id == user_id).with_for_update())


def list_users(session: Session, after_username: str | None, limit: int) -> list[AppUser]:
    stmt = select(AppUser).order_by(AppUser.username).limit(limit)
    if after_username is not None:
        stmt = stmt.where(AppUser.username > after_username)
    return list(session.scalars(stmt))


# Arbitrary constant identifying the "admin membership" advisory lock.
ADMIN_MEMBERSHIP_LOCK_KEY = 7_402_115_001


def lock_admin_membership(session: Session) -> None:
    """Serialise role/activation changes for the transaction (released at commit/rollback).

    Taken *before* any row lock, so concurrent demotions queue instead of deadlocking.
    """
    session.execute(select(func.pg_advisory_xact_lock(ADMIN_MEMBERSHIP_LOCK_KEY)))


def count_active_admins(session: Session) -> int:
    stmt = (
        select(func.count())
        .select_from(AppUser)
        .where(AppUser.role == "admin", AppUser.is_active.is_(True))
    )
    return session.scalar(stmt) or 0


def get_session_by_token_hash(session: Session, token_hash: str) -> AuthSession | None:
    return session.scalar(select(AuthSession).where(AuthSession.token_hash == token_hash))


def revoke_user_sessions(session: Session, user_id: uuid.UUID, at: datetime) -> int:
    result = session.execute(
        update(AuthSession)
        .where(AuthSession.user_id == user_id, AuthSession.revoked_at.is_(None))
        .values(revoked_at=at)
    )
    return int(result.rowcount)  # type: ignore[attr-defined]
