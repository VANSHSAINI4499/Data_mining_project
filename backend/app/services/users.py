"""User management (admin) and the CLI bootstrap admin."""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core import clock
from app.core.errors import ConflictError, FieldError, NotFoundError, ValidationFailedError
from app.core.pagination import DEFAULT_LIMIT, decode_cursor, encode_cursor
from app.core.security import Role, hash_password, validate_password
from app.models import AppUser
from app.repositories import users as users_repo
from app.services import audit
from app.services.actors import Actor

USERNAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{2,63}$")


@dataclass(frozen=True)
class UserPage:
    items: list[AppUser]
    next_cursor: str | None
    limit: int


def normalize_username(username: str) -> str:
    normalized = username.strip().lower()
    if not USERNAME_PATTERN.match(normalized):
        raise ValidationFailedError(
            "invalid username",
            errors=[
                FieldError(
                    "username",
                    "invalid_username",
                    "3-64 chars: letters, digits, '.', '_', '-'; must start with a letter or digit",
                )
            ],
        )
    return normalized


def create_user(
    session: Session, actor: Actor, username: str, password: str, role: Role
) -> AppUser:
    normalized = normalize_username(username)
    validate_password(password, normalized)
    password_hash = hash_password(password)  # slow; do it before opening the transaction
    try:
        with session.begin():
            if users_repo.get_user_by_username(session, normalized) is not None:
                raise ConflictError(f"user {normalized!r} already exists")
            user = AppUser(
                user_id=uuid.uuid4(),
                username=normalized,
                password_hash=password_hash,
                role=role.value,
            )
            session.add(user)
            session.flush()
            audit.record(
                session,
                actor,
                "user.create",
                target_type="app_user",
                target_id=user.user_id,
                details={"username": normalized, "role": role.value},
            )
    except IntegrityError as exc:  # concurrent creation of the same username
        raise ConflictError(f"user {normalized!r} already exists") from exc
    return user


def list_users(session: Session, cursor: str | None, limit: int = DEFAULT_LIMIT) -> UserPage:
    key = decode_cursor(cursor, frozenset({"username"}))
    with session.begin():
        rows = users_repo.list_users(session, key["username"] if key else None, limit + 1)
    items = rows[:limit]
    next_cursor = encode_cursor({"username": items[-1].username}) if len(rows) > limit else None
    return UserPage(items, next_cursor, limit)


def get_user(session: Session, user_id: uuid.UUID) -> AppUser:
    with session.begin():
        user = users_repo.get_user(session, user_id)
    if user is None:
        raise NotFoundError(f"user {user_id} not found")
    return user


def update_user(
    session: Session,
    actor: Actor,
    user_id: uuid.UUID,
    *,
    role: Role | None = None,
    is_active: bool | None = None,
    password: str | None = None,
) -> AppUser:
    new_hash: str | None = None
    with session.begin():
        if role is not None or is_active is not None:
            users_repo.lock_admin_membership(session)
        user = users_repo.get_user_for_update(session, user_id)
        if user is None:
            raise NotFoundError(f"user {user_id} not found")
        if password is not None:
            validate_password(password, user.username)
            new_hash = hash_password(password)

        loses_admin = (
            user.role == Role.ADMIN.value
            and user.is_active
            and ((role is not None and role is not Role.ADMIN) or is_active is False)
        )
        if loses_admin and users_repo.count_active_admins(session) <= 1:
            raise ConflictError("cannot demote or deactivate the last active admin")

        changes: dict[str, object] = {}
        if role is not None and role.value != user.role:
            changes["role"] = {"old": user.role, "new": role.value}
            user.role = role.value
        if is_active is not None and is_active != user.is_active:
            changes["is_active"] = {"old": user.is_active, "new": is_active}
            user.is_active = is_active
        if new_hash is not None:
            changes["password"] = {"changed": True}
            user.password_hash = new_hash
            user.failed_login_count = 0
            user.locked_until = None
        # Role changes, deactivation, and password resets invalidate existing sessions.
        if changes:
            users_repo.revoke_user_sessions(session, user.user_id, clock.now())
            audit.record(
                session,
                actor,
                "user.update",
                target_type="app_user",
                target_id=user.user_id,
                details={"changes": changes},
            )
    return user
