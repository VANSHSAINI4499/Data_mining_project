from __future__ import annotations

import pytest

from app.core.errors import ValidationFailedError
from app.core.security import (
    Role,
    hash_password,
    new_token,
    token_digest,
    validate_password,
    verify_password,
)

pytestmark = pytest.mark.unit


def _codes(password: str, username: str = "alice") -> set[str]:
    try:
        validate_password(password, username)
    except ValidationFailedError as exc:
        return {e.code for e in exc.errors}
    return set()


def test_password_policy_accepts_long_unique_password() -> None:
    assert _codes("a-long-unique-passphrase") == set()


@pytest.mark.parametrize(
    ("password", "code"),
    [
        ("short", "too_short"),
        ("x" * 257, "too_long"),
        ("password1234", "too_common"),
        ("AliceAliceAlice", None),
    ],
)
def test_password_policy_rejections(password: str, code: str | None) -> None:
    codes = _codes(password)
    assert (code in codes) if code else codes == set()


def test_password_equal_to_username_rejected() -> None:
    assert "equals_username" in _codes("administrator1", username="Administrator1")


def test_hash_is_argon2id_and_verifies() -> None:
    hashed = hash_password("a-long-unique-passphrase")
    assert hashed.startswith("$argon2id$")
    assert verify_password(hashed, "a-long-unique-passphrase")
    assert not verify_password(hashed, "wrong-passphrase-here")
    assert not verify_password("not-a-hash", "anything")


def test_tokens_are_random_and_256_bit() -> None:
    tokens = {new_token() for _ in range(100)}
    assert len(tokens) == 100
    assert all(len(t) >= 43 for t in tokens)


def test_token_digest_is_keyed() -> None:
    assert token_digest("t", "k1") != token_digest("t", "k2")
    assert token_digest("t", "k1") == token_digest("t", "k1")


@pytest.mark.parametrize(
    ("role", "required", "allowed"),
    [
        (Role.VIEWER, Role.VIEWER, True),
        (Role.VIEWER, Role.ANALYST, False),
        (Role.ANALYST, Role.VIEWER, True),
        (Role.ANALYST, Role.ADMIN, False),
        (Role.ADMIN, Role.ANALYST, True),
    ],
)
def test_role_hierarchy(role: Role, required: Role, allowed: bool) -> None:
    assert role.includes(required) is allowed
