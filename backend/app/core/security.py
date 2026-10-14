"""Password hashing, password policy, and session/CSRF token helpers.

SECURITY_REQUIREMENTS.md §1: argon2id hashes; opaque random tokens stored only as
HMAC-SHA-256 digests keyed with ``CTI_SECRET_KEY``.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from enum import StrEnum

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from app.core.errors import FieldError, ValidationFailedError

_hasher = PasswordHasher()  # argon2id with library defaults

MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 256

# Small built-in deny-list (SECURITY_REQUIREMENTS.md §1). Not a substitute for length.
COMMON_PASSWORDS = frozenset(
    {
        "password1234",
        "123456789012",
        "qwertyuiopas",
        "passwordpassword",
        "letmein12345",
        "administrator",
        "welcome12345",
        "iloveyou1234",
        "changeme1234",
        "admin1234567",
        "qwerty123456",
        "password123!",
        "1q2w3e4r5t6y",
        "abc123456789",
        "trustno11234",
    }
)


class Role(StrEnum):
    VIEWER = "viewer"
    ANALYST = "analyst"
    ADMIN = "admin"

    @property
    def rank(self) -> int:
        return _ROLE_RANK[self]

    def includes(self, required: Role) -> bool:
        return self.rank >= required.rank


_ROLE_RANK = {Role.VIEWER: 1, Role.ANALYST: 2, Role.ADMIN: 3}


def validate_password(password: str, username: str) -> None:
    problems: list[FieldError] = []
    if len(password) < MIN_PASSWORD_LENGTH:
        problems.append(
            FieldError(
                "password", "too_short", f"must be at least {MIN_PASSWORD_LENGTH} characters"
            )
        )
    if len(password) > MAX_PASSWORD_LENGTH:
        problems.append(
            FieldError("password", "too_long", f"must be at most {MAX_PASSWORD_LENGTH} characters")
        )
    lowered = password.lower()
    if username and lowered == username.lower():
        problems.append(FieldError("password", "equals_username", "must not equal the username"))
    if lowered in COMMON_PASSWORDS:
        problems.append(FieldError("password", "too_common", "is too common"))
    if problems:
        raise ValidationFailedError("password does not meet the policy", errors=problems)


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


# A valid hash used to equalise timing when the username does not exist.
DUMMY_PASSWORD_HASH = _hasher.hash("dummy-password-for-timing")


def new_token() -> str:
    """256-bit URL-safe random token."""
    return secrets.token_urlsafe(32)


def token_digest(token: str, key: str) -> str:
    return hmac.new(key.encode(), token.encode(), hashlib.sha256).hexdigest()


def digests_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a, b)
