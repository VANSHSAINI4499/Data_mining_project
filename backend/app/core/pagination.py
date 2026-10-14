"""Opaque cursor encoding for keyset pagination (API_SPECIFICATION.md §6)."""

from __future__ import annotations

import base64
import binascii
import json
from typing import Any

from app.core.errors import FieldError, ValidationFailedError

DEFAULT_LIMIT = 50
MAX_LIMIT = 500


def encode_cursor(key: dict[str, Any]) -> str:
    raw = json.dumps(key, separators=(",", ":"), sort_keys=True, default=str).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def decode_cursor(cursor: str | None, required_keys: frozenset[str]) -> dict[str, Any] | None:
    if cursor is None:
        return None
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        data = json.loads(base64.urlsafe_b64decode(padded.encode()))
    except (binascii.Error, ValueError, UnicodeDecodeError):
        data = None
    if not isinstance(data, dict) or set(data) != required_keys:
        raise ValidationFailedError(
            "invalid cursor", errors=[FieldError("cursor", "invalid_cursor", "malformed cursor")]
        )
    return data
