from __future__ import annotations

import pytest

from app.core.errors import ValidationFailedError
from app.core.pagination import decode_cursor, encode_cursor

pytestmark = pytest.mark.unit


def test_cursor_roundtrip() -> None:
    key = {"created_at": "2026-10-14T12:00:00+00:00", "job_id": "abc"}
    assert decode_cursor(encode_cursor(key), frozenset(key)) == key


def test_none_cursor_means_first_page() -> None:
    assert decode_cursor(None, frozenset({"a"})) is None


@pytest.mark.parametrize("cursor", ["!!!", "bm90LWpzb24", encode_cursor({"other": 1}), ""])
def test_invalid_cursors_raise_validation_error(cursor: str) -> None:
    with pytest.raises(ValidationFailedError) as info:
        decode_cursor(cursor, frozenset({"username"}))
    assert info.value.errors[0].field == "cursor"
