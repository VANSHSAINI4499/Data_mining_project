from __future__ import annotations

import json
import logging

import pytest

from app.core.logging import REDACTED, JsonFormatter, redact_text, request_id_var

pytestmark = pytest.mark.unit


def _format(msg: str, *args: object, **extra: object) -> dict[str, object]:
    record = logging.LogRecord("t", logging.INFO, __file__, 1, msg, args or None, None)
    for key, value in extra.items():
        setattr(record, key, value)
    return json.loads(JsonFormatter().format(record))  # type: ignore[no-any-return]


def test_output_is_json_with_core_fields() -> None:
    payload = _format("hello %s", "world")
    assert payload["message"] == "hello world"
    assert payload["level"] == "INFO"
    assert "timestamp" in payload


def test_request_id_from_context_is_included() -> None:
    token = request_id_var.set("req-123")
    try:
        assert _format("x")["request_id"] == "req-123"
    finally:
        request_id_var.reset(token)


@pytest.mark.parametrize("key", ["password", "session_token", "api_key", "Authorization", "cookie"])
def test_sensitive_extra_keys_are_redacted(key: str) -> None:
    assert _format("x", **{key: "super-secret-value"})[key] == REDACTED


def test_nested_sensitive_keys_are_redacted() -> None:
    payload = _format("x", details={"user": "alice", "password": "pw", "inner": {"token": "t"}})
    assert payload["details"] == {
        "user": "alice",
        "password": REDACTED,
        "inner": {"token": REDACTED},
    }


def test_secrets_in_messages_are_redacted() -> None:
    text = redact_text("login failed password=hunter2 token: abc123 user=alice")
    assert "hunter2" not in text and "abc123" not in text
    assert "user=alice" in text


def test_credentials_in_urls_are_redacted() -> None:
    text = redact_text("cannot connect postgresql+psycopg://cti:pa55word@db:5432/cti")
    assert "pa55word" not in text
    assert "cti:" in text and "@db:5432" in text


def test_long_messages_are_truncated() -> None:
    assert len(redact_text("a" * 10_000)) < 2100
