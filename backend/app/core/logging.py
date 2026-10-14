"""Structured JSON logging with request/job context and secret redaction.

Rules (DEVELOPMENT_RULES.md §7): never log secrets, tokens, passwords, or full untrusted
strings. The redaction here is a safety net, not a licence to pass secrets to the logger.
"""

from __future__ import annotations

import json
import logging
import re
import sys
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import Any

request_id_var: ContextVar[str | None] = ContextVar("request_id", default=None)
job_id_var: ContextVar[str | None] = ContextVar("job_id", default=None)
user_id_var: ContextVar[str | None] = ContextVar("user_id", default=None)
client_ip_var: ContextVar[str | None] = ContextVar("client_ip", default=None)

REDACTED = "[REDACTED]"
SENSITIVE_KEY = re.compile(r"password|secret|token|key|authorization|cookie|credential", re.I)
# key=value or key: value pairs inside free-text messages
SENSITIVE_PAIR = re.compile(
    r"(?i)\b([\w.-]*(?:password|secret|token|apikey|api_key|authorization|cookie)[\w.-]*)"
    r"(\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|[^\s,;&]+)"
)
# credentials embedded in connection URLs: scheme://user:password@host
URL_CREDENTIALS = re.compile(r"(\b[a-z][a-z0-9+.-]*://[^:/\s@]+:)([^@\s]+)(@)", re.I)

MAX_STRING = 2000

# Attributes present on every LogRecord; anything else came from `extra=`.
_STANDARD_ATTRS = frozenset(
    vars(logging.LogRecord("x", logging.INFO, "x", 0, "x", None, None)).keys()
) | {"message", "asctime", "taskName"}


def redact_text(text: str) -> str:
    text = URL_CREDENTIALS.sub(rf"\g<1>{REDACTED}\g<3>", text)
    text = SENSITIVE_PAIR.sub(rf"\g<1>\g<2>{REDACTED}", text)
    if len(text) > MAX_STRING:
        text = text[:MAX_STRING] + "…[truncated]"
    return text


def redact_value(key: str, value: Any) -> Any:
    if SENSITIVE_KEY.search(key):
        return REDACTED
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return {str(k): redact_value(str(k), v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [redact_value(key, v) for v in value]
    if isinstance(value, int | float | bool) or value is None:
        return value
    return redact_text(str(value))


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": redact_text(record.getMessage()),
        }
        for name, var in (
            ("request_id", request_id_var),
            ("job_id", job_id_var),
            ("user_id", user_id_var),
        ):
            value = var.get()
            if value is not None:
                payload[name] = value
        for key, value in record.__dict__.items():
            if key not in _STANDARD_ATTRS and not key.startswith("_"):
                payload[key] = redact_value(key, value)
        if record.exc_info:
            payload["exception"] = redact_text(self.formatException(record.exc_info))
        return json.dumps(payload, default=str, ensure_ascii=False)


def configure_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level)
    # uvicorn installs its own handlers; route them through ours.
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        lg = logging.getLogger(name)
        lg.handlers.clear()
        lg.propagate = True
