"""Rejection codes and batch-level failures (DATA_INGESTION.md §7)."""

from __future__ import annotations

from dataclasses import dataclass

# Record-level codes: the record is rejected, the batch continues.
MALFORMED_CSV_ROW = "MALFORMED_CSV_ROW"
WRONG_FIELD_COUNT = "WRONG_FIELD_COUNT"
MALFORMED_JSON = "MALFORMED_JSON"
NESTING_TOO_DEEP = "NESTING_TOO_DEEP"
RECORD_TOO_LARGE = "RECORD_TOO_LARGE"
ENCODING_ERROR = "ENCODING_ERROR"
MISSING_REQUIRED_FIELD = "MISSING_REQUIRED_FIELD"
INVALID_TIMESTAMP = "INVALID_TIMESTAMP"
TIMESTAMP_OUT_OF_RANGE = "TIMESTAMP_OUT_OF_RANGE"
INVALID_IP = "INVALID_IP"
INVALID_PORT = "INVALID_PORT"
INVALID_NUMBER = "INVALID_NUMBER"
NEGATIVE_COUNTER = "NEGATIVE_COUNTER"
UNKNOWN_EVENT_TYPE = "UNKNOWN_EVENT_TYPE"
INVALID_VALUE = "INVALID_VALUE"

# Batch-level codes: processing stops and the batch is marked failed.
UNSUPPORTED_VARIANT = "UNSUPPORTED_VARIANT"
TIMEZONE_NOT_CONFIGURED = "TIMEZONE_NOT_CONFIGURED"
TIMESTAMP_FORMAT_AMBIGUOUS = "TIMESTAMP_FORMAT_AMBIGUOUS"
ADAPTER_MISMATCH_SUSPECTED = "ADAPTER_MISMATCH_SUSPECTED"
BINARY_CONTENT = "BINARY_CONTENT"
FILE_CHANGED = "FILE_CHANGED"
FILE_NOT_FOUND = "FILE_NOT_FOUND"
FILE_TOO_LARGE = "FILE_TOO_LARGE"
MISSING_OPTION = "MISSING_OPTION"
CANCELLED = "CANCELLED"
LOCK_TIMEOUT = "LOCK_TIMEOUT"

DETAIL_VALUE_MAX = 200


def excerpt(value: object) -> str:
    """Sanitised, bounded representation of an offending value for error details."""
    text = repr(value)
    return text if len(text) <= DETAIL_VALUE_MAX else text[:DETAIL_VALUE_MAX] + "…"


@dataclass(frozen=True)
class Rejection:
    code: str
    detail: str
    field: str | None = None


class BatchFatalError(Exception):
    """Stops the whole batch with a batch-level code (not retried)."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail
