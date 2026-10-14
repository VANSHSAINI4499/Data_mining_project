"""Data carried through the ingestion pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from typing import Any

from app.ingestion.errors import Rejection


@dataclass
class RawRecord:
    """One record exactly as read. ``payload`` is the parsed structure (CSV row as a mapping of
    original header -> value, or a JSON object); ``raw_text`` holds the original text when it
    could not be parsed. ``sha256`` is computed over the original bytes."""

    record_number: int
    sha256: str
    payload: Any = None
    raw_text: str | None = None
    truncated: bool = False
    problem: Rejection | None = None  # structural failure detected while reading


@dataclass
class MappedRecord:
    """Adapter output: canonical field values (not yet validated) plus extras."""

    fields: dict[str, Any]
    attributes: dict[str, Any] = field(default_factory=dict)
    label_raw: str | None = None
    is_attack: bool | None = None
    # Extra values the adapter wants in the fingerprint beyond canonical fields.
    fingerprint_extra: tuple[Any, ...] = ()


@dataclass(frozen=True)
class BatchContext:
    """Per-batch settings an adapter may need."""

    source_key: str
    timezone: str | None
    assume_event_date: date | None = None
    variant: str | None = None
    date_order: str | None = None  # "dmy" | "mdy" for ambiguous day/month timestamps
    dataset_partition: str | None = None  # e.g. "training" | "testing" (UNSW-NB15)
