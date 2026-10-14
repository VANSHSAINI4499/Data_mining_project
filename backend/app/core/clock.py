"""Injectable clock so time-dependent logic is testable without patching libraries."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime


def _utc_now() -> datetime:
    return datetime.now(UTC)


_clock: list[Callable[[], datetime]] = [_utc_now]


def now() -> datetime:
    return _clock[0]()


def set_clock(fn: Callable[[], datetime] | None) -> None:
    """Override the clock (tests only). ``None`` restores real UTC time."""
    _clock[0] = fn if fn is not None else _utc_now
