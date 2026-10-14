"""Record-level deduplication key (DATA_INGESTION.md §6).

``sha256(adapter | adapter_major | canonical JSON of the identity values)``. Changing what goes
into a fingerprint changes dedup behaviour, so it requires an adapter *major* version bump.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from datetime import datetime
from typing import Any


def _canonical(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return value


def fingerprint(adapter: str, adapter_version: str, values: Sequence[Any]) -> str:
    major = adapter_version.split(".", 1)[0]
    body = json.dumps([_canonical(v) for v in values], separators=(",", ":"), default=str)
    return hashlib.sha256(f"{adapter}|{major}|{body}".encode()).hexdigest()
