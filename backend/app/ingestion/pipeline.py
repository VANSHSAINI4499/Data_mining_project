"""Per-record pipeline: raw -> mapped -> validated/normalised -> fingerprinted (pure)."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from app.ingestion.adapters.base import Adapter
from app.ingestion.errors import Rejection
from app.ingestion.fingerprint import fingerprint
from app.ingestion.labels import LabelMapping
from app.ingestion.normalize import NORMALIZER_VERSION, normalize_event
from app.ingestion.records import RawRecord

MAX_ATTRIBUTES_BYTES = 64 * 1024
ATTRIBUTES_TOO_LARGE = "ATTRIBUTES_TOO_LARGE"


@dataclass
class GroundTruth:
    label_raw: str
    category_code: str | None
    is_attack: bool | None
    mapping_status: str
    mapping_version: str


@dataclass
class Prepared:
    raw: RawRecord
    event: dict[str, Any] | None = None
    ground_truth: GroundTruth | None = None
    rejection: Rejection | None = None
    warnings: list[tuple[str, str]] = field(default_factory=list)
    naive_timestamp: bool = False


def prepare_record(adapter: Adapter, raw: RawRecord, mapping: LabelMapping | None) -> Prepared:
    if raw.problem is not None:
        return Prepared(raw, rejection=raw.problem)
    mapped = adapter.map(raw)
    if isinstance(mapped, Rejection):
        return Prepared(raw, rejection=mapped)
    normalized = normalize_event(mapped.fields, adapter.ctx)
    if isinstance(normalized, Rejection):
        return Prepared(raw, rejection=normalized)

    values = normalized.values
    warnings = list(normalized.warnings)
    attributes = mapped.attributes
    if len(json.dumps(attributes, default=str)) > MAX_ATTRIBUTES_BYTES:
        warnings.append(("attributes", ATTRIBUTES_TOO_LARGE))
        attributes = {}
    values["attributes"] = attributes
    values["event_fingerprint"] = fingerprint(
        adapter.name, adapter.version, adapter.fingerprint_values(values, mapped)
    )
    values["adapter_version"] = adapter.tag
    values["normalizer_version"] = NORMALIZER_VERSION

    ground_truth = None
    if mapped.label_raw is not None:
        if mapping is None:
            code, status, version = None, "unmapped", f"{adapter.name}@none"
        else:
            code, status = mapping.map(mapped.label_raw, mapped.is_attack)
            version = mapping.version_tag
        ground_truth = GroundTruth(mapped.label_raw, code, mapped.is_attack, status, version)
    return Prepared(
        raw, values, ground_truth, warnings=warnings, naive_timestamp=normalized.naive_timestamp
    )
