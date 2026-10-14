"""Canonical CSV / JSON / JSONL adapters: columns or keys use canonical field names.

Recognised extra columns: ``label_raw`` (dataset label, mapped through the ``canonical``
label mapping) and ``is_attack``. Every other column goes to ``attributes``.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import IO, Any

from app.ingestion import errors as E
from app.ingestion.adapters.base import Adapter, parse_bool, register, to_attributes
from app.ingestion.errors import Rejection
from app.ingestion.normalize import CANONICAL_FIELDS, is_missing
from app.ingestion.readers import DelimitedReader, read_json_array, read_jsonl
from app.ingestion.records import MappedRecord, RawRecord

LABEL_KEYS = ("label_raw", "is_attack")
ALL_EVENT_TYPES = (
    "network_flow",
    "ids_alert",
    "auth",
    "endpoint_process",
    "endpoint_file",
    "endpoint_network",
    "dns",
    "http",
    "other",
)
# A computed-only field; adapters may not supply it.
NOT_SUPPLIABLE = frozenset({"time_quality"})


def map_canonical(payload: dict[str, Any]) -> MappedRecord | Rejection:
    fields: dict[str, Any] = {}
    extras: dict[str, Any] = {}
    for key, value in payload.items():
        name = str(key).strip()
        if name in CANONICAL_FIELDS and name not in NOT_SUPPLIABLE:
            fields[name] = value
        elif name not in LABEL_KEYS:
            extras[name] = value
    label = payload.get("label_raw")
    label_raw = None if is_missing(label) else str(label).strip()[:128]
    is_attack = parse_bool(payload.get("is_attack"))
    if not is_missing(payload.get("is_attack")) and is_attack is None:
        return Rejection(E.INVALID_VALUE, "is_attack must be true/false/1/0", "is_attack")
    return MappedRecord(
        fields=fields, attributes=to_attributes(extras), label_raw=label_raw, is_attack=is_attack
    )


class _CanonicalBase(Adapter):
    version = "1.0"
    event_types = ALL_EVENT_TYPES
    label_mapping = "canonical"

    def map(self, raw: RawRecord) -> MappedRecord | Rejection:
        assert isinstance(raw.payload, dict)
        return map_canonical(raw.payload)


@register
class CanonicalCsvAdapter(_CanonicalBase):
    name = "canonical_csv"
    description = "CSV with canonical column names (DATA_DICTIONARY.md)."
    extensions = frozenset({".csv"})

    def read(self, stream: IO[bytes]) -> Iterator[RawRecord]:
        reader = DelimitedReader(stream, self.encodings, self.stats)
        reader.read_header()
        self.metadata["header_map"] = reader.header_map
        yield from reader.records()


@register
class CanonicalJsonAdapter(_CanonicalBase):
    name = "canonical_json"
    description = "A JSON array of objects with canonical keys."
    extensions = frozenset({".json"})

    def read(self, stream: IO[bytes]) -> Iterator[RawRecord]:
        yield from read_json_array(stream, self.encodings, self.stats)


@register
class CanonicalJsonlAdapter(_CanonicalBase):
    name = "canonical_jsonl"
    description = "JSON lines: one object with canonical keys per line."
    extensions = frozenset({".jsonl", ".ndjson", ".json"})

    def read(self, stream: IO[bytes]) -> Iterator[RawRecord]:
        yield from read_jsonl(stream, self.encodings, self.stats)
