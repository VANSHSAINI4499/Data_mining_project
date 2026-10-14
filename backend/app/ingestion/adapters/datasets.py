"""Public dataset adapters: CIC-IDS2017 and UNSW-NB15 (DATA_INGESTION.md §4.1-4.3).

Rules: detect variants from headers (never assume), keep every non-canonical column in
``attributes`` (numbers parsed, non-finite values stored as null and counted), map labels
through versioned files, and never fabricate timestamps or IPs.
"""

from __future__ import annotations

import math
import re
import tomllib
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import IO, Any, ClassVar

from app.core.config import REPO_ROOT
from app.ingestion import errors as E
from app.ingestion.adapters.base import Adapter, attribute_key, register
from app.ingestion.errors import BatchFatalError, Rejection
from app.ingestion.normalize import FieldError, is_missing
from app.ingestion.readers import DelimitedReader
from app.ingestion.records import MappedRecord, RawRecord

DATASET_CONFIG_DIR = REPO_ROOT / "config" / "datasets"
NON_FINITE = frozenset({"inf", "+inf", "-inf", "infinity", "+infinity", "-infinity", "nan"})


def numeric_attribute(value: Any) -> tuple[Any, bool]:
    """Parse a numeric-looking attribute. Returns (value, was_non_finite)."""
    if value is None:
        return None, False
    text = str(value).strip()
    if text.lower() in NON_FINITE:
        return None, True
    if text == "":
        return None, False
    try:
        number = float(text)
    except ValueError:
        return text, False
    if not math.isfinite(number):
        return None, True
    return (
        int(number)
        if number.is_integer() and "." not in text and "e" not in text.lower()
        else number
    ), False


def _assumed_time(adapter: Adapter) -> str:
    assumed = adapter.ctx.assume_event_date
    if assumed is None:
        raise BatchFatalError(
            E.MISSING_OPTION,
            "this file variant has no timestamps: pass --assume-event-date (the date is recorded "
            "as an assumption and these events are classification-only)",
        )
    return datetime(assumed.year, assumed.month, assumed.day, tzinfo=UTC).isoformat()


def _missing_columns(columns: list[str], required: frozenset[str]) -> list[str]:
    return sorted(required - set(columns))


# --- CIC-IDS2017 ----------------------------------------------------------------------

CIC_BASE = frozenset(
    {
        "destination port",
        "flow duration",
        "total fwd packets",
        "total backward packets",
        "total length of fwd packets",
        "total length of bwd packets",
        "label",
    }
)
CIC_IDS = frozenset({"source ip", "source port", "destination ip", "protocol", "timestamp"})
CIC_CANONICAL = {
    "flow id": "source_event_id",
    "source ip": "src_ip",
    "source port": "src_port",
    "destination ip": "dst_ip",
    "destination port": "dst_port",
    "protocol": "protocol",
    "total fwd packets": "packets_out",
    "total backward packets": "packets_in",
    "total length of fwd packets": "bytes_out",
    "total length of bwd packets": "bytes_in",
}
# CICFlowMeter reports Flow Duration in microseconds (verify against your copy's documentation).
FLOW_DURATION_UNIT_SECONDS = 1e-6
_CIC_TS = re.compile(
    r"^(\d{1,2})/(\d{1,2})/(\d{4}) (\d{1,2}):(\d{2})(?::(\d{2}))?(?:\s*([AaPp][Mm]))?$"
)


def parse_cic_timestamp(text: str, date_order: str | None) -> datetime:
    """``D/M/YYYY H:MM[:SS] [AM|PM]`` with explicit handling of day/month ambiguity."""
    match = _CIC_TS.match(text.strip())
    if match is None:
        try:
            return datetime.fromisoformat(text.strip())
        except ValueError as exc:
            raise FieldError(E.INVALID_TIMESTAMP, f"unrecognised timestamp {text[:40]!r}") from exc
    a, b, year, hour, minute, second, ampm = match.groups()
    first, second_part = int(a), int(b)
    if first > 12 and second_part > 12:
        raise FieldError(E.INVALID_TIMESTAMP, f"invalid date {text[:40]!r}")
    if first > 12:
        order = "dmy"
    elif second_part > 12:
        order = "mdy"
    elif first == second_part:
        order = date_order or "dmy"  # identical day and month: order does not matter
    elif date_order is None:
        raise BatchFatalError(
            E.TIMESTAMP_FORMAT_AMBIGUOUS,
            f"timestamp {text[:40]!r} could be day/month or month/day: pass --date-order dmy|mdy",
        )
    else:
        order = date_order
    if date_order is not None and order != date_order and first != second_part:
        raise FieldError(
            E.INVALID_TIMESTAMP, f"timestamp {text[:40]!r} contradicts date order {date_order}"
        )
    day, month = (first, second_part) if order == "dmy" else (second_part, first)
    h = int(hour)
    if ampm:
        if not 1 <= h <= 12:
            raise FieldError(E.INVALID_TIMESTAMP, f"invalid 12-hour time {text[:40]!r}")
        h = h % 12 + (12 if ampm.lower() == "pm" else 0)
    try:
        return datetime(int(year), month, day, h, int(minute), int(second or 0))  # naive
    except ValueError as exc:
        raise FieldError(E.INVALID_TIMESTAMP, f"invalid date {text[:40]!r}") from exc


@register
class CicIds2017Adapter(Adapter):
    name = "cicids2017"
    version = "1.0"
    description = (
        "CIC-IDS2017 CICFlowMeter CSV. Variants: flows_with_ids (IPs + Timestamp; needs the "
        "source timezone) and features_only (needs --assume-event-date; classification only)."
    )
    extensions = frozenset({".csv"})
    event_types = ("network_flow",)
    variants = ("flows_with_ids", "features_only")
    encodings = ("utf-8", "cp1252")
    label_mapping = "cicids2017"
    expected_fields: ClassVar[dict[str, float]] = {
        "dst_port": 0.01,
        "duration_s": 0.01,
        "packets_out": 0.01,
    }

    def read(self, stream: IO[bytes]) -> Iterator[RawRecord]:
        reader = DelimitedReader(stream, self.encodings, self.stats)
        columns = reader.read_header()
        self.metadata["header_map"] = reader.header_map
        duplicated = [m["normalized"] for m in reader.header_map if "__" in m["normalized"]]
        if duplicated:
            self.metadata["duplicated_headers"] = duplicated
        missing = _missing_columns(columns, CIC_BASE)
        if missing:
            raise BatchFatalError(E.UNSUPPORTED_VARIANT, f"missing required columns: {missing}")
        detected = "flows_with_ids" if not _missing_columns(columns, CIC_IDS) else "features_only"
        if self.ctx.variant is not None and self.ctx.variant != detected:
            raise BatchFatalError(
                E.UNSUPPORTED_VARIANT,
                f"requested variant {self.ctx.variant} but the header matches {detected}"
                + (
                    f" (missing {_missing_columns(columns, CIC_IDS)})"
                    if detected == "features_only"
                    else ""
                ),
            )
        self.metadata["variant"] = detected
        if detected == "flows_with_ids" and self.ctx.timezone is None:
            raise BatchFatalError(
                E.TIMEZONE_NOT_CONFIGURED,
                "CIC-IDS2017 timestamps are local capture time without a timezone: set the "
                "source's default_timezone or pass --timezone (record your evidence; OD-4)",
            )
        if detected == "features_only":
            _assumed_time(self)
        self.metadata["non_finite_values"] = 0
        yield from reader.records()

    def map(self, raw: RawRecord) -> MappedRecord | Rejection:
        row: dict[str, str] = raw.payload
        fields: dict[str, Any] = {"event_type": "network_flow"}
        for column, target in CIC_CANONICAL.items():
            if column in row:
                fields[target] = row[column]
        duration, non_finite = numeric_attribute(row.get("flow duration"))
        if non_finite:
            self.metadata["non_finite_values"] += 1
        if isinstance(duration, int | float):
            fields["duration_s"] = duration * FLOW_DURATION_UNIT_SECONDS
        if self.metadata["variant"] == "flows_with_ids":
            try:
                fields["event_time"] = parse_cic_timestamp(row["timestamp"], self.ctx.date_order)
            except FieldError as exc:
                return Rejection(exc.code, exc.detail, "event_time")
        else:
            fields["event_time"] = _assumed_time(self)
            fields["time_quality"] = "assumed"
        attributes: dict[str, Any] = {}
        for column, value in row.items():
            if column in CIC_CANONICAL or column in ("timestamp", "label"):
                continue
            parsed, non_finite = numeric_attribute(value)
            if non_finite:
                self.metadata["non_finite_values"] += 1
            attributes[attribute_key(column)] = parsed
        label = (row.get("label") or "").strip()
        extra: tuple[Any, ...] = ()
        if self.metadata["variant"] == "features_only":
            extra = (raw.record_number,)  # repeated feature rows are real rows, not duplicates
        return MappedRecord(
            fields=fields, attributes=attributes, label_raw=label, fingerprint_extra=extra
        )

    def fingerprint_values(self, values: dict[str, Any], mapped: MappedRecord) -> list[Any]:
        keys = (
            "src_ip",
            "src_port",
            "dst_ip",
            "dst_port",
            "ip_proto",
            "event_time",
            "duration_s",
            "packets_out",
            "packets_in",
            "bytes_out",
            "bytes_in",
        )
        return [*(values.get(k) for k in keys), mapped.label_raw, *mapped.fingerprint_extra]


# --- UNSW-NB15 ------------------------------------------------------------------------

UNSW_PARTITION_REQUIRED = frozenset(
    {
        "id",
        "dur",
        "proto",
        "spkts",
        "dpkts",
        "sbytes",
        "dbytes",
        "attack_cat",
        "label",
    }
)
UNSW_RAW_CANONICAL = {
    "srcip": "src_ip",
    "sport": "src_port",
    "dstip": "dst_ip",
    "dsport": "dst_port",
    "proto": "protocol",
    "state": "conn_state",
    "dur": "duration_s",
    "sbytes": "bytes_out",
    "dbytes": "bytes_in",
    "spkts": "packets_out",
    "dpkts": "packets_in",
    "service": "app_protocol",
    "stime": "event_time",
    "ltime": "event_end_time",
}
UNSW_PARTITION_CANONICAL = {
    "dur": "duration_s",
    "proto": "protocol",
    "state": "conn_state",
    "sbytes": "bytes_out",
    "dbytes": "bytes_in",
    "spkts": "packets_out",
    "dpkts": "packets_in",
    "service": "app_protocol",
}
_IPV4 = re.compile(rb"^\d{1,3}(\.\d{1,3}){3}$")


def unsw_raw_columns() -> list[str]:
    with (DATASET_CONFIG_DIR / "unsw_nb15_columns.toml").open("rb") as fh:
        return [str(c).lower() for c in tomllib.load(fh)["columns"]]


@register
class UnswNb15Adapter(Adapter):
    name = "unsw_nb15"
    version = "1.0"
    description = (
        "UNSW-NB15 CSV. Variants: raw_records (header-less UNSW-NB15_1..4.csv; column spec in "
        "config/datasets) and partition (training/testing set CSVs; needs "
        "--assume-event-date; classification only)."
    )
    extensions = frozenset({".csv"})
    event_types = ("network_flow",)
    variants = ("raw_records", "partition")
    encodings = ("utf-8", "cp1252")
    label_mapping = "unsw_nb15"
    expected_fields: ClassVar[dict[str, float]] = {"duration_s": 0.01, "packets_out": 0.01}

    def read(self, stream: IO[bytes]) -> Iterator[RawRecord]:
        head = stream.readline(4096)
        stream.seek(0)
        first_field = head.split(b",", 1)[0].strip().lstrip(b"\xef\xbb\xbf")
        detected = "raw_records" if _IPV4.match(first_field) else "partition"
        if self.ctx.variant is not None and self.ctx.variant != detected:
            raise BatchFatalError(
                E.UNSUPPORTED_VARIANT,
                f"requested variant {self.ctx.variant} but the file looks like {detected}",
            )
        self.metadata["variant"] = detected
        self.metadata["non_finite_values"] = 0
        if detected == "raw_records":
            columns = unsw_raw_columns()
            reader = DelimitedReader(stream, self.encodings, self.stats, header=columns)
            self.metadata["column_spec"] = "config/datasets/unsw_nb15_columns.toml"
        else:
            reader = DelimitedReader(stream, self.encodings, self.stats)
            columns = reader.read_header()
            self.metadata["header_map"] = reader.header_map
            missing = _missing_columns(columns, UNSW_PARTITION_REQUIRED)
            if missing:
                raise BatchFatalError(E.UNSUPPORTED_VARIANT, f"missing required columns: {missing}")
            _assumed_time(self)
            self.metadata["dataset_partition"] = self.ctx.dataset_partition
        yield from reader.records()

    def map(self, raw: RawRecord) -> MappedRecord | Rejection:
        row: dict[str, str] = raw.payload
        raw_variant = self.metadata["variant"] == "raw_records"
        mapping = UNSW_RAW_CANONICAL if raw_variant else UNSW_PARTITION_CANONICAL
        fields: dict[str, Any] = {"event_type": "network_flow"}
        for column, target in mapping.items():
            value = row.get(column)
            fields[target] = None if value is None or is_missing(value) else value.strip()
        if not raw_variant:
            fields["event_time"] = _assumed_time(self)
            fields["time_quality"] = "assumed"
        attributes: dict[str, Any] = {}
        for column, value in row.items():
            if column in mapping or column in ("attack_cat", "label"):
                continue
            parsed, non_finite = numeric_attribute(value)
            if non_finite:
                self.metadata["non_finite_values"] += 1
            attributes[attribute_key(column)] = parsed
        attack_cat = (row.get("attack_cat") or "").strip()
        label = (row.get("label") or "").strip()
        is_attack = {"0": False, "1": True}.get(label)
        if label and is_attack is None:
            return Rejection(E.INVALID_VALUE, f"label must be 0 or 1, got {label[:20]!r}", "label")
        extra = () if raw_variant else (row.get("id"), self.ctx.dataset_partition)
        return MappedRecord(
            fields=fields,
            attributes=attributes,
            label_raw=attack_cat,
            is_attack=is_attack,
            fingerprint_extra=extra,
        )

    def fingerprint_values(self, values: dict[str, Any], mapped: MappedRecord) -> list[Any]:
        keys = (
            "src_ip",
            "src_port",
            "dst_ip",
            "dst_port",
            "protocol",
            "event_time",
            "event_end_time",
            "duration_s",
            "bytes_out",
            "bytes_in",
            "packets_out",
            "packets_in",
        )
        return [
            *(values.get(k) for k in keys),
            mapped.label_raw,
            mapped.is_attack,
            *mapped.fingerprint_extra,
        ]
