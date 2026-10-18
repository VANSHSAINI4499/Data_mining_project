"""Canonical validation and normalisation (DATA_INGESTION.md §5, DATA_DICTIONARY.md §3).

Explicit typed validators (rather than a Pydantic model) so every failure maps to one code in
the rejection catalogue. Rule: an invalid *required* field rejects the record; an invalid
*optional* field becomes NULL and is counted as a warning.
"""

from __future__ import annotations

import functools
import ipaddress
import math
import re
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from zoneinfo import ZoneInfo

from app.core import clock
from app.ingestion import errors as E
from app.ingestion.errors import BatchFatalError, Rejection, excerpt
from app.ingestion.records import BatchContext

NORMALIZER_VERSION = "1.0.0"

EVENT_TYPES = frozenset(
    {
        "network_flow",
        "ids_alert",
        "auth",
        "endpoint_process",
        "endpoint_file",
        "endpoint_network",
        "dns",
        "http",
        "other",
    }
)
DIRECTIONS = frozenset({"inbound", "outbound", "internal", "external", "unknown"})
AUTH_RESULTS = frozenset({"success", "failure", "unknown"})
AUTH_METHODS = frozenset({"password", "publickey", "kerberos", "mfa", "other", "unknown"})
TIME_QUALITY = frozenset({"exact", "second", "assumed"})
PROTO_BY_NUMBER = {1: "icmp", 6: "tcp", 17: "udp", 58: "icmpv6"}
NUMBER_BY_PROTO = {name: number for number, name in PROTO_BY_NUMBER.items()}
# dim_date covers 2000-01-01 .. 2040-12-31 and fact_security_event.date_key references it.
MIN_EVENT_TIME = datetime(2000, 1, 1, tzinfo=UTC)
FUTURE_TOLERANCE = timedelta(hours=24)
TRUNCATED = "TRUNCATED"

_PROTO_KEYWORD = re.compile(r"^[a-z][a-z0-9+._-]{0,31}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_MISSING = frozenset({"", "-", "(empty)", "nan", "null", "none", "n/a"})


class FieldError(Exception):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


def is_missing(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, float) and math.isnan(value):
        return True
    return isinstance(value, str) and value.strip().lower() in _MISSING


# --- primitive parsers -------------------------------------------------------------------------


def parse_number(value: Any) -> float:
    if isinstance(value, bool):
        raise FieldError(E.INVALID_NUMBER, f"boolean is not a number: {excerpt(value)}")
    if isinstance(value, int | float):
        number = float(value)
    else:
        text = str(value).strip()
        try:
            number = float(text)
        except ValueError as exc:
            raise FieldError(E.INVALID_NUMBER, f"not a number: {excerpt(value)}") from exc
    if not math.isfinite(number):
        raise FieldError(E.INVALID_NUMBER, f"not a finite number: {excerpt(value)}")
    return number


def parse_int(value: Any) -> int:
    number = parse_number(value)
    if not number.is_integer():
        raise FieldError(E.INVALID_NUMBER, f"not an integer: {excerpt(value)}")
    return int(number)


def parse_counter(value: Any) -> int:
    number = parse_int(value)
    if number < 0:
        raise FieldError(E.NEGATIVE_COUNTER, f"negative counter: {excerpt(value)}")
    return number


def parse_nonneg_float(value: Any) -> float:
    number = parse_number(value)
    if number < 0:
        raise FieldError(E.NEGATIVE_COUNTER, f"negative value: {excerpt(value)}")
    return number


def parse_port(value: Any) -> int:
    if isinstance(value, str) and value.strip().lower().startswith("0x"):
        try:
            port = int(value.strip(), 16)  # explicit hex notation seen in some datasets
        except ValueError as exc:
            raise FieldError(E.INVALID_PORT, f"invalid port: {excerpt(value)}") from exc
    else:
        try:
            port = parse_int(value)
        except FieldError as exc:
            raise FieldError(E.INVALID_PORT, f"invalid port: {excerpt(value)}") from exc
    if not 0 <= port <= 65535:
        raise FieldError(E.INVALID_PORT, f"port outside 0-65535: {excerpt(value)}")
    return port


def parse_ip(value: Any) -> str:
    text = str(value).strip()
    result = _canonical_ip(text)
    if result is None:
        raise FieldError(E.INVALID_IP, f"invalid IP address: {excerpt(value)}")
    return result


@functools.lru_cache(maxsize=65_536)
def _canonical_ip(text: str) -> str | None:
    """Canonical text form, or None if invalid (cached: logs repeat the same addresses)."""
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return str(address)


@dataclass
class ParsedTime:
    value: datetime
    fractional: bool
    naive: bool


def parse_timestamp(value: Any, timezone: str | None) -> ParsedTime:
    """datetime / epoch seconds (number or numeric string) / ISO-8601 string -> aware UTC."""
    fractional = False
    if isinstance(value, datetime):
        moment = value
        fractional = value.microsecond != 0
    elif isinstance(value, int | float) and not isinstance(value, bool):
        seconds = parse_number(value)
        fractional = not float(seconds).is_integer()
        try:
            moment = datetime.fromtimestamp(seconds, tz=UTC)
        except (OverflowError, OSError, ValueError) as exc:
            raise FieldError(E.INVALID_TIMESTAMP, f"epoch out of range: {excerpt(value)}") from exc
    else:
        text = str(value).strip()
        if _looks_numeric(text):
            return parse_timestamp(float(text), timezone)
        return _iso(text, timezone)
    naive = moment.tzinfo is None
    if naive:
        moment = _localize(moment, timezone)
    return ParsedTime(moment.astimezone(UTC), fractional, naive)


def _looks_numeric(text: str) -> bool:
    return bool(re.fullmatch(r"[+-]?\d+(\.\d+)?", text))


def _iso(text: str, timezone: str | None) -> ParsedTime:
    try:
        moment = datetime.fromisoformat(text)
    except ValueError as exc:
        raise FieldError(E.INVALID_TIMESTAMP, f"unparseable timestamp: {excerpt(text)}") from exc
    fractional = moment.microsecond != 0 or "." in text.split("T")[-1].split(" ")[-1]
    naive = moment.tzinfo is None
    if naive:
        moment = _localize(moment, timezone)
    return ParsedTime(moment.astimezone(UTC), fractional, naive)


def _localize(moment: datetime, timezone: str | None) -> datetime:
    if timezone is None:
        raise BatchFatalError(
            E.TIMEZONE_NOT_CONFIGURED,
            "timestamps have no timezone and the source has no default_timezone configured",
        )
    return moment.replace(tzinfo=ZoneInfo(timezone))


def clean_text(value: Any, max_len: int, *, strip_controls: bool = False) -> tuple[str, bool]:
    text = str(value).replace("\x00", "")
    if strip_controls:
        text = _CONTROL.sub("", text)
    text = text.strip()
    if len(text) > max_len:
        return text[:max_len], True
    return text, False


# --- field specifications ----------------------------------------------------------------------


@dataclass(frozen=True)
class FieldSpec:
    kind: str
    max_len: int = 0
    choices: frozenset[str] = frozenset()


SPECS: dict[str, FieldSpec] = {
    "event_type": FieldSpec("enum", choices=EVENT_TYPES),
    "time_quality": FieldSpec("enum", choices=TIME_QUALITY),
    "source_event_id": FieldSpec("text", 128),
    "src_ip": FieldSpec("ip"),
    "dst_ip": FieldSpec("ip"),
    "src_port": FieldSpec("port"),
    "dst_port": FieldSpec("port"),
    "protocol": FieldSpec("protocol"),
    "ip_proto": FieldSpec("ip_proto"),
    "app_protocol": FieldSpec("lower_text", 32),
    "direction": FieldSpec("enum", choices=DIRECTIONS),
    "conn_state": FieldSpec("text", 16),
    "duration_s": FieldSpec("nonneg_float"),
    "bytes_out": FieldSpec("counter"),
    "bytes_in": FieldSpec("counter"),
    "packets_out": FieldSpec("counter"),
    "packets_in": FieldSpec("counter"),
    "user_name": FieldSpec("control_text", 256),
    "auth_result": FieldSpec("enum", choices=AUTH_RESULTS),
    "auth_method": FieldSpec("enum", choices=AUTH_METHODS),
    "service": FieldSpec("text", 64),
    "host_name": FieldSpec("control_text", 255),
    "process_name": FieldSpec("text", 260),
    "process_command_line": FieldSpec("text", 32 * 1024),
    "parent_process_name": FieldSpec("text", 260),
    "file_path": FieldSpec("text", 4096),
    "file_sha256": FieldSpec("sha256"),
    "dns_query": FieldSpec("domain", 253),
    "http_host": FieldSpec("domain", 253),
    "url": FieldSpec("text", 8192),
    "signature_id": FieldSpec("counter"),
    "signature": FieldSpec("text", 1024),
    "alert_category": FieldSpec("text", 256),
    "source_severity": FieldSpec("smallint"),
}
TIME_FIELDS = ("event_time", "event_end_time")
CANONICAL_FIELDS = frozenset(SPECS) | frozenset(TIME_FIELDS)

REQUIRED_BY_TYPE: dict[str, tuple[str, ...]] = {
    "ids_alert": ("signature_id",),
    "auth": ("user_name", "auth_result"),
    "endpoint_process": ("host_name",),
    "endpoint_file": ("host_name",),
    "endpoint_network": ("host_name",),
}
# Network flows need endpoints unless the time (and usually the IPs) were not provided at all,
# i.e. dataset "features only" variants loaded with an assumed date (DATA_INGESTION.md §4.2).
FLOW_ENDPOINTS = ("src_ip", "dst_ip")


def _parse_field(name: str, spec: FieldSpec, value: Any) -> tuple[Any, bool]:
    """Returns (normalised value, truncated). Raises FieldError."""
    kind = spec.kind
    if kind == "enum":
        text = str(value).strip().lower()
        if text not in spec.choices:
            code = E.UNKNOWN_EVENT_TYPE if name == "event_type" else E.INVALID_VALUE
            raise FieldError(code, f"unsupported {name}: {excerpt(value)}")
        return text, False
    if kind == "ip":
        return parse_ip(value), False
    if kind == "port":
        return parse_port(value), False
    if kind == "counter":
        return parse_counter(value), False
    if kind == "nonneg_float":
        return parse_nonneg_float(value), False
    if kind == "smallint":
        number = parse_int(value)
        if not -32768 <= number <= 32767:
            raise FieldError(E.INVALID_NUMBER, f"out of range: {excerpt(value)}")
        return number, False
    if kind == "ip_proto":
        number = parse_int(value)
        if not 0 <= number <= 255:
            raise FieldError(E.INVALID_NUMBER, f"IP protocol number out of range: {excerpt(value)}")
        return number, False
    if kind == "protocol":
        return _protocol(value), False
    if kind == "sha256":
        text = str(value).strip().lower()
        if not _SHA256.match(text):
            raise FieldError(E.INVALID_VALUE, f"not a SHA-256 hex digest: {excerpt(value)}")
        return text, False
    if kind == "domain":
        text, truncated = clean_text(value, spec.max_len, strip_controls=True)
        return text.lower().rstrip("."), truncated
    if kind == "lower_text":
        text, truncated = clean_text(value, spec.max_len, strip_controls=True)
        return text.lower(), truncated
    if kind == "control_text":
        return clean_text(value, spec.max_len, strip_controls=True)
    return clean_text(value, spec.max_len)


def _protocol(value: Any) -> str | int:
    if isinstance(value, int) or (isinstance(value, str) and value.strip().isdigit()):
        return int(value)  # resolved to (protocol, ip_proto) by the caller
    text = str(value).strip().lower()
    if not _PROTO_KEYWORD.match(text):
        raise FieldError(E.INVALID_VALUE, f"invalid protocol: {excerpt(value)}")
    return text


@dataclass
class Normalized:
    values: dict[str, Any]
    warnings: list[tuple[str, str]] = field(default_factory=list)  # (field, code)
    naive_timestamp: bool = False


def normalize_event(
    raw_fields: dict[str, Any], ctx: BatchContext, now: Callable[[], datetime] = clock.now
) -> Normalized | Rejection:
    unknown = set(raw_fields) - CANONICAL_FIELDS
    if unknown:  # adapters must route extras to attributes; this is a programming error
        raise ValueError(f"non-canonical fields from adapter: {sorted(unknown)}")
    values: dict[str, Any] = {}
    warnings: list[tuple[str, str]] = []

    event_type = raw_fields.get("event_type")
    if is_missing(event_type):
        return Rejection(E.MISSING_REQUIRED_FIELD, "event_type is required", "event_type")
    required = set(REQUIRED_BY_TYPE.get(str(event_type).strip().lower(), ()))
    required.add("event_type")

    for name, spec in SPECS.items():
        value = raw_fields.get(name)
        if value is None or is_missing(value):  # inline None check: most fields are absent
            if name in required:
                return Rejection(E.MISSING_REQUIRED_FIELD, f"{name} is required", name)
            values[name] = None
            continue
        try:
            parsed, truncated = _parse_field(name, spec, value)
        except FieldError as exc:
            if name in required:
                return Rejection(exc.code, exc.detail, name)
            warnings.append((name, exc.code))
            values[name] = None
            continue
        if truncated:
            warnings.append((name, TRUNCATED))
        values[name] = parsed

    # protocol <-> ip_proto
    proto = values.get("protocol")
    if isinstance(proto, int):  # numeric protocol given in the protocol field
        if not 0 <= proto <= 255:
            warnings.append(("protocol", E.INVALID_VALUE))
            values["protocol"] = None
        else:
            if values.get("ip_proto") is None:
                values["ip_proto"] = proto
            values["protocol"] = PROTO_BY_NUMBER.get(proto, "unknown")
    elif isinstance(proto, str) and values.get("ip_proto") is None:
        values["ip_proto"] = NUMBER_BY_PROTO.get(proto)

    # time
    if is_missing(raw_fields.get("event_time")):
        return Rejection(E.MISSING_REQUIRED_FIELD, "event_time is required", "event_time")
    naive_used = False
    try:
        start = parse_timestamp(raw_fields["event_time"], ctx.timezone)
    except FieldError as exc:
        return Rejection(exc.code, exc.detail, "event_time")
    naive_used |= start.naive
    current = now()
    if not MIN_EVENT_TIME <= start.value <= current + FUTURE_TOLERANCE:
        return Rejection(
            E.TIMESTAMP_OUT_OF_RANGE,
            f"event_time outside 2000-01-01 .. now+24h: {start.value.isoformat()}",
            "event_time",
        )
    values["event_time"] = start.value
    end_raw = raw_fields.get("event_end_time")
    values["event_end_time"] = None
    if not is_missing(end_raw):
        try:
            end = parse_timestamp(end_raw, ctx.timezone)
            naive_used |= end.naive
            if end.value < start.value:
                warnings.append(("event_end_time", E.INVALID_VALUE))
            else:
                values["event_end_time"] = end.value
        except FieldError as exc:
            warnings.append(("event_end_time", exc.code))

    if values.get("time_quality") is None:
        values["time_quality"] = "exact" if start.fractional else "second"

    if values["event_type"] == "network_flow" and values["time_quality"] != "assumed":
        for name in FLOW_ENDPOINTS:
            if values.get(name) is None:
                code = (
                    E.MISSING_REQUIRED_FIELD if is_missing(raw_fields.get(name)) else E.INVALID_IP
                )
                return Rejection(code, f"{name} is required for network_flow events", name)

    user = values.get("user_name")
    values["user_name_normalized"] = unicodedata.normalize("NFKC", user).lower() if user else None
    values["date_key"] = int(start.value.strftime("%Y%m%d"))
    values["event_hour"] = start.value.hour
    return Normalized(values, warnings, naive_used)
