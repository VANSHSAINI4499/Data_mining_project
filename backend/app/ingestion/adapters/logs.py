"""Log adapters: Zeek conn, Suricata EVE, auth/endpoint JSONL (DATA_INGESTION.md §4.4-4.7)."""

from __future__ import annotations

from collections.abc import Iterator
from typing import IO, Any, ClassVar

from app.ingestion import errors as E
from app.ingestion.adapters.base import Adapter, register, to_attributes
from app.ingestion.adapters.canonical import map_canonical
from app.ingestion.errors import BatchFatalError, Rejection
from app.ingestion.normalize import is_missing
from app.ingestion.readers import (
    ReadStats,
    decode,
    iter_lines,
    read_jsonl,
    sha256_hex,
    truncate_text,
)
from app.ingestion.records import MappedRecord, RawRecord


def _get(obj: dict[str, Any], dotted: str) -> Any:
    """Nested lookup ``a.b.c``; also accepts flat keys containing dots (Zeek JSON)."""
    if dotted in obj:
        return obj[dotted]
    current: Any = obj
    for part in dotted.split("."):
        if isinstance(current, list):
            current = current[0] if current else None
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


# --- Zeek conn.log -----------------------------------------------------------------------------

ZEEK_MAP = {
    "ts": "event_time",
    "uid": "source_event_id",
    "id.orig_h": "src_ip",
    "id.orig_p": "src_port",
    "id.resp_h": "dst_ip",
    "id.resp_p": "dst_port",
    "proto": "protocol",
    "service": "app_protocol",
    "duration": "duration_s",
    "orig_bytes": "bytes_out",
    "resp_bytes": "bytes_in",
    "orig_pkts": "packets_out",
    "resp_pkts": "packets_in",
    "conn_state": "conn_state",
}


def _zeek_unescape(text: str) -> str:
    return (
        text.encode("latin-1", "backslashreplace").decode("unicode_escape")
        if "\\x" in text
        else text
    )


@register
class ZeekConnAdapter(Adapter):
    name = "zeek_conn"
    version = "1.0"
    description = "Zeek conn.log in TSV (#fields header) or JSON-lines format."
    extensions = frozenset({".log", ".tsv", ".jsonl", ".json", ".ndjson"})
    event_types = ("network_flow",)
    variants = ("tsv", "json")
    expected_fields: ClassVar[dict[str, float]] = {
        "src_ip": 0.0,
        "dst_ip": 0.0,
        "dst_port": 0.05,
        "duration_s": 0.5,
    }

    def read(self, stream: IO[bytes]) -> Iterator[RawRecord]:
        head = stream.read(1)
        stream.seek(0)
        if self.ctx.variant == "json" or (self.ctx.variant is None and head == b"{"):
            self.metadata["variant"] = "json"
            yield from read_jsonl(stream, self.encodings, self.stats)
        else:
            self.metadata["variant"] = "tsv"
            yield from self._read_tsv(stream, self.stats)

    def _read_tsv(self, stream: IO[bytes], stats: ReadStats) -> Iterator[RawRecord]:
        separator, unset, empty = "\t", "-", "(empty)"
        fields: list[str] | None = None
        number = 0
        for line in iter_lines(stream):
            if line.data is not None and line.data.startswith(b"#"):
                directive = line.data.decode("utf-8", "replace")
                if directive.startswith("#separator "):
                    separator = _zeek_unescape(directive.split(" ", 1)[1].strip())
                    continue
                parts = directive.split(separator)
                key, values = parts[0][1:], parts[1:]
                if key == "unset_field" and values:
                    unset = values[0]
                elif key == "empty_field" and values:
                    empty = values[0]
                elif key == "fields":
                    fields = values
                    self.metadata["fields"] = fields
                continue
            if line.data is not None and not line.data.strip():
                continue
            if fields is None:
                raise BatchFatalError(E.UNSUPPORTED_VARIANT, "Zeek TSV file has no #fields header")
            number += 1
            digest = sha256_hex(line.raw)
            if line.data is None:
                yield RawRecord(
                    number,
                    digest,
                    raw_text=truncate_text(line.raw.decode("utf-8", "replace"))[0],
                    truncated=True,
                    problem=Rejection(E.RECORD_TOO_LARGE, "record too large"),
                )
                continue
            decoded = decode(line.data, self.encodings)
            if decoded is None:
                yield RawRecord(
                    number,
                    digest,
                    raw_text=line.data.decode("utf-8", "replace"),
                    problem=Rejection(E.ENCODING_ERROR, "not UTF-8"),
                )
                continue
            text, encoding = decoded
            stats.used(encoding)
            values = text.split(separator)
            if len(values) != len(fields):
                yield RawRecord(
                    number,
                    digest,
                    payload=values,
                    problem=Rejection(
                        E.WRONG_FIELD_COUNT, f"expected {len(fields)} fields, got {len(values)}"
                    ),
                )
                continue
            payload = {
                k: (None if v == unset else "" if v == empty else v)
                for k, v in zip(fields, values, strict=True)
            }
            yield RawRecord(number, digest, payload=payload)

    def map(self, raw: RawRecord) -> MappedRecord | Rejection:
        assert isinstance(raw.payload, dict)
        fields: dict[str, Any] = {"event_type": "network_flow"}
        for source, target in ZEEK_MAP.items():
            fields[target] = _get(raw.payload, source)
        extras = {k: v for k, v in raw.payload.items() if k not in ZEEK_MAP}
        return MappedRecord(fields=fields, attributes=to_attributes(extras))

    def fingerprint_values(self, values: dict[str, Any], mapped: MappedRecord) -> list[Any]:
        return [
            values.get("source_event_id"),
            values.get("event_time"),
            values.get("src_ip"),
            values.get("dst_ip"),
            values.get("dst_port"),
        ]


# --- Suricata EVE --------------------------------------------------------------------------------

EVE_TYPE_MAP = {"alert": "ids_alert", "flow": "network_flow", "dns": "dns", "http": "http"}
# Field locations differ between Suricata versions; the first non-empty path wins.
DNS_QUERY_PATHS = ("dns.rrname", "dns.queries.rrname", "dns.query.rrname")
HTTP_HOST_PATHS = ("http.hostname",)
HTTP_URL_PATHS = ("http.url",)


def _first(obj: dict[str, Any], paths: tuple[str, ...]) -> Any:
    for path in paths:
        value = _get(obj, path)
        if not is_missing(value):
            return value
    return None


@register
class SuricataEveAdapter(Adapter):
    name = "suricata_eve"
    version = "1.0"
    description = "Suricata EVE JSON lines (alert, flow, dns, http; other types kept as 'other')."
    extensions = frozenset({".json", ".jsonl", ".ndjson", ".log"})
    event_types = ("ids_alert", "network_flow", "dns", "http", "other")
    expected_fields: ClassVar[dict[str, float]] = {"src_ip": 0.05, "dst_ip": 0.05}

    def read(self, stream: IO[bytes]) -> Iterator[RawRecord]:
        yield from read_jsonl(stream, self.encodings, self.stats)

    def map(self, raw: RawRecord) -> MappedRecord | Rejection:
        obj = raw.payload
        assert isinstance(obj, dict)
        eve_type = obj.get("event_type")
        if is_missing(eve_type):
            return Rejection(E.MISSING_REQUIRED_FIELD, "event_type is required", "event_type")
        event_type = EVE_TYPE_MAP.get(str(eve_type), "other")
        fields: dict[str, Any] = {
            "event_type": event_type,
            "event_time": obj.get("timestamp"),
            "source_event_id": obj.get("flow_id"),
            "src_ip": obj.get("src_ip"),
            "src_port": obj.get("src_port"),
            "dst_ip": obj.get("dest_ip"),
            "dst_port": obj.get("dest_port"),
            "protocol": obj.get("proto"),
            "app_protocol": obj.get("app_proto"),
        }
        if event_type == "ids_alert":
            fields.update(
                signature_id=_get(obj, "alert.signature_id"),
                signature=_get(obj, "alert.signature"),
                alert_category=_get(obj, "alert.category"),
                source_severity=_get(obj, "alert.severity"),
            )
        elif event_type == "network_flow":
            fields.update(
                packets_out=_get(obj, "flow.pkts_toserver"),
                packets_in=_get(obj, "flow.pkts_toclient"),
                bytes_out=_get(obj, "flow.bytes_toserver"),
                bytes_in=_get(obj, "flow.bytes_toclient"),
                event_end_time=_get(obj, "flow.end"),
            )
            if not is_missing(_get(obj, "flow.start")):
                fields["event_time"] = _get(obj, "flow.start")
        elif event_type == "dns":
            fields["dns_query"] = _first(obj, DNS_QUERY_PATHS)
        elif event_type == "http":
            fields["http_host"] = _first(obj, HTTP_HOST_PATHS)
            fields["url"] = _first(obj, HTTP_URL_PATHS)
        common = {
            "timestamp",
            "flow_id",
            "event_type",
            "src_ip",
            "src_port",
            "dest_ip",
            "dest_port",
            "proto",
            "app_proto",
        }
        extras = {k: v for k, v in obj.items() if k not in common}
        extras["eve_event_type"] = eve_type
        return MappedRecord(fields=fields, attributes=to_attributes(extras))

    def fingerprint_values(self, values: dict[str, Any], mapped: MappedRecord) -> list[Any]:
        # flow_id groups several events of one flow; it is not unique per event.
        return [
            values.get("source_event_id"),
            mapped.attributes.get("eve_event_type"),
            values.get("event_time"),
            values.get("signature_id"),
            values.get("src_ip"),
            values.get("dst_ip"),
        ]


# --- auth / endpoint JSONL -----------------------------------------------------------------------

AUTH_KEYS = ("user_name", "auth_result", "auth_method", "src_ip", "host_name", "service")


@register
class AuthJsonlAdapter(Adapter):
    name = "auth_jsonl"
    version = "1.0"
    description = "Authentication events (timestamp, user_name, auth_result, ...) as JSON lines."
    extensions = frozenset({".jsonl", ".ndjson", ".json"})
    event_types = ("auth",)
    label_mapping = "canonical"
    expected_fields: ClassVar[dict[str, float]] = {"src_ip": 0.5}

    def read(self, stream: IO[bytes]) -> Iterator[RawRecord]:
        yield from read_jsonl(stream, self.encodings, self.stats)

    def map(self, raw: RawRecord) -> MappedRecord | Rejection:
        obj = dict(raw.payload)
        if is_missing(obj.get("timestamp")):
            return Rejection(E.MISSING_REQUIRED_FIELD, "timestamp is required", "timestamp")
        payload = {"event_type": "auth", "event_time": obj.pop("timestamp")}
        for key in AUTH_KEYS:
            if key in obj:
                payload[key] = obj.pop(key)
        for key in ("label_raw", "is_attack"):
            if key in obj:
                payload[key] = obj.pop(key)
        payload.update(obj)  # remaining keys become attributes via map_canonical
        return map_canonical(payload)


ENDPOINT_ACTIONS = {
    "process_start": "endpoint_process",
    "file_create": "endpoint_file",
    "file_modify": "endpoint_file",
    "network_connect": "endpoint_network",
}
ENDPOINT_KEYS = (
    "host_name",
    "user_name",
    "process_name",
    "process_command_line",
    "parent_process_name",
    "file_path",
    "file_sha256",
    "dst_ip",
    "dst_port",
)


@register
class EndpointJsonlAdapter(Adapter):
    name = "endpoint_jsonl"
    version = "1.0"
    description = "Endpoint events (process/file/network) as JSON lines with event_action."
    extensions = frozenset({".jsonl", ".ndjson", ".json"})
    event_types = ("endpoint_process", "endpoint_file", "endpoint_network")
    label_mapping = "canonical"

    def read(self, stream: IO[bytes]) -> Iterator[RawRecord]:
        yield from read_jsonl(stream, self.encodings, self.stats)

    def map(self, raw: RawRecord) -> MappedRecord | Rejection:
        obj = dict(raw.payload)
        action = obj.pop("event_action", None)
        if is_missing(action):
            return Rejection(E.MISSING_REQUIRED_FIELD, "event_action is required", "event_action")
        event_type = ENDPOINT_ACTIONS.get(str(action).strip().lower())
        if event_type is None:
            return Rejection(
                E.UNKNOWN_EVENT_TYPE,
                f"unsupported event_action {str(action)[:50]!r}",
                "event_action",
            )
        if is_missing(obj.get("timestamp")):
            return Rejection(E.MISSING_REQUIRED_FIELD, "timestamp is required", "timestamp")
        payload: dict[str, Any] = {"event_type": event_type, "event_time": obj.pop("timestamp")}
        for key in (*ENDPOINT_KEYS, "label_raw", "is_attack"):
            if key in obj:
                payload[key] = obj.pop(key)
        payload.update(obj)
        payload["event_action"] = action  # kept as an attribute
        return map_canonical(payload)
