"""Web server access logs: Nginx/Apache "combined" and "common" formats (DATA_INGESTION.md §4).

One log line becomes one ``http`` event. The request URL is stored as observed and is never
fetched. Decoded query-string parameters are kept in ``attributes.query_params`` (bounded) so
they can be inspected or classified later; method, status, protocol, referer, and user agent
are attributes because the canonical event model has no columns for them.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import IO, Any, ClassVar
from urllib.parse import parse_qsl, urlsplit

from app.ingestion import errors as E
from app.ingestion.adapters.base import Adapter, register
from app.ingestion.errors import Rejection
from app.ingestion.readers import decode, iter_lines, sha256_hex, truncate_text
from app.ingestion.records import MappedRecord, RawRecord

_QUOTED = r'"((?:[^"\\]|\\.)*)"'
LINE = re.compile(
    r"^(?P<remote_addr>\S+) (?P<ident>\S+) (?P<remote_user>\S+) "
    r"\[(?P<time_local>[^\]]+)\] "
    rf"{_QUOTED.replace('(', '(?P<request>', 1)} "
    r"(?P<status>\d{3}|-) (?P<body_bytes>\d+|-)"
    rf"(?: {_QUOTED.replace('(', '(?P<referer>', 1)} {_QUOTED.replace('(', '(?P<user_agent>', 1)})?"
    r"(?P<rest>.*)$"
)
TIME = re.compile(
    r"^(?P<day>\d{1,2})/(?P<mon>[A-Za-z]{3})/(?P<year>\d{4}):"
    r"(?P<h>\d{2}):(?P<m>\d{2}):(?P<s>\d{2}) (?P<tz>[+-]\d{4})$"
)
MONTHS = {
    m: i
    for i, m in enumerate(
        ("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"), 1
    )
}
REQUEST = re.compile(r"^(?P<method>[A-Z]{3,10}) (?P<target>\S+)(?: (?P<protocol>HTTP/[\d.]+))?$")
MAX_PARAMS = 50
MAX_PARAM_CHARS = 2048
MAX_URL_CHARS = 8192


def _dash(value: str | None) -> str | None:
    return None if value in (None, "", "-") else value


def _unescape(value: str | None) -> str | None:
    # Nginx escapes '"' and '\' inside quoted fields as \x22 / \x5C; Apache uses \" and \\.
    if value is None:
        return None
    return value.replace('\\"', '"').replace("\\\\", "\\")


def iso_time(text: str) -> str | None:
    """'15/Oct/2026:10:12:01 +0530' -> '2026-10-15T10:12:01+05:30' (locale-independent)."""
    match = TIME.match(text.strip())
    if match is None or match["mon"].lower() not in MONTHS:
        return None
    tz = match["tz"]
    return (
        f"{match['year']}-{MONTHS[match['mon'].lower()]:02d}-{int(match['day']):02d}"
        f"T{match['h']}:{match['m']}:{match['s']}{tz[:3]}:{tz[3:]}"
    )


def query_params(target: str) -> list[list[str]]:
    """Decoded (name, value) pairs from the query string, bounded in count and length."""
    query = urlsplit(target).query if "?" in target else ""
    pairs = parse_qsl(query, keep_blank_values=True, max_num_fields=None)
    return [[k[:MAX_PARAM_CHARS], v[:MAX_PARAM_CHARS]] for k, v in pairs[:MAX_PARAMS]]


@register
class NginxAccessAdapter(Adapter):
    name = "nginx_access"
    version = "1.0"
    description = (
        "Nginx/Apache access log in 'combined' or 'common' format (one request per line); "
        "query parameters are decoded into attributes. URLs are never fetched."
    )
    extensions = frozenset({".log", ".txt", ".access"})
    event_types = ("http",)
    variants = ("combined", "common")
    expected_fields: ClassVar[dict[str, float]] = {"src_ip": 0.0, "url": 0.05}

    def __init__(self, ctx: Any) -> None:
        super().__init__(ctx)
        self._seen: dict[str, int] = {}

    def read(self, stream: IO[bytes]) -> Iterator[RawRecord]:
        number = 0
        formats: dict[str, int] = {}
        for line in iter_lines(stream):
            if line.data is not None and not line.data.strip():
                continue
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
            self.stats.used(encoding)
            match = LINE.match(text.rstrip("\r\n"))
            if match is None:
                yield RawRecord(
                    number,
                    digest,
                    raw_text=truncate_text(text)[0],
                    problem=Rejection(
                        E.INVALID_VALUE, "not an access-log line in combined/common format"
                    ),
                )
                continue
            fmt = "combined" if match["user_agent"] is not None else "common"
            if self.ctx.variant and self.ctx.variant != fmt:
                yield RawRecord(
                    number,
                    digest,
                    raw_text=truncate_text(text)[0],
                    problem=Rejection(
                        E.INVALID_VALUE,
                        f"line is in {fmt} format, batch expects {self.ctx.variant}",
                    ),
                )
                continue
            formats[fmt] = formats.get(fmt, 0) + 1
            payload = {k: v for k, v in match.groupdict().items() if v is not None}
            yield RawRecord(number, digest, payload=payload, raw_text=truncate_text(text)[0])
        self.metadata["formats"] = formats

    def map(self, raw: RawRecord) -> MappedRecord | Rejection:
        p = raw.payload
        assert isinstance(p, dict)
        when = iso_time(p["time_local"])
        if when is None:
            return Rejection(
                E.INVALID_TIMESTAMP, "time_local is not dd/Mon/yyyy:HH:MM:SS +zzzz", "time_local"
            )
        request = _unescape(p.get("request")) or ""
        req = REQUEST.match(request)
        attributes: dict[str, Any] = {
            "status": None if p["status"] == "-" else int(p["status"]),
            "request_line": request[:MAX_URL_CHARS],
            "referer": _dash(_unescape(p.get("referer"))),
            "user_agent": _dash(_unescape(p.get("user_agent"))),
            "log_format": "combined" if "user_agent" in p else "common",
        }
        url = None
        if req is not None:
            url = req["target"][:MAX_URL_CHARS]
            attributes.update(
                method=req["method"],
                protocol=req["protocol"],
                query_params=query_params(req["target"]),
            )
        else:
            # e.g. "-" or raw TLS bytes sent to a plain-HTTP port: kept, but no URL is guessed.
            attributes["request_unparsed"] = True
        if p.get("rest", "").strip():
            attributes["extra_fields"] = p["rest"].strip()[:MAX_URL_CHARS]
        occurrence = self._seen.get(raw.sha256, 0)
        self._seen[raw.sha256] = occurrence + 1
        fields: dict[str, Any] = {
            "event_type": "http",
            "event_time": when,
            "src_ip": p["remote_addr"],
            "user_name": _dash(p.get("remote_user")),
            "url": url,
            "app_protocol": "http",
            "bytes_in": None if p["body_bytes"] == "-" else int(p["body_bytes"]),
        }
        return MappedRecord(
            fields=fields, attributes=attributes, fingerprint_extra=(raw.sha256, occurrence)
        )

    def fingerprint_values(self, values: dict[str, Any], mapped: MappedRecord) -> list[Any]:
        # Identical lines are separate requests; the occurrence index keeps them apart while
        # re-importing the same lines still deduplicates.
        return [values.get("event_time"), values.get("src_ip"), *mapped.fingerprint_extra]
