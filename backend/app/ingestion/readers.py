"""Bounded, streaming readers for untrusted files (DATA_INGESTION.md §3, SECURITY §4).

Nothing here interprets content beyond structure: no eval, no type guessing, no network.
Every record keeps the SHA-256 of its original bytes.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import re
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from typing import IO, Any

from app.ingestion import errors as E
from app.ingestion.errors import BatchFatalError, Rejection
from app.ingestion.records import RawRecord

MAX_RECORD_BYTES = 1024 * 1024
RAW_TEXT_MAX = 64 * 1024
MAX_JSON_DEPTH = 32
MAX_FIELDS = 512
MAX_JSON_ARRAY_FILE_BYTES = 256 * 1024 * 1024
BINARY_SNIFF_BYTES = 8192
UTF8_BOM = b"\xef\xbb\xbf"

csv.field_size_limit(MAX_RECORD_BYTES)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def looks_binary(head: bytes) -> bool:
    return b"\x00" in head[:BINARY_SNIFF_BYTES]


@dataclass
class Line:
    number: int  # 1-based physical line number
    data: bytes | None  # None when the line exceeded the size limit
    raw: bytes  # bytes kept for hashing (bounded)


def iter_lines(stream: IO[bytes], max_bytes: int = MAX_RECORD_BYTES) -> Iterator[Line]:
    """Yield physical lines without their terminator, never holding more than ``max_bytes``."""
    number = 0
    first = True
    while True:
        chunk = stream.readline(max_bytes + 1)
        if not chunk:
            return
        number += 1
        if first:
            first = False
            if chunk.startswith(UTF8_BOM):
                chunk = chunk[len(UTF8_BOM) :]
        if len(chunk) > max_bytes and not chunk.endswith(b"\n"):
            # Too long: hash what we keep, then discard the remainder of the line.
            kept = chunk[:max_bytes]
            while True:
                rest = stream.readline(max_bytes + 1)
                if not rest or rest.endswith(b"\n"):
                    break
            yield Line(number, None, kept)
            continue
        data = chunk.rstrip(b"\n").rstrip(b"\r")
        yield Line(number, data, data)


def decode(data: bytes, encodings: Sequence[str]) -> tuple[str, str] | None:
    for encoding in encodings:
        try:
            return data.decode(encoding), encoding
        except UnicodeDecodeError:
            continue
    return None


def truncate_text(text: str) -> tuple[str, bool]:
    if len(text) <= RAW_TEXT_MAX:
        return text, False
    return text[:RAW_TEXT_MAX], True


def json_depth(value: Any, limit: int = MAX_JSON_DEPTH) -> int:
    """Depth of nested containers, stopping early once ``limit`` is exceeded."""
    stack: list[tuple[Any, int]] = [(value, 1)]
    deepest = 0
    while stack:
        item, depth = stack.pop()
        if isinstance(item, dict | list):
            deepest = max(deepest, depth)
            if deepest > limit:
                return deepest
            children = item.values() if isinstance(item, dict) else item
            stack.extend((child, depth + 1) for child in children)
    return deepest


# --- header handling -------------------------------------------------------------------------

_WS = re.compile(r"\s+")


def normalize_header(name: str) -> str:
    return _WS.sub(" ", name.strip()).casefold()


def normalize_headers(names: Sequence[str]) -> tuple[list[str], list[dict[str, str]]]:
    """Normalise names; duplicates get ``__2``, ``__3`` suffixes. Returns (names, mapping)."""
    seen: dict[str, int] = {}
    result: list[str] = []
    mapping: list[dict[str, str]] = []
    for original in names:
        base = normalize_header(original)
        count = seen.get(base, 0) + 1
        seen[base] = count
        name = base if count == 1 else f"{base}__{count}"
        result.append(name)
        mapping.append({"original": original, "normalized": name})
    return result, mapping


# --- JSON lines --------------------------------------------------------------------------------


@dataclass
class ReadStats:
    encodings: dict[str, int] = field(default_factory=dict)

    def used(self, encoding: str) -> None:
        self.encodings[encoding] = self.encodings.get(encoding, 0) + 1


def _parse_json_object(text: str) -> tuple[Any, Rejection | None]:
    try:
        value = json.loads(text)
    except RecursionError:
        return None, Rejection(E.NESTING_TOO_DEEP, f"nesting deeper than {MAX_JSON_DEPTH}")
    except json.JSONDecodeError as exc:
        return None, Rejection(E.MALFORMED_JSON, f"invalid JSON: {exc.msg}")
    except ValueError as exc:
        return None, Rejection(E.MALFORMED_JSON, f"invalid JSON: {exc}")
    if not isinstance(value, dict):
        return None, Rejection(
            E.MALFORMED_JSON, f"expected a JSON object, got {type(value).__name__}"
        )
    if json_depth(value) > MAX_JSON_DEPTH:
        return None, Rejection(E.NESTING_TOO_DEEP, f"nesting deeper than {MAX_JSON_DEPTH}")
    return value, None


def read_jsonl(
    stream: IO[bytes], encodings: Sequence[str], stats: ReadStats
) -> Iterator[RawRecord]:
    record_number = 0
    for line in iter_lines(stream):
        if line.data is not None and not line.data.strip():
            continue
        record_number += 1
        digest = sha256_hex(line.raw)
        if line.data is None:
            text, truncated = truncate_text(line.raw.decode("utf-8", "replace"))
            yield RawRecord(
                record_number,
                digest,
                raw_text=text,
                truncated=True,
                problem=Rejection(E.RECORD_TOO_LARGE, f"record exceeds {MAX_RECORD_BYTES} bytes"),
            )
            continue
        decoded = decode(line.data, encodings)
        if decoded is None:
            text, truncated = truncate_text(line.data.decode("utf-8", "replace"))
            yield RawRecord(
                record_number,
                digest,
                raw_text=text,
                truncated=truncated,
                problem=Rejection(E.ENCODING_ERROR, f"not decodable as {', '.join(encodings)}"),
            )
            continue
        text, encoding = decoded
        stats.used(encoding)
        value, problem = _parse_json_object(text)
        if problem is not None:
            raw_text, truncated = truncate_text(text)
            yield RawRecord(
                record_number, digest, raw_text=raw_text, truncated=truncated, problem=problem
            )
        else:
            yield RawRecord(record_number, digest, payload=value)


def read_json_array(
    stream: IO[bytes], encodings: Sequence[str], stats: ReadStats
) -> Iterator[RawRecord]:
    data = stream.read(MAX_JSON_ARRAY_FILE_BYTES + 1)
    if len(data) > MAX_JSON_ARRAY_FILE_BYTES:
        raise BatchFatalError(
            E.FILE_TOO_LARGE,
            f"JSON array files are limited to {MAX_JSON_ARRAY_FILE_BYTES} bytes; use JSON lines",
        )
    if data.startswith(UTF8_BOM):
        data = data[len(UTF8_BOM) :]
    decoded = decode(data, encodings)
    if decoded is None:
        raise BatchFatalError(E.ENCODING_ERROR, f"file is not decodable as {', '.join(encodings)}")
    text, encoding = decoded
    stats.used(encoding)
    try:
        value = json.loads(text)
    except RecursionError as exc:
        raise BatchFatalError(E.NESTING_TOO_DEEP, "JSON nesting too deep") from exc
    except ValueError as exc:
        raise BatchFatalError(E.MALFORMED_JSON, f"invalid JSON document: {exc}") from exc
    if not isinstance(value, list):
        raise BatchFatalError(E.MALFORMED_JSON, "expected a top-level JSON array of objects")
    for index, element in enumerate(value, start=1):
        canonical = json.dumps(element, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        digest = sha256_hex(canonical.encode("utf-8"))
        if not isinstance(element, dict):
            yield RawRecord(
                index,
                digest,
                raw_text=truncate_text(canonical)[0],
                problem=Rejection(E.MALFORMED_JSON, "array element is not an object"),
            )
        elif json_depth(element) > MAX_JSON_DEPTH:
            yield RawRecord(
                index,
                digest,
                raw_text=truncate_text(canonical)[0],
                problem=Rejection(E.NESTING_TOO_DEEP, f"nesting deeper than {MAX_JSON_DEPTH}"),
            )
        elif len(canonical.encode("utf-8")) > MAX_RECORD_BYTES:
            yield RawRecord(
                index,
                digest,
                raw_text=truncate_text(canonical)[0],
                truncated=True,
                problem=Rejection(E.RECORD_TOO_LARGE, f"record exceeds {MAX_RECORD_BYTES} bytes"),
            )
        else:
            yield RawRecord(index, digest, payload=element)


# --- delimited text (CSV / TSV) ----------------------------------------------------------------


class DelimitedReader:
    """Streams delimited records, keeping the original bytes of each (possibly multi-line)
    record for hashing. The first record is the header unless ``header`` is given."""

    def __init__(
        self,
        stream: IO[bytes],
        encodings: Sequence[str],
        stats: ReadStats,
        *,
        delimiter: str = ",",
        header: Sequence[str] | None = None,
    ) -> None:
        self._lines = iter_lines(stream)
        self._encodings = encodings
        self._stats = stats
        self._buffer: list[bytes] = []
        self._buffer_size = 0
        self._problem: Rejection | None = None
        self._reader = csv.reader(self._text_lines(), delimiter=delimiter, strict=False)
        self.header_map: list[dict[str, str]] = []
        self.columns: list[str] = []
        if header is not None:
            self.columns, self.header_map = normalize_headers(header)
        self._has_header = header is None

    def _text_lines(self) -> Iterator[str]:
        for line in self._lines:
            raw = line.raw
            self._buffer.append(raw)
            self._buffer_size += len(raw) + 1
            if line.data is None or self._buffer_size > MAX_RECORD_BYTES:
                self._problem = self._problem or Rejection(
                    E.RECORD_TOO_LARGE, f"record exceeds {MAX_RECORD_BYTES} bytes"
                )
                yield "\n"
                continue
            decoded = decode(line.data, self._encodings)
            if decoded is None:
                self._problem = self._problem or Rejection(
                    E.ENCODING_ERROR, f"not decodable as {', '.join(self._encodings)}"
                )
                yield line.data.decode("utf-8", "replace") + "\n"
            else:
                text, encoding = decoded
                self._stats.used(encoding)
                yield text + "\n"

    def _take(self) -> tuple[bytes, Rejection | None]:
        raw = b"\n".join(self._buffer)
        problem = self._problem
        self._buffer, self._buffer_size, self._problem = [], 0, None
        return raw, problem

    def _next_row(self) -> tuple[list[str] | None, bytes, Rejection | None] | None:
        try:
            row = next(self._reader)
        except StopIteration:
            return None
        except csv.Error as exc:
            raw, problem = self._take()
            return None, raw, problem or Rejection(E.MALFORMED_CSV_ROW, f"CSV error: {exc}")
        raw, problem = self._take()
        return row, raw, problem

    def read_header(self) -> list[str]:
        """Consume the header record (first non-blank record)."""
        if not self._has_header:
            return self.columns
        while True:
            item = self._next_row()
            if item is None:
                raise BatchFatalError(E.UNSUPPORTED_VARIANT, "file has no header row")
            row, _raw, problem = item
            if row is None or problem is not None:
                raise BatchFatalError(
                    E.UNSUPPORTED_VARIANT,
                    f"header row is unreadable ({problem.code if problem else 'CSV error'})",
                )
            if not row or all(not cell.strip() for cell in row):
                continue
            self.columns, self.header_map = normalize_headers(row)
            self._has_header = False
            return self.columns

    def records(self) -> Iterator[RawRecord]:
        if self._has_header:
            self.read_header()
        number = 0
        while True:
            item = self._next_row()
            if item is None:
                return
            row, raw, problem = item
            if row is not None and problem is None and not any(cell.strip() for cell in row):
                continue  # blank line
            number += 1
            digest = sha256_hex(raw)
            if problem is not None or row is None:
                text, truncated = truncate_text(raw.decode("utf-8", "replace"))
                yield RawRecord(
                    number,
                    digest,
                    raw_text=text,
                    truncated=truncated
                    or (problem is not None and problem.code == E.RECORD_TOO_LARGE),
                    problem=problem or Rejection(E.MALFORMED_CSV_ROW, "unparseable row"),
                )
            elif len(row) > MAX_FIELDS:
                text, truncated = truncate_text(raw.decode("utf-8", "replace"))
                yield RawRecord(
                    number,
                    digest,
                    raw_text=text,
                    truncated=truncated,
                    problem=Rejection(E.WRONG_FIELD_COUNT, f"more than {MAX_FIELDS} fields"),
                )
            elif len(row) != len(self.columns):
                yield RawRecord(
                    number,
                    digest,
                    payload=row,
                    problem=Rejection(
                        E.WRONG_FIELD_COUNT, f"expected {len(self.columns)} fields, got {len(row)}"
                    ),
                )
            else:
                yield RawRecord(number, digest, payload=dict(zip(self.columns, row, strict=True)))


def bytes_stream(data: bytes) -> IO[bytes]:
    return io.BytesIO(data)
