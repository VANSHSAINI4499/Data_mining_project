from __future__ import annotations

import hashlib
import io

import pytest

from app.ingestion import errors as E
from app.ingestion.errors import BatchFatalError
from app.ingestion.readers import (
    MAX_JSON_DEPTH,
    MAX_RECORD_BYTES,
    DelimitedReader,
    ReadStats,
    iter_lines,
    json_depth,
    normalize_headers,
    read_json_array,
    read_jsonl,
)

pytestmark = pytest.mark.unit


def _csv(data: bytes, encodings: tuple[str, ...] = ("utf-8",)) -> DelimitedReader:
    return DelimitedReader(io.BytesIO(data), encodings, ReadStats())


def test_iter_lines_strips_terminators_and_bom() -> None:
    lines = list(iter_lines(io.BytesIO(b"\xef\xbb\xbfa,b\r\nc,d\nlast")))
    assert [line.data for line in lines] == [b"a,b", b"c,d", b"last"]


def test_iter_lines_flags_oversized_line_and_continues() -> None:
    data = b"x" * (MAX_RECORD_BYTES + 10) + b"\nnext\n"
    lines = list(iter_lines(io.BytesIO(data)))
    assert lines[0].data is None
    assert lines[1].data == b"next"


def test_header_normalisation_and_duplicates() -> None:
    names, mapping = normalize_headers(
        [" Destination Port", "Fwd Header  Length", "fwd header length"]
    )
    assert names == ["destination port", "fwd header length", "fwd header length__2"]
    assert mapping[0] == {"original": " Destination Port", "normalized": "destination port"}


def test_csv_records_hash_original_bytes_and_keep_line_numbers() -> None:
    reader = _csv(b"a,b\n1,2\n\n3,4\n")
    reader.read_header()
    records = list(reader.records())
    assert [r.record_number for r in records] == [1, 2]
    assert records[0].payload == {"a": "1", "b": "2"}
    assert records[0].sha256 == hashlib.sha256(b"1,2").hexdigest()


def test_csv_multiline_quoted_record() -> None:
    reader = _csv(b'a,b\n"line1\nline2",x\n')
    reader.read_header()
    (record,) = list(reader.records())
    assert record.payload == {"a": "line1\nline2", "b": "x"}
    assert record.sha256 == hashlib.sha256(b'"line1\nline2",x').hexdigest()


def test_csv_wrong_field_count_is_rejected_but_preserved() -> None:
    reader = _csv(b"a,b\n1,2,3\n")
    reader.read_header()
    (record,) = list(reader.records())
    assert record.problem is not None and record.problem.code == E.WRONG_FIELD_COUNT
    assert record.payload == ["1", "2", "3"]


def test_csv_encoding_fallback_and_error() -> None:
    reader = _csv(b"a\ncaf\xe9\n", ("utf-8", "cp1252"))
    reader.read_header()
    (record,) = list(reader.records())
    assert record.payload == {"a": "café"}
    strict = _csv(b"a\ncaf\xe9\n")
    strict.read_header()
    (bad,) = list(strict.records())
    assert bad.problem is not None and bad.problem.code == E.ENCODING_ERROR


def test_csv_without_header_is_fatal() -> None:
    with pytest.raises(BatchFatalError) as info:
        _csv(b"\n\n").read_header()
    assert info.value.code == E.UNSUPPORTED_VARIANT


def test_jsonl_valid_malformed_non_object_and_deep() -> None:
    deep = "[" * (MAX_JSON_DEPTH + 2) + "]" * (MAX_JSON_DEPTH + 2)
    lines = ['{"a": 1}', "{broken", "[1, 2]", '{"x": ' + deep + "}", ""]
    records = list(read_jsonl(io.BytesIO("\n".join(lines).encode()), ("utf-8",), ReadStats()))
    assert records[0].payload == {"a": 1}
    codes = [r.problem.code if r.problem else None for r in records]
    assert codes == [None, E.MALFORMED_JSON, E.MALFORMED_JSON, E.NESTING_TOO_DEEP]
    assert records[1].raw_text == "{broken"


def test_json_array_requires_list_of_objects() -> None:
    records = list(read_json_array(io.BytesIO(b'[{"a": 1}, 5]'), ("utf-8",), ReadStats()))
    assert records[0].payload == {"a": 1}
    assert records[1].problem is not None and records[1].problem.code == E.MALFORMED_JSON
    with pytest.raises(BatchFatalError):
        list(read_json_array(io.BytesIO(b'{"a": 1}'), ("utf-8",), ReadStats()))


def test_json_depth() -> None:
    assert json_depth({"a": [1, {"b": 2}]}) == 3
    assert json_depth(5) == 0
