from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from app.ingestion import errors as E
from app.ingestion.errors import BatchFatalError, Rejection
from app.ingestion.fingerprint import fingerprint
from app.ingestion.labels import LabelMapping, normalize_label
from app.ingestion.normalize import Normalized, normalize_event
from app.ingestion.records import BatchContext

pytestmark = pytest.mark.unit

UTC_CTX = BatchContext(source_key="t", timezone="UTC")
NOW = datetime(2026, 10, 14, 12, 0, tzinfo=UTC)


def _norm(fields: dict[str, Any], ctx: BatchContext = UTC_CTX) -> Normalized | Rejection:
    return normalize_event(fields, ctx, now=lambda: NOW)


def _flow(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "event_type": "network_flow",
        "event_time": "2017-07-05T13:42:10Z",
        "src_ip": "192.0.2.10",
        "dst_ip": "198.51.100.7",
        "dst_port": "22",
        "protocol": "6",
        "bytes_out": "2048",
        "duration_s": "1.5",
    }
    base.update(overrides)
    return base


def test_valid_flow_is_normalised() -> None:
    result = _norm(_flow())
    assert isinstance(result, Normalized)
    v = result.values
    assert v["event_time"] == datetime(2017, 7, 5, 13, 42, 10, tzinfo=UTC)
    assert (v["protocol"], v["ip_proto"], v["dst_port"], v["bytes_out"]) == ("tcp", 6, 22, 2048)
    assert v["time_quality"] == "second"
    assert (v["date_key"], v["event_hour"]) == (20170705, 13)
    assert result.warnings == []


@pytest.mark.parametrize(
    ("overrides", "code", "field"),
    [
        ({"event_type": None}, E.MISSING_REQUIRED_FIELD, "event_type"),
        ({"event_type": "teleport"}, E.UNKNOWN_EVENT_TYPE, "event_type"),
        ({"event_time": None}, E.MISSING_REQUIRED_FIELD, "event_time"),
        ({"event_time": "yesterday"}, E.INVALID_TIMESTAMP, "event_time"),
        ({"event_time": "1995-01-01T00:00:00Z"}, E.TIMESTAMP_OUT_OF_RANGE, "event_time"),
        ({"event_time": "2026-10-16T00:00:00Z"}, E.TIMESTAMP_OUT_OF_RANGE, "event_time"),
        ({"src_ip": "999.1.1.1"}, E.INVALID_IP, "src_ip"),
        ({"dst_ip": ""}, E.MISSING_REQUIRED_FIELD, "dst_ip"),
    ],
)
def test_required_field_failures_reject(overrides: dict[str, Any], code: str, field: str) -> None:
    result = _norm(_flow(**overrides))
    assert isinstance(result, Rejection)
    assert (result.code, result.field) == (code, field)


@pytest.mark.parametrize(
    ("overrides", "field", "code"),
    [
        ({"dst_port": "70000"}, "dst_port", E.INVALID_PORT),
        ({"bytes_out": "-5"}, "bytes_out", E.NEGATIVE_COUNTER),
        ({"duration_s": "Infinity"}, "duration_s", E.INVALID_NUMBER),
        ({"direction": "sideways"}, "direction", E.INVALID_VALUE),
    ],
)
def test_optional_field_failures_warn_and_null(
    overrides: dict[str, Any], field: str, code: str
) -> None:
    result = _norm(_flow(**overrides))
    assert isinstance(result, Normalized)
    assert result.values[field] is None
    assert (field, code) in result.warnings


def test_missing_values_are_null_not_errors() -> None:
    result = _norm(_flow(bytes_out="-", duration_s="NaN", dst_port="(empty)"))
    assert isinstance(result, Normalized)
    assert result.values["bytes_out"] is None and result.warnings == []


def test_hex_port_and_ipv4_mapped_ipv6() -> None:
    result = _norm(_flow(dst_port="0x0016", src_ip="::ffff:192.0.2.10"))
    assert isinstance(result, Normalized)
    assert result.values["dst_port"] == 22 and result.values["src_ip"] == "192.0.2.10"


def test_naive_timestamp_uses_source_timezone() -> None:
    ctx = BatchContext(source_key="t", timezone="America/Halifax")
    result = _norm(_flow(event_time="2017-07-05 09:42:10"), ctx)
    assert isinstance(result, Normalized)
    assert result.values["event_time"] == datetime(2017, 7, 5, 12, 42, 10, tzinfo=UTC)
    assert result.naive_timestamp


def test_naive_timestamp_without_timezone_is_fatal() -> None:
    with pytest.raises(BatchFatalError) as info:
        _norm(_flow(event_time="2017-07-05 09:42:10"), BatchContext(source_key="t", timezone=None))
    assert info.value.code == E.TIMEZONE_NOT_CONFIGURED


def test_epoch_and_fractional_seconds() -> None:
    result = _norm(_flow(event_time="1421927414.5"))
    assert isinstance(result, Normalized)
    assert result.values["time_quality"] == "exact"
    assert result.values["event_time"] == datetime(2015, 1, 22, 11, 50, 14, 500000, tzinfo=UTC)


def test_auth_requirements_and_user_normalisation() -> None:
    base = {"event_type": "auth", "event_time": "2026-03-01T10:15:02Z"}
    missing = _norm({**base, "user_name": "Alice"})
    assert isinstance(missing, Rejection) and missing.field == "auth_result"
    ok = _norm({**base, "user_name": " Alice\x00\x07 ", "auth_result": "FAILURE"})
    assert isinstance(ok, Normalized)
    assert ok.values["user_name"] == "Alice"
    assert ok.values["user_name_normalized"] == "alice"
    assert ok.values["auth_result"] == "failure"


def test_long_text_is_truncated_with_warning() -> None:
    result = _norm(
        {
            "event_type": "endpoint_process",
            "event_time": "2026-03-01T10:15:02Z",
            "host_name": "ws-1",
            "process_command_line": "x" * 40000,
        }
    )
    assert isinstance(result, Normalized)
    assert len(result.values["process_command_line"]) == 32 * 1024
    assert ("process_command_line", "TRUNCATED") in result.warnings


def test_assumed_time_allows_flows_without_ips() -> None:
    result = _norm(
        {
            "event_type": "network_flow",
            "event_time": "2017-07-03T00:00:00Z",
            "time_quality": "assumed",
            "dst_port": "80",
        }
    )
    assert isinstance(result, Normalized)
    assert result.values["time_quality"] == "assumed" and result.values["src_ip"] is None


def test_non_canonical_field_from_adapter_is_a_programming_error() -> None:
    with pytest.raises(ValueError, match="non-canonical"):
        _norm(_flow(Label="BENIGN"))


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Web Attack – XSS", "web attack xss"),  # noqa: RUF001 (en dash under test)
        ("Web Attack � Brute Force", "web attack brute force"),
        ("  DoS Hulk ", "dos hulk"),
        ("BRUTE_FORCE", "brute force"),
    ],
)
def test_label_normalisation(raw: str, expected: str) -> None:
    assert normalize_label(raw) == expected


def test_label_mapping_statuses() -> None:
    mapping = LabelMapping("x", 1, {"benign": "BENIGN", "dos": "DOS", "": "BENIGN"})
    assert mapping.map("DoS", None) == ("DOS", "mapped")
    assert mapping.map("dos", False) == (None, "ambiguous")
    assert mapping.map("", True) == (None, "ambiguous")
    assert mapping.map("", False) == ("BENIGN", "mapped")
    assert mapping.map("weird", None) == (None, "unmapped")
    assert mapping.version_tag == "x@1"


def test_fingerprint_is_stable_and_version_major_scoped() -> None:
    t = datetime(2017, 7, 5, tzinfo=UTC)
    a = fingerprint("zeek_conn", "1.0", ["uid", t, 22.0])
    assert a == fingerprint("zeek_conn", "1.3", ["uid", t, 22])
    assert a != fingerprint("zeek_conn", "2.0", ["uid", t, 22])
    assert a != fingerprint("other", "1.0", ["uid", t, 22])
