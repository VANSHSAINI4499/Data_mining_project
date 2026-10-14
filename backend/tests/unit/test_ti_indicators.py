"""Indicator normalisation and CSV / STIX 2.1 / ATT&CK parsing (THREAT_INTELLIGENCE.md)."""

from __future__ import annotations

import json

import pytest

from app.ti.indicators import (
    IndicatorError,
    defang,
    normalize,
    parse_attack_bundle,
    parse_csv,
    parse_pattern,
    parse_stix_bundle,
    refang,
)


@pytest.mark.parametrize(
    ("kind", "value", "expected"),
    [
        ("ipv4", " 203.0.113[.]99 ", "203.0.113.99"),
        ("ipv6", "2001:DB8::1", "2001:db8::1"),
        ("ipv4", "::ffff:198.51.100.7", "198.51.100.7"),
        ("domain", "C2.Example[.]Test.", "c2.example.test"),
        ("domain", "bücher.example", "xn--bcher-kva.example"),
        (
            "url",
            "hxxps://Payload.Example[.]test:443/a.bin#frag",
            "https://payload.example.test/a.bin",
        ),
        ("url", "http://host.example:8080/x?q=1", "http://host.example:8080/x?q=1"),
        ("sha256", "A" * 64, "a" * 64),
        ("md5", "D41D8CD98F00B204E9800998ECF8427E", "d41d8cd98f00b204e9800998ecf8427e"),
        ("email", "Alice[at]Example.TEST", "Alice@example.test"),
    ],
)
def test_normalize(kind: str, value: str, expected: str) -> None:
    assert normalize(kind, value) == expected


@pytest.mark.parametrize(
    ("kind", "value"),
    [
        ("ipv4", "010.0.0.1"),
        ("ipv4", "2001:db8::1"),
        ("ipv6", "192.0.2.1"),
        ("domain", "*.example.test"),
        ("domain", "localhost"),
        ("url", "javascript:alert(1)"),
        ("sha256", "abc"),
        ("email", "nobody"),
        ("registry_key", "HKLM"),
        ("ipv4", ""),
    ],
)
def test_normalize_rejects(kind: str, value: str) -> None:
    with pytest.raises(IndicatorError):
        normalize(kind, value)


def test_refang_and_defang_round_trip() -> None:
    assert refang("hxxp://evil[.]example(.)test") == "http://evil.example.test"
    assert defang("url", "http://evil.example.test/x") == "hxxp://evil[.]example[.]test/x"
    assert defang("domain", "c2.example.test") == "c2[.]example[.]test"
    assert defang("ipv4", "203.0.113.9") == "203.0.113.9"


def test_parse_csv_accepts_and_rejects_rows() -> None:
    data = (
        b"indicator_type,value,confidence,valid_until,technique_ids\n"
        b"ipv4,203.0.113.99,80,2026-03-12T00:00:00Z,T1071;t1071.001\n"
        b"domain,bad domain,50,,\n"
        b"ipv4,203.0.113.5,150,,\n"
        b"ipv4,203.0.113.6,40,2026-03-12 00:00:00,\n"
        b"sha256,abc,50,,T9\n"
    )
    report = parse_csv(data)
    assert report.received == 5
    assert [i.value_normalized for i in report.indicators] == ["203.0.113.99"]
    assert report.indicators[0].technique_ids == ["T1071", "T1071.001"]
    assert [r["row"] for r in report.rejected] == [2, 3, 4, 5]
    assert "timezone" in report.rejected[2]["reason"]


def test_parse_csv_requires_columns() -> None:
    with pytest.raises(IndicatorError):
        parse_csv(b"type,val\nipv4,1.2.3.4\n")


def test_parse_pattern_supported_and_unsupported() -> None:
    assert parse_pattern("[ipv4-addr:value = '203.0.113.9']") == [("ipv4", "203.0.113.9")]
    assert parse_pattern(
        "[domain-name:value = 'a.example.test'] OR [url:value = 'http://b.example.test/x']"
    ) == [("domain", "a.example.test"), ("url", "http://b.example.test/x")]
    assert parse_pattern("[file:hashes.'SHA-256' = '" + "a" * 64 + "']") == [("sha256", "a" * 64)]
    for pattern in (
        "[ipv4-addr:value = '1.2.3.4'] AND [domain-name:value = 'x.test']",
        "[ipv4-addr:value ISSUBSET '10.0.0.0/8']",
        "[ipv4-addr:value = '1.2.3.4'] WITHIN 5 SECONDS",
        "[process:name = 'x.exe']",
        "[domain-name:value MATCHES '.*']",
    ):
        assert isinstance(parse_pattern(pattern), str), pattern


def test_parse_pattern_quotes_hide_keywords() -> None:
    assert parse_pattern("[url:value = 'http://x.test/a AND b']") == [
        ("url", "http://x.test/a AND b")
    ]


def _bundle(*objects: dict[str, object]) -> bytes:
    return json.dumps({"type": "bundle", "id": "bundle--1", "objects": list(objects)}).encode()


def test_parse_stix_bundle() -> None:
    data = _bundle(
        {
            "type": "indicator",
            "id": "indicator--a",
            "pattern_type": "stix",
            "pattern": "[ipv4-addr:value = '203.0.113.99']",
            "confidence": 85,
            "created": "2026-01-01T00:00:00Z",
            "modified": "2026-01-02T00:00:00Z",
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_until": "2026-03-01T00:00:00Z",
            "object_marking_refs": ["marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"],
        },
        {"type": "indicator", "id": "indicator--b", "pattern_type": "sigma", "pattern": "x"},
        {"type": "indicator", "id": "indicator--c", "pattern": "[process:pid = 4]"},
        {
            "type": "attack-pattern",
            "id": "attack-pattern--t",
            "external_references": [{"source_name": "mitre-attack", "external_id": "T1071"}],
        },
        {
            "type": "relationship",
            "relationship_type": "indicates",
            "source_ref": "indicator--a",
            "target_ref": "attack-pattern--t",
        },
    )
    report = parse_stix_bundle(data)
    assert report.received == 3
    (item,) = report.indicators
    assert (item.indicator_type, item.value_normalized, item.confidence) == (
        "ipv4",
        "203.0.113.99",
        85,
    )
    assert item.tlp == "TLP:GREEN" and item.technique_ids == ["T1071"]
    assert item.stix_id == "indicator--a"
    assert {u["stix_id"] for u in report.unsupported_patterns} == {"indicator--b", "indicator--c"}


def test_parse_stix_rejects_non_bundles() -> None:
    with pytest.raises(IndicatorError):
        parse_stix_bundle(b"not json")
    with pytest.raises(IndicatorError):
        parse_stix_bundle(b'{"type": "indicator"}')


def test_parse_attack_bundle() -> None:
    data = _bundle(
        {"type": "x-mitre-collection", "x_mitre_version": "17.1"},
        {
            "type": "attack-pattern",
            "id": "attack-pattern--1",
            "name": "Brute Force",
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": "credential-access"}
            ],
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": "T1110",
                    "url": "https://attack.mitre.org/techniques/T1110",
                }
            ],
        },
        {
            "type": "attack-pattern",
            "id": "attack-pattern--2",
            "name": "Password Spraying",
            "x_mitre_is_subtechnique": True,
            "revoked": False,
            "x_mitre_deprecated": True,
            "external_references": [{"source_name": "mitre-attack", "external_id": "T1110.003"}],
        },
        {"type": "attack-pattern", "id": "attack-pattern--3", "external_references": []},
    )
    records, version = parse_attack_bundle(data)
    assert version == "17.1"
    by_id = {r.technique_id: r for r in records}
    assert set(by_id) == {"T1110", "T1110.003"}
    assert by_id["T1110"].tactics == ["credential-access"]
    assert by_id["T1110.003"].is_subtechnique and by_id["T1110.003"].deprecated
    assert by_id["T1110.003"].parent_technique_id == "T1110"
