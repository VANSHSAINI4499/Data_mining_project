"""Rule DSL validation, pure sequence matching, and risk_v1 scoring (ATTACK_CORRELATION.md)."""

from __future__ import annotations

import tomllib
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from pydantic import ValidationError

from app.correlation import risk
from app.correlation.rules import Evidence, RuleDefinition, dedup_key, find_matches
from app.services.correlation import RULES_FILE

T0 = datetime(2026, 1, 9, 2, 0, tzinfo=UTC)


def _rule(**overrides: Any) -> RuleDefinition:
    data: dict[str, Any] = {
        "key": "bruteforce_then_success",
        "name": "Brute force then success",
        "description": "failures then a success",
        "entity_type": "account",
        "window": "15m",
        "base_severity": "high",
        "steps": [
            {
                "id": "failures",
                "evidence": "event",
                "where": {"event_type": "auth", "auth_result": "failure"},
                "min_count": 3,
            },
            {
                "id": "success",
                "evidence": "event",
                "where": {"auth_result": "success"},
                "after": "failures",
            },
        ],
    }
    return RuleDefinition.model_validate(data | overrides)


def _ev(step: str, minutes: float, entity: str = "svc-backup", ref: int = 0) -> Evidence:
    return Evidence(
        step, "event", ref or int(minutes * 100), entity, T0 + timedelta(minutes=minutes)
    )


def test_default_rules_file_is_valid() -> None:
    with RULES_FILE.open("rb") as fh:
        rules = [RuleDefinition.model_validate(r) for r in tomllib.load(fh)["rule"]]
    assert {r.key for r in rules} == {
        "ti_match_active",
        "bruteforce_then_success",
        "recon_then_attack",
        "anomaly_with_malicious_classification",
        "repeated_ids_signature",
        "web_attack_payloads_from_client",
    }


def test_web_payload_evidence_filters_are_allow_listed() -> None:
    base = {
        "key": "web_rule",
        "name": "web rule",
        "description": "web payload evidence",
        "entity_type": "src_ip",
        "window": "1h",
        "base_severity": "medium",
    }
    ok = RuleDefinition.model_validate(
        base
        | {
            "steps": [
                {
                    "id": "p",
                    "evidence": "web_payload_result",
                    "where": {"predicted_class": ["SQLI", "XSS"], "min_score": 0.6},
                    "min_count": 2,
                }
            ]
        }
    )
    assert ok.steps[0].evidence == "web_payload_result"
    for where in ({"min_score": 1.5}, {"predicted_category": "WEB_ATTACK"}, {"param_name": "q"}):
        with pytest.raises(ValueError):
            RuleDefinition.model_validate(
                base | {"steps": [{"id": "p", "evidence": "web_payload_result", "where": where}]}
            )


@pytest.mark.parametrize(
    "bad",
    [
        {"steps": [{"id": "a", "evidence": "event", "where": {"raw_sql": "1=1"}}]},
        {"steps": [{"id": "a", "evidence": "event", "where": {"dst_port": "22; drop"}}]},
        {"steps": [{"id": "a", "evidence": "event", "after": "b"}]},
        {"steps": [{"id": "a", "evidence": "event"}, {"id": "a", "evidence": "event"}]},
        {"steps": [{"id": "a", "evidence": "shell"}]},
        {"window": "7d"},
        {"entity_type": "user_agent"},
        {"key": "Bad Key"},
        {"steps": []},
        {
            "steps": [
                {"id": "a", "evidence": "anomaly_result", "where": {"min_score_percentile": 101}}
            ]
        },
        {"extra": True},
    ],
)
def test_rule_validation_rejects(bad: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        _rule(**bad)


def test_bruteforce_sequence_matches() -> None:
    rule = _rule()
    evidence = [_ev("failures", m) for m in (0, 1, 2, 3)] + [_ev("success", 4)]
    (match,) = find_matches(rule, evidence)
    assert match.entity == "svc-backup"
    assert match.start == T0 and match.end == T0 + timedelta(minutes=4)
    assert len(match.evidence) == 5


def test_success_before_threshold_does_not_match() -> None:
    rule = _rule()
    evidence = [_ev("failures", 0), _ev("failures", 1), _ev("success", 1.5), _ev("failures", 2)]
    assert find_matches(rule, evidence) == []


def test_sequence_outside_window_does_not_match() -> None:
    rule = _rule()
    evidence = [_ev("failures", m) for m in (0, 1, 2)] + [_ev("success", 16)]
    assert find_matches(rule, evidence) == []


def test_entities_are_independent() -> None:
    rule = _rule()
    evidence = [_ev("failures", m, "alice") for m in (0, 1)] + [_ev("failures", 2, "bob")]
    evidence += [_ev("success", 3, "alice"), _ev("success", 3, "bob")]
    assert find_matches(rule, evidence) == []


def test_matches_do_not_overlap() -> None:
    rule = _rule()
    evidence = [_ev("failures", m) for m in range(8)] + [_ev("success", 8)]
    assert len(find_matches(rule, evidence)) == 1


def test_dedup_key_is_stable_and_hides_entity() -> None:
    key = dedup_key("r", "account", "svc-backup")
    assert key == dedup_key("r", "account", "svc-backup")
    assert key != dedup_key("r", "account", "svc-backup2")
    assert "svc-backup" not in key


def test_risk_score_breakdown_is_transparent() -> None:
    score, breakdown = risk.compute(
        classifications=[
            {"predicted_score": 0.9, "severity_weight": 0.8, "evidence_ref": 1},
            {"predicted_score": 0.5, "severity_weight": 1.0, "evidence_ref": 2},
        ],
        anomalies=[{"score_percentile": 99.0, "evidence_ref": 3}],
        indicator_matches=[{"confidence": 80, "reliability": "B", "evidence_ref": 4}],
        evidence_count=100,
        base_severity="high",
        asset_criticality="unknown",
        asset_id=None,
    )
    parts = breakdown["components"]
    assert parts["classification"]["value"] == pytest.approx(30 * 0.72)
    assert parts["anomaly"]["value"] == pytest.approx(19.8)
    assert parts["threat_intel"]["value"] == pytest.approx(30 * 0.8 * 0.8)
    assert parts["repetition"]["value"] == pytest.approx(10 * 2 / 3, abs=0.01)
    assert parts["rule_severity"]["value"] == pytest.approx(7.5)
    expected = round(sum(p["value"] for p in parts.values()))
    assert score == expected and breakdown["score"] == score
    assert breakdown["severity"] == risk.severity_label(score)
    assert breakdown["risk_model_version"] == "risk_v1"
    assert "not a probability" in breakdown["note"]


def test_risk_with_no_model_or_ti_inputs() -> None:
    score, breakdown = risk.compute(
        classifications=[],
        anomalies=[],
        indicator_matches=[],
        evidence_count=1,
        base_severity="low",
        asset_criticality="unknown",
        asset_id=None,
    )
    assert score == 2  # rule severity 10 * 0.25, rounded; repetition log10(1) = 0
    assert breakdown["components"]["classification"]["inputs"] is None


def test_risk_asset_multiplier_and_cap() -> None:
    score, _ = risk.compute(
        classifications=[{"predicted_score": 1.0, "severity_weight": 1.0, "evidence_ref": 1}],
        anomalies=[{"score_percentile": 100.0, "evidence_ref": 2}],
        indicator_matches=[{"confidence": 100, "reliability": "A", "evidence_ref": 3}],
        evidence_count=10_000,
        base_severity="critical",
        asset_criticality="critical",
        asset_id="srv-1",
    )
    assert score == 100
    assert risk.severity_label(74) == "high" and risk.severity_label(75) == "critical"


def _ids_rule() -> RuleDefinition:
    return RuleDefinition.model_validate(
        {
            "key": "repeated_ids_signature",
            "name": "Repeated IDS signature",
            "description": "same signature five times",
            "entity_type": "src_ip",
            "window": "1h",
            "base_severity": "low",
            "steps": [
                {
                    "id": "alerts",
                    "evidence": "event",
                    "where": {"event_type": "ids_alert"},
                    "min_count": 5,
                    "same": "signature_id",
                }
            ],
        }
    )


def _ids(minutes: int, signature: int, ref: int) -> Evidence:
    return Evidence(
        "alerts",
        "event",
        ref,
        "203.0.113.88",
        T0 + timedelta(minutes=minutes),
        {"signature_id": signature},
    )


def test_same_signature_required() -> None:
    rule = _ids_rule()
    mixed = [_ids(m, 1000 + m % 3, m + 1) for m in range(8)]  # at most 3 of any signature
    assert find_matches(rule, mixed) == []
    repeated = [_ids(m, 2001219, m + 1) for m in range(5)] + [_ids(6, 7, 99)]
    (match,) = find_matches(rule, repeated)
    assert {e.data["signature_id"] for e in match.evidence} == {2001219}
    assert len(match.evidence) == 5


def test_same_only_for_event_steps() -> None:
    with pytest.raises(ValidationError):
        _rule(steps=[{"id": "a", "evidence": "anomaly_result", "same": "dst_port"}])
