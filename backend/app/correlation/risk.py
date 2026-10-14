"""Transparent additive risk score ``risk_v1`` (ATTACK_CORRELATION.md §6). Not a probability."""

from __future__ import annotations

import math
import tomllib
from functools import lru_cache
from pathlib import Path
from typing import Any

from app.core.config import REPO_ROOT

WEIGHTS_FILE = REPO_ROOT / "config" / "correlation_rules" / "risk_weights.toml"


@lru_cache
def weights(path: Path = WEIGHTS_FILE) -> dict[str, Any]:
    with path.open("rb") as fh:
        return tomllib.load(fh)


def severity_label(score: int) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


def compute(
    *,
    classifications: list[dict[str, Any]],
    anomalies: list[dict[str, Any]],
    indicator_matches: list[dict[str, Any]],
    evidence_count: int,
    base_severity: str,
    asset_criticality: str,
    asset_id: str | None,
) -> tuple[int, dict[str, Any]]:
    """Each input dict carries the values used plus an ``evidence_ref`` for the breakdown."""
    w = weights()
    caps = w["caps"]
    components: dict[str, Any] = {}

    best = max(
        classifications, key=lambda c: c["severity_weight"] * c["predicted_score"], default=None
    )
    value = (
        caps["classification"] * (best["severity_weight"] * best["predicted_score"])
        if best
        else 0.0
    )
    components["classification"] = {
        "value": round(value, 2),
        "max": caps["classification"],
        "inputs": best,
    }

    best_anomaly = max(anomalies, key=lambda a: a["score_percentile"], default=None)
    value = caps["anomaly"] * best_anomaly["score_percentile"] / 100 if best_anomaly else 0.0
    components["anomaly"] = {
        "value": round(value, 2),
        "max": caps["anomaly"],
        "inputs": best_anomaly,
    }

    rel = w["reliability"]
    best_ti = max(
        indicator_matches,
        key=lambda m: m["confidence"] / 100 * rel.get(m["reliability"], rel["F"]),
        default=None,
    )
    value = (
        (
            caps["threat_intel"]
            * best_ti["confidence"]
            / 100
            * rel.get(best_ti["reliability"], rel["F"])
        )
        if best_ti
        else 0.0
    )
    components["threat_intel"] = {
        "value": round(value, 2),
        "max": caps["threat_intel"],
        "inputs": best_ti,
    }

    repetition = caps["repetition"] * min(1.0, math.log10(max(evidence_count, 1)) / 3)
    components["repetition"] = {
        "value": round(repetition, 2),
        "max": caps["repetition"],
        "inputs": {"evidence_count": evidence_count},
    }

    severity = caps["rule_severity"] * w["rule_severity"][base_severity]
    components["rule_severity"] = {
        "value": round(severity, 2),
        "max": caps["rule_severity"],
        "inputs": {"base_severity": base_severity},
    }

    base = sum(c["value"] for c in components.values())
    multiplier = w["asset_multiplier"].get(asset_criticality, 1.0)
    score = min(100, round(base * multiplier))
    breakdown = {
        "risk_model_version": w["version"],
        "components": components,
        "base": round(base, 2),
        "asset_multiplier": multiplier,
        "asset": {"asset_id": asset_id, "criticality": asset_criticality},
        "score": score,
        "severity": severity_label(score),
        "note": "transparent rule-based score (0-100); not a probability",
    }
    return score, breakdown
