"""Anomaly scoring methods (ANOMALY_DETECTION.md §4-§6, §9). Pure; no database access.

Scores are *not* probabilities: higher means more unusual for this model version. The flag
threshold is a percentile of the reference-period score distribution, never ``contamination``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.impute import SimpleImputer
from sklearn.metrics import average_precision_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer, StandardScaler

from app.ml.anomaly.windows import robust_stats, robust_z

DEVIATION_Z = 3.0
QUANTILE_POINTS = 2001
# Robust-z thresholds never go below a conventional "notable deviation", even when the
# reference period has almost no variation (its 99th percentile can then be 0).
ROBUST_Z_MIN_THRESHOLD = 3.0
IFOREST_RECOMMENDED_REFERENCE_WINDOWS = 256


@dataclass(frozen=True)
class MethodConfig:
    method: str
    entity_type: str
    window_size: str
    features: list[str]
    random_seed: int = 42
    threshold_percentile: float = 99.0
    baseline_days: int = 14
    min_baseline_windows: int = 24
    n_estimators: int = 200


@dataclass
class EntityHistory:
    scores: pd.Series  # robust-z score per window (NaN when insufficient history)
    deviations: list[list[dict[str, Any]]]
    baselines: list[dict[str, Any] | None]
    insufficient: pd.Series = field(default_factory=lambda: pd.Series(dtype=bool))


def history_scores(windows: pd.DataFrame, cfg: MethodConfig) -> EntityHistory:
    """Per-entity robust z against the trailing ``baseline_days`` of earlier windows."""
    scores = pd.Series(np.nan, index=windows.index, dtype="float64")
    deviations: list[list[dict[str, Any]]] = [[] for _ in range(len(windows))]
    baselines: list[dict[str, Any] | None] = [None] * len(windows)
    insufficient = pd.Series(True, index=windows.index)
    look_back = pd.Timedelta(timedelta(days=cfg.baseline_days))
    position = {idx: i for i, idx in enumerate(windows.index)}
    for _entity, unsorted in windows.groupby("entity_value", sort=False):
        group = unsorted.sort_values("window_start")
        starts = group["window_start"].to_numpy()
        values = group[cfg.features].astype("float64")
        for j, idx in enumerate(group.index):
            current = starts[j]
            mask = (starts < current) & (starts >= current - look_back)
            history = values[mask]
            if len(history) < cfg.min_baseline_windows:
                continue
            median, mad, mean_abs = robust_stats(history)
            z = robust_z(values.loc[idx], median, mad, mean_abs)
            scores.loc[idx] = float(z.abs().max())
            insufficient.loc[idx] = False
            deviations[position[idx]] = explain(values.loc[idx], z, median, mad)
            baselines[position[idx]] = {
                "windows": len(history),
                "median": {k: _num(v) for k, v in median.items()},
                "mad": {k: _num(v) for k, v in mad.items()},
            }
    return EntityHistory(scores, deviations, baselines, insufficient)


def explain(
    row: pd.Series,
    z: pd.Series,
    median: pd.Series,
    mad: pd.Series,
    *,
    against: str = "entity history",
) -> list[dict[str, Any]]:
    """Features whose |robust z| >= 3, largest first, with value vs. baseline."""
    values, medians, mads = row.to_dict(), median.to_dict(), mad.to_dict()
    items: list[dict[str, Any]] = []
    for key, score in z.to_dict().items():
        if abs(float(score)) < DEVIATION_Z:
            continue
        items.append(
            {
                "feature": str(key),
                "value": _num(values[key]),
                "baseline_median": _num(medians[key]),
                "baseline_mad": _num(mads[key]),
                "robust_z": round(float(score), 3),
                "against": against,
            }
        )
    return sorted(items, key=lambda d: -abs(d["robust_z"]))[:10]


def _num(value: Any) -> float | None:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return None if np.isnan(number) else round(number, 6)


def _signed_log1p(x: Any) -> Any:
    return np.sign(x) * np.log1p(np.abs(x))


def fit_isolation_forest(reference: pd.DataFrame, cfg: MethodConfig) -> Pipeline:
    pipeline = Pipeline(
        [
            ("impute", SimpleImputer(strategy="median", keep_empty_features=True)),
            ("log", FunctionTransformer(_signed_log1p)),
            ("scale", StandardScaler()),
            (
                "model",
                IsolationForest(
                    n_estimators=cfg.n_estimators,
                    max_samples="auto",
                    contamination="auto",
                    random_state=cfg.random_seed,
                ),
            ),
        ]
    )
    pipeline.fit(reference[cfg.features].astype("float64"))
    return pipeline


def isolation_scores(pipeline: Pipeline, windows: pd.DataFrame, features: list[str]) -> np.ndarray:
    """Negated ``score_samples`` so that higher = more unusual."""
    return np.asarray(-pipeline.score_samples(windows[features].astype("float64")))


def quantiles(scores: np.ndarray) -> list[float]:
    clean = scores[~np.isnan(scores)]
    if clean.size == 0:
        return []
    return [float(q) for q in np.quantile(clean, np.linspace(0, 1, QUANTILE_POINTS))]


def threshold_from(reference_quantiles: list[float], percentile: float, method: str) -> float:
    if not reference_quantiles:
        raise ValueError("no reference scores to derive a threshold from")
    value = float(np.quantile(np.asarray(reference_quantiles), percentile / 100.0))
    if method == "robust_zscore":
        value = max(value, ROBUST_Z_MIN_THRESHOLD)
    return value


def percentile_of(score: float, reference_quantiles: list[float]) -> float:
    """'More unusual than X % of reference windows.'"""
    if not reference_quantiles or np.isnan(score):
        return float("nan")
    ref = np.asarray(reference_quantiles)
    return float(np.searchsorted(ref, score, side="left") / len(ref) * 100.0)


def proxy_evaluation(scores: np.ndarray, malicious: np.ndarray, threshold: float) -> dict[str, Any]:
    """Proxy metrics against 'window contains >= 1 labelled-malicious event' (§9)."""
    valid = ~np.isnan(scores)
    scores, malicious = scores[valid], malicious[valid].astype(bool)
    flagged = scores >= threshold
    positives = int(malicious.sum())
    result: dict[str, Any] = {
        "label": "proxy evaluation - unusual is not the same as malicious",
        "windows": len(scores),
        "windows_with_labelled_attacks": positives,
        "flagged": int(flagged.sum()),
        "flagged_with_labelled_attacks": int((flagged & malicious).sum()),
    }
    if positives and positives < len(scores):
        order = np.argsort(-scores)
        for k in (10, 50):
            top = order[: min(k, len(order))]
            result[f"precision_at_{k}"] = round(float(malicious[top].mean()), 4)
        result["recall_of_attack_windows"] = round(
            float((flagged & malicious).sum() / positives), 4
        )
        result["pr_auc"] = round(float(average_precision_score(malicious, scores)), 4)
    else:
        result["note"] = "metrics need both attack and non-attack windows in the labelled data"
    return result
