"""Population Stability Index helpers (ANOMALY_DETECTION.md §11). Pure functions."""

from __future__ import annotations

import math
from collections.abc import Iterable, Sequence

import numpy as np

EPS = 1e-4
PSI_WARNING = 0.25


def _psi(expected: Sequence[float], actual: Sequence[float]) -> float:
    total = 0.0
    for exp_share, act_share in zip(expected, actual, strict=True):
        e, a = max(exp_share, EPS), max(act_share, EPS)
        total += (a - e) * math.log(a / e)
    return total


def bin_edges(reference: Sequence[float], bins: int = 10) -> list[float]:
    """Quantile edges fixed from the reference sample (duplicates collapsed)."""
    values = np.asarray([v for v in reference if v is not None and not math.isnan(v)], dtype=float)
    if values.size == 0:
        return []
    edges = np.unique(np.quantile(values, np.linspace(0, 1, bins + 1)[1:-1]))
    return [float(x) for x in edges]


def _shares(values: Iterable[float], edges: list[float]) -> list[float]:
    arr = np.asarray([v for v in values if v is not None and not math.isnan(v)], dtype=float)
    if arr.size == 0:
        return [0.0] * (len(edges) + 1)
    idx = np.searchsorted(np.asarray(edges), arr, side="right")
    counts = np.bincount(idx, minlength=len(edges) + 1)
    return [float(c) / arr.size for c in counts]


def psi_numeric(
    reference: Sequence[float], current: Sequence[float], edges: list[float] | None = None
) -> float:
    edges = bin_edges(reference) if edges is None else edges
    return round(_psi(_shares(reference, edges), _shares(current, edges)), 6)


def category_shares(values: Iterable[str]) -> dict[str, float]:
    items = list(values)
    if not items:
        return {}
    out: dict[str, float] = {}
    for v in items:
        out[v] = out.get(v, 0.0) + 1.0
    return {k: n / len(items) for k, n in sorted(out.items())}


def psi_categorical(reference: dict[str, float], current: dict[str, float]) -> float:
    keys = sorted(set(reference) | set(current))
    return round(
        _psi([reference.get(k, 0.0) for k in keys], [current.get(k, 0.0) for k in keys]), 6
    )
