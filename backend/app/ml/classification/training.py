"""Supervised training and evaluation (ML_CLASSIFICATION.md §5-§9). Pure: no database access.

Inputs are a feature matrix, labels, and per-row metadata; outputs are fitted pipelines plus a
JSON-serialisable report. Every random choice uses the configured seed.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.dummy import DummyClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.inspection import permutation_importance
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    confusion_matrix,
    f1_score,
    precision_recall_fscore_support,
)
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer, OneHotEncoder, StandardScaler
from sklearn.tree import DecisionTreeClassifier

BENIGN = "BENIGN"
OTHER = "OTHER_MALICIOUS"
SHORTCUT_THRESHOLD = 0.98
SUSPICIOUS_TEST_F1 = 0.995
MAX_MISSING_FRACTION = 0.5
PERMUTATION_MAX_ROWS = 20_000
SHORTCUT_MAX_ROWS = 50_000


class TrainingError(Exception):
    """Training cannot proceed (bad data, leakage failure). The run is marked failed."""


# --- configuration ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TrainConfig:
    random_seed: int = 42
    split_strategy: str = "group_stratified"
    group_key: str = "feature_hash"
    test_fraction: float = 0.2
    validation_fraction: float = 0.2
    min_class_support_train: int = 50
    rare_class_policy: str = "merge"
    max_majority_ratio: float = 10.0
    bootstrap_resamples: int = 1000
    rf_grid: dict[str, list[Any]] = field(
        default_factory=lambda: {
            "n_estimators": [100, 300],
            "max_depth": [0, 20],
            "min_samples_leaf": [1, 5],
        }
    )
    max_minutes: float = 30.0


# --- splitting -------------------------------------------------------------------------------


class _UnionFind:
    def __init__(self, n: int) -> None:
        self.parent = list(range(n))

    def find(self, i: int) -> int:
        while self.parent[i] != i:
            self.parent[i] = self.parent[self.parent[i]]
            i = self.parent[i]
        return i

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra


def build_groups(meta: pd.DataFrame, feature_hashes: pd.Series, group_key: str) -> np.ndarray:
    """Group ids so related rows never cross splits (§6.2)."""
    _, groups = np.unique(feature_hashes.to_numpy(), return_inverse=True)
    if group_key == "feature_hash":
        return np.asarray(groups)
    if group_key != "conversation":
        raise TrainingError(f"unknown group_key {group_key!r}")
    if meta["src_ip"].isna().any() or (meta["time_quality"] == "assumed").any():
        raise TrainingError("group_key 'conversation' needs IPs and real timestamps on every row")
    minute = pd.to_datetime(meta["event_time"], utc=True).astype("int64") // 60_000_000_000
    conv = pd.Series(
        list(
            zip(
                meta["src_ip"],
                meta["dst_ip"],
                meta["dst_port"],
                meta["protocol"],
                minute,
                strict=True,
            )
        ),
        index=meta.index,
    )
    _, conv_ids = np.unique(conv.astype(str).to_numpy(), return_inverse=True)
    uf = _UnionFind(len(meta))
    for ids in (groups, conv_ids):
        first: dict[int, int] = {}
        for row, gid in enumerate(ids):
            if gid in first:
                uf.union(first[gid], row)
            else:
                first[gid] = row
    return np.array([uf.find(i) for i in range(len(meta))])


@dataclass
class Split:
    train: np.ndarray
    validation: np.ndarray
    test: np.ndarray
    report: dict[str, Any]


def _sgkf_first_fold(
    y: np.ndarray, groups: np.ndarray, fraction: float, seed: int
) -> tuple[np.ndarray, np.ndarray]:
    n_splits = max(2, round(1 / fraction))
    distinct = len(np.unique(groups))
    if distinct < n_splits:
        raise TrainingError(
            f"only {distinct} distinct feature-vector groups; a leakage-aware split needs at "
            f"least {n_splits} (many rows are exact duplicates of each other)"
        )
    splitter = StratifiedGroupKFold(n_splits=n_splits, shuffle=True, random_state=seed)
    keep, held = next(splitter.split(np.zeros(len(y)), y, groups))
    return keep, held


def split_data(y: np.ndarray, groups: np.ndarray, meta: pd.DataFrame, cfg: TrainConfig) -> Split:
    idx = np.arange(len(y))
    report: dict[str, Any] = {"strategy": cfg.split_strategy, "group_key": cfg.group_key}
    if cfg.split_strategy == "group_stratified":
        rest, test = _sgkf_first_fold(y, groups, cfg.test_fraction, cfg.random_seed)
        tr, va = _sgkf_first_fold(
            y[rest], groups[rest], cfg.validation_fraction, cfg.random_seed + 1
        )
        train, validation = rest[tr], rest[va]
    elif cfg.split_strategy == "temporal":
        if (meta["time_quality"] == "assumed").any():
            raise TrainingError("temporal split is not allowed with assumed timestamps")
        order = np.argsort(pd.to_datetime(meta["event_time"], utc=True).to_numpy(), kind="stable")
        n = len(order)
        cut_val = int(n * (1 - cfg.test_fraction - cfg.validation_fraction))
        cut_test = int(n * (1 - cfg.test_fraction))
        train, validation, test = order[:cut_val], order[cut_val:cut_test], order[cut_test:]
        seen = set(groups[train])
        validation = validation[~np.isin(groups[validation], list(seen))]
        seen |= set(groups[validation])
        dropped = int((np.isin(groups[test], list(seen))).sum())
        test = test[~np.isin(groups[test], list(seen))]
        report["dropped_cross_split_group_rows"] = dropped
    elif cfg.split_strategy == "predefined":
        part = meta["dataset_partition"].fillna("")
        train_mask = (part == "training").to_numpy()
        test_mask = (part == "testing").to_numpy()
        if not train_mask.any() or not test_mask.any():
            raise TrainingError(
                "predefined split needs batches marked dataset_partition 'training' and 'testing'"
            )
        test = idx[test_mask]
        train_pool = idx[train_mask]
        overlap = np.isin(groups[test], groups[train_pool])
        report["official_partition_overlap_rows"] = int(overlap.sum())
        tr, va = _sgkf_first_fold(
            y[train_pool], groups[train_pool], cfg.validation_fraction, cfg.random_seed + 1
        )
        train, validation = train_pool[tr], train_pool[va]
    else:
        raise TrainingError(f"unknown split_strategy {cfg.split_strategy!r}")
    for name, part_idx in (("train", train), ("validation", validation), ("test", test)):
        report[f"{name}_rows"] = len(part_idx)
        report[f"{name}_class_counts"] = _counts(y[part_idx])
        if len(part_idx) == 0:
            raise TrainingError(f"{name} split is empty; add data or change the split strategy")
    missing = sorted(set(y[train]) - set(y[test]))
    report["classes_missing_from_test"] = missing
    return Split(np.sort(train), np.sort(validation), np.sort(test), report)


def _counts(values: np.ndarray) -> dict[str, int]:
    uniq, counts = np.unique(values, return_counts=True)
    return {str(k): int(v) for k, v in zip(uniq, counts, strict=True)}


# --- duplicates, conflicts, imbalance -------------------------------------------------------


def duplicate_report(y: np.ndarray, groups: np.ndarray) -> tuple[dict[str, Any], np.ndarray]:
    """Counts duplicates and returns a mask of rows in label-conflicting groups (§6.3)."""
    frame = pd.DataFrame({"g": groups, "y": y})
    sizes = frame.groupby("g").size()
    labels_per_group = frame.groupby("g")["y"].nunique()
    conflict_groups = set(labels_per_group[labels_per_group > 1].index)
    conflict_mask = frame["g"].isin(conflict_groups).to_numpy()
    dup_groups = sizes[sizes > 1]
    per_class = frame[frame["g"].isin(dup_groups.index)].groupby("y")["g"].nunique()
    report = {
        "rows": len(y),
        "groups": len(sizes),
        "duplicate_rows": int((dup_groups - 1).sum()),
        "duplicate_groups_by_class": {str(k): int(v) for k, v in per_class.items()},
        "label_conflict_groups": len(conflict_groups),
        "label_conflict_rows_excluded": int(conflict_mask.sum()),
    }
    return report, conflict_mask


def apply_rare_class_policy(
    y: np.ndarray, train: np.ndarray, cfg: TrainConfig
) -> tuple[np.ndarray, np.ndarray, dict[str, Any]]:
    """Returns (new labels, keep mask, report). Benign is never merged."""
    counts = _counts(y[train])
    rare = sorted(
        c for c, n in counts.items() if n < cfg.min_class_support_train and c not in (BENIGN, OTHER)
    )
    keep = np.ones(len(y), dtype=bool)
    new_y = y.copy()
    if rare:
        if cfg.rare_class_policy == "merge":
            new_y = np.where(np.isin(y, rare), OTHER, y)
        elif cfg.rare_class_policy == "exclude":
            keep = ~np.isin(y, rare)
        else:
            raise TrainingError(f"unknown rare_class_policy {cfg.rare_class_policy!r}")
    return (
        new_y,
        keep,
        {"rare_classes": rare, "policy": cfg.rare_class_policy, "train_support": counts},
    )


def downsample_majority(
    y: np.ndarray, train: np.ndarray, cfg: TrainConfig
) -> tuple[np.ndarray, dict[str, Any]]:
    if cfg.max_majority_ratio <= 0:
        return train, {"applied": False}
    counts = _counts(y[train])
    attacks = [n for c, n in counts.items() if c != BENIGN]
    if BENIGN not in counts or not attacks:
        return train, {"applied": False}
    cap = int(max(attacks) * cfg.max_majority_ratio)
    if counts[BENIGN] <= cap:
        return train, {"applied": False}
    rng = np.random.default_rng(cfg.random_seed)
    benign = train[y[train] == BENIGN]
    kept = rng.choice(benign, size=cap, replace=False)
    result = np.sort(np.concatenate([train[y[train] != BENIGN], kept]))
    return result, {"applied": True, "benign_before": counts[BENIGN], "benign_after": cap}


# --- pipelines -------------------------------------------------------------------------------


def _signed_log1p(x: Any) -> Any:
    return np.sign(x) * np.log1p(np.abs(x))


def build_pipeline(numeric: list[str], categorical: list[str], estimator: Any) -> Pipeline:
    transformers: list[tuple[str, Any, list[str]]] = []
    if numeric:
        transformers.append(
            (
                "num",
                Pipeline(
                    [
                        (
                            "impute",
                            SimpleImputer(
                                strategy="median", add_indicator=True, keep_empty_features=True
                            ),
                        ),
                        ("log", FunctionTransformer(_signed_log1p)),
                        ("scale", StandardScaler()),
                    ]
                ),
                numeric,
            )
        )
    if categorical:
        transformers.append(
            (
                "cat",
                Pipeline(
                    [
                        ("impute", SimpleImputer(strategy="constant", fill_value="missing")),
                        ("onehot", OneHotEncoder(handle_unknown="ignore", sparse_output=False)),
                    ]
                ),
                categorical,
            )
        )
    return Pipeline([("features", ColumnTransformer(transformers)), ("model", estimator)])


def _rf(params: dict[str, Any], seed: int) -> RandomForestClassifier:
    depth = params.get("max_depth", 0)
    return RandomForestClassifier(
        n_estimators=int(params.get("n_estimators", 300)),
        max_depth=None if not depth else int(depth),
        min_samples_leaf=int(params.get("min_samples_leaf", 1)),
        max_features="sqrt",
        class_weight="balanced_subsample",
        n_jobs=-1,
        random_state=seed,
    )


def _grid(grid: dict[str, list[Any]]) -> list[dict[str, Any]]:
    combos: list[dict[str, Any]] = [{}]
    for key, values in grid.items():
        combos = [{**c, key: v} for c in combos for v in values]
    return combos


# --- evaluation ------------------------------------------------------------------------------


def evaluate(y_true: np.ndarray, y_pred: np.ndarray, labels: list[str]) -> dict[str, Any]:
    p, r, f, s = precision_recall_fscore_support(y_true, y_pred, labels=labels, zero_division=0)
    cm = confusion_matrix(y_true, y_pred, labels=labels)
    with np.errstate(invalid="ignore", divide="ignore"):
        normalised = np.where(
            cm.sum(axis=1, keepdims=True) > 0, cm / cm.sum(axis=1, keepdims=True), 0.0
        )
    malicious_true = y_true != BENIGN
    malicious_pred = y_pred != BENIGN
    benign_rows = ~malicious_true
    return {
        "per_class": {
            label: {
                "precision": float(p[i]),
                "recall": float(r[i]),
                "f1": float(f[i]),
                "support": int(s[i]),
            }
            for i, label in enumerate(labels)
        },
        "macro_f1": float(
            f1_score(y_true, y_pred, labels=labels, average="macro", zero_division=0)
        ),
        "weighted_f1": float(
            f1_score(y_true, y_pred, labels=labels, average="weighted", zero_division=0)
        ),
        "balanced_accuracy": float(balanced_accuracy_score(y_true, y_pred)),
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "confusion_matrix": {
            "labels": labels,
            "counts": cm.tolist(),
            "row_normalized": np.round(normalised, 6).tolist(),
        },
        "binary": {
            "malicious_recall": float(
                (malicious_pred & malicious_true).sum() / malicious_true.sum()
            )
            if malicious_true.any()
            else None,
            "benign_false_positive_rate": float(
                (malicious_pred & benign_rows).sum() / benign_rows.sum()
            )
            if benign_rows.any()
            else None,
        },
        "rows": len(y_true),
    }


def bootstrap_macro_f1(
    y_true: np.ndarray, y_pred: np.ndarray, labels: list[str], resamples: int, seed: int
) -> dict[str, Any]:
    rng = np.random.default_rng(seed)
    n = len(y_true)
    scores = []
    for _ in range(resamples):
        idx = rng.integers(0, n, n)
        scores.append(
            f1_score(y_true[idx], y_pred[idx], labels=labels, average="macro", zero_division=0)
        )
    low, high = np.percentile(scores, [2.5, 97.5])
    return {"level": 0.95, "low": float(low), "high": float(high), "resamples": resamples}


def shortcut_features(
    x_train: pd.DataFrame,
    y_train: np.ndarray,
    x_val: pd.DataFrame,
    y_val: np.ndarray,
    seed: int,
) -> list[dict[str, Any]]:
    """Single features that alone reach macro-F1 >= 0.98 on validation (§6.4)."""
    rng = np.random.default_rng(seed)
    if len(x_train) > SHORTCUT_MAX_ROWS:
        pick = np.sort(rng.choice(len(x_train), SHORTCUT_MAX_ROWS, replace=False))
        x_train, y_train = x_train.iloc[pick], y_train[pick]
    labels = sorted(set(y_val))
    flagged = []
    for column in x_train.columns:
        is_cat = not pd.api.types.is_numeric_dtype(x_train[column])
        pipe = build_pipeline(
            [] if is_cat else [column],
            [column] if is_cat else [],
            DecisionTreeClassifier(max_depth=3, random_state=seed),
        )
        pipe.fit(x_train[[column]], y_train)
        score = f1_score(
            y_val, pipe.predict(x_val[[column]]), labels=labels, average="macro", zero_division=0
        )
        if score >= SHORTCUT_THRESHOLD:
            flagged.append({"feature": column, "validation_macro_f1": round(float(score), 4)})
    return flagged


# --- orchestration ----------------------------------------------------------------------------


@dataclass
class TrainResult:
    pipeline: Pipeline
    labels: list[str]
    report: dict[str, Any]
    test_features: pd.DataFrame
    test_labels: np.ndarray


def train_and_evaluate(
    features: pd.DataFrame,
    y_raw: np.ndarray,
    meta: pd.DataFrame,
    hashes: pd.Series,
    numeric: list[str],
    categorical: list[str],
    cfg: TrainConfig,
    progress: Callable[[str], None] | None = None,
) -> TrainResult:
    started = time.monotonic()

    def step(message: str) -> None:
        if progress:
            progress(message)

    if len(features) < 20:
        raise TrainingError(f"only {len(features)} labelled rows; need at least 20")
    data_report: dict[str, Any] = {"rows_in_snapshot": len(features)}

    too_sparse = (features.isna().mean(axis=1) > MAX_MISSING_FRACTION).to_numpy()
    data_report["excluded_too_many_missing_features"] = int(too_sparse.sum())

    groups = build_groups(meta, hashes, cfg.group_key)
    dup, conflict = duplicate_report(y_raw, groups)
    data_report["duplicates"] = dup
    usable = ~too_sparse & ~conflict
    features, y_raw, meta, groups = (features[usable], y_raw[usable], meta[usable], groups[usable])
    features = features.reset_index(drop=True)
    meta = meta.reset_index(drop=True)
    if len(np.unique(y_raw)) < 2:
        raise TrainingError("need at least two distinct classes after exclusions")

    step("splitting")
    split = split_data(y_raw, groups, meta, cfg)
    y, keep, rare_report = apply_rare_class_policy(y_raw, split.train, cfg)
    data_report["rare_classes"] = rare_report
    train = split.train[keep[split.train]]
    validation = split.validation[keep[split.validation]]
    test = split.test[keep[split.test]]
    train, down_report = downsample_majority(y, train, cfg)
    data_report["downsampling"] = down_report
    split.report["after_rare_class_policy"] = {
        "train_class_counts": _counts(y[train]),
        "validation_class_counts": _counts(y[validation]),
        "test_class_counts": _counts(y[test]),
    }

    # Leakage checks (§6.4)
    leakage: dict[str, Any] = {"failures": [], "warnings": []}
    for a_name, a, b_name, b in (
        ("train", train, "validation", validation),
        ("train", train, "test", test),
        ("validation", validation, "test", test),
    ):
        shared = set(groups[a]) & set(groups[b])
        if shared:
            leakage["failures"].append(f"{len(shared)} groups appear in both {a_name} and {b_name}")
        ids = set(meta["event_id"].iloc[a]) & set(meta["event_id"].iloc[b])
        if ids:
            leakage["failures"].append(f"{len(ids)} event ids in both {a_name} and {b_name}")
    if leakage["failures"]:
        raise TrainingError("leakage check failed: " + "; ".join(leakage["failures"]))

    labels = sorted(set(y[train]))
    if len(labels) < 2:
        raise TrainingError("training split has fewer than two classes")
    x_tr, x_va, x_te = features.iloc[train], features.iloc[validation], features.iloc[test]
    y_tr, y_va, y_te = y[train], y[validation], y[test]

    step("shortcut-feature check")
    shortcuts = shortcut_features(x_tr, y_tr, x_va, y_va, cfg.random_seed)
    for item in shortcuts:
        leakage["warnings"].append(
            f"possible shortcut/leakage feature: {item['feature']} (validation macro-F1 "
            f"{item['validation_macro_f1']} with a depth-3 tree on this feature alone)"
        )
    leakage["shortcut_features"] = shortcuts

    models: dict[str, dict[str, Any]] = {}

    def fit_eval(name: str, estimator: Any) -> Pipeline:
        pipe = build_pipeline(numeric, categorical, estimator)
        pipe.fit(x_tr, y_tr)
        models[name] = {
            "validation": evaluate(y_va, pipe.predict(x_va), labels),
            "test": evaluate(y_te, pipe.predict(x_te), labels),
        }
        return pipe

    step("baselines")
    fit_eval("dummy_most_frequent", DummyClassifier(strategy="most_frequent"))
    fit_eval(
        "dummy_stratified", DummyClassifier(strategy="stratified", random_state=cfg.random_seed)
    )
    fit_eval(
        "logistic_regression",
        LogisticRegression(class_weight="balanced", max_iter=2000, random_state=cfg.random_seed),
    )

    step("random forest tuning")
    tuning: list[dict[str, Any]] = []
    best: tuple[float, dict[str, Any]] | None = None
    for params in _grid(cfg.rf_grid):
        if time.monotonic() - started > cfg.max_minutes * 60:
            tuning.append({"params": params, "skipped": "time budget exhausted"})
            continue
        pipe = build_pipeline(numeric, categorical, _rf(params, cfg.random_seed))
        pipe.fit(x_tr, y_tr)
        score = f1_score(y_va, pipe.predict(x_va), labels=labels, average="macro", zero_division=0)
        tuning.append({"params": params, "validation_macro_f1": float(score)})
        if best is None or score > best[0]:
            best = (float(score), params)
    if best is None:
        raise TrainingError("time budget exhausted before any random forest was trained")
    rf = fit_eval("random_forest", _rf(best[1], cfg.random_seed))
    rf_test_pred = rf.predict(x_te)

    test_f1 = models["random_forest"]["test"]["macro_f1"]
    if test_f1 >= SUSPICIOUS_TEST_F1:
        leakage["warnings"].append(
            f"suspiciously high test macro-F1 ({test_f1:.4f}); review the leakage report"
        )

    step("permutation importance")
    rng = np.random.default_rng(cfg.random_seed)
    pick = np.sort(rng.choice(len(x_va), min(len(x_va), PERMUTATION_MAX_ROWS), replace=False))
    perm = permutation_importance(
        rf,
        x_va.iloc[pick],
        y_va[pick],
        scoring="f1_macro",
        n_repeats=5,
        random_state=cfg.random_seed,
        n_jobs=1,
    )
    importance = sorted(
        (
            {"feature": col, "mean": float(m), "std": float(s)}
            for col, m, s in zip(
                x_va.columns, perm.importances_mean, perm.importances_std, strict=True
            )
        ),
        key=lambda d: -d["mean"],
    )[:20]

    step("bootstrap")
    ci = bootstrap_macro_f1(y_te, rf_test_pred, labels, cfg.bootstrap_resamples, cfg.random_seed)

    report = {
        "primary_model": "random_forest",
        "selection_metric": "validation macro-F1",
        "random_forest_params": best[1],
        "tuning": tuning,
        "models": models,
        "class_labels": labels,
        "test_macro_f1_ci": ci,
        "permutation_importance": importance,
        "leakage": leakage,
        "split": split.report,
        "data": data_report,
        "elapsed_seconds": round(time.monotonic() - started, 2),
    }
    return TrainResult(rf, labels, report, x_te, y_te)
