"""Classification pipeline unit tests (TESTING_STRATEGY.md §7)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import pytest
from sklearn.metrics import f1_score

from app.ml import artifacts
from app.ml.classification.training import (
    TrainConfig,
    TrainingError,
    apply_rare_class_policy,
    build_groups,
    downsample_majority,
    duplicate_report,
    evaluate,
    split_data,
    train_and_evaluate,
)
from app.ml.features import (
    FeatureError,
    FeatureSet,
    build_features,
    denylisted,
    feature_hash,
    load_feature_set,
)

pytestmark = pytest.mark.unit

FAST = TrainConfig(
    min_class_support_train=5,
    bootstrap_resamples=50,
    rf_grid={"n_estimators": [20], "max_depth": [0], "min_samples_leaf": [1]},
)


def _frame(n: int = 600, seed: int = 0) -> tuple[pd.DataFrame, np.ndarray]:
    rng = np.random.default_rng(seed)
    labels = rng.choice(["BENIGN", "DOS", "RECONNAISSANCE"], size=n, p=[0.6, 0.25, 0.15])
    base = {"BENIGN": 5000, "DOS": 200, "RECONNAISSANCE": 60}
    rows = []
    for i, label in enumerate(labels):
        rows.append(
            {
                "event_id": i + 1,
                "event_time": pd.Timestamp("2026-01-01", tz="UTC") + pd.Timedelta(seconds=i),
                "time_quality": "second",
                "src_ip": f"192.0.2.{i % 50}",
                "dst_ip": "198.51.100.7",
                "dst_port": 80 if label != "RECONNAISSANCE" else int(rng.integers(1, 1000)),
                "protocol": "tcp",
                "duration_s": float(rng.exponential(2 if label == "BENIGN" else 0.1)),
                "bytes_out": int(base[label] * rng.uniform(0.5, 1.5)),
                "bytes_in": int(base[label] * rng.uniform(0.2, 2.0)),
                "packets_out": int(rng.integers(1, 40)),
                "packets_in": int(rng.integers(0, 40)),
                "attributes": {},
                "dataset_partition": None,
            }
        )
    return pd.DataFrame(rows), np.asarray(labels)


def _train(frame: pd.DataFrame, y: np.ndarray, cfg: TrainConfig = FAST) -> Any:
    fs = load_feature_set("flow_v1")
    features = build_features(frame, fs, require_attributes=True)
    meta = frame[
        [
            "event_id",
            "event_time",
            "time_quality",
            "src_ip",
            "dst_ip",
            "dst_port",
            "protocol",
            "dataset_partition",
        ]
    ]
    return train_and_evaluate(
        features, y, meta, feature_hash(features), fs.numeric_columns, fs.categorical_columns, cfg
    )


def test_feature_sets_load_and_denylist_is_enforced() -> None:
    fs = load_feature_set("flow_v1")
    assert "src_ip" not in fs.numeric_columns and "protocol" in fs.categorical_columns
    native = load_feature_set("cicids2017_native_v1")
    assert "attr_flow_bytes_s" in native.numeric_columns
    assert denylisted(
        ["attr_label", "attr_attack_cat", "src_ip", "attr_flow_id", "attr_timestamp", "bytes_out"]
    ) == ["attr_label", "attr_attack_cat", "src_ip", "attr_flow_id", "attr_timestamp"]
    with pytest.raises(FeatureError):
        load_feature_set("does_not_exist")


def test_derived_features_match_hand_computed_values() -> None:
    frame = pd.DataFrame(
        [
            {
                "duration_s": 2.0,
                "bytes_out": 1000,
                "bytes_in": 499,
                "packets_out": 10,
                "packets_in": 0,
                "protocol": "gre",
                "dst_port": 50000,
                "attributes": {},
            }
        ]
    )
    x = build_features(frame, load_feature_set("flow_v1"), require_attributes=True).iloc[0]
    assert x["total_bytes"] == 1499 and x["total_packets"] == 10
    assert x["bytes_per_packet_out"] == 100 and np.isnan(x["bytes_per_packet_in"])
    assert x["out_in_byte_ratio"] == pytest.approx(1001 / 500)
    assert x["packets_per_second"] == 5 and x["bytes_per_second"] == pytest.approx(749.5)
    assert x["protocol"] == "other" and x["dst_port_class"] == "dynamic"


def test_missing_native_attributes_fail_training_but_not_inference() -> None:
    frame = pd.DataFrame(
        [
            {
                "duration_s": 1,
                "bytes_out": 1,
                "bytes_in": 1,
                "packets_out": 1,
                "packets_in": 1,
                "protocol": "tcp",
                "dst_port": 80,
                "attributes": {"flow_bytes_s": 5},
            }
        ]
    )
    fs = load_feature_set("cicids2017_native_v1")
    with pytest.raises(FeatureError, match="missing from every row"):
        build_features(frame, fs, require_attributes=True)
    x = build_features(frame, fs, require_attributes=False)
    assert x["attr_flow_bytes_s"].iloc[0] == 5 and np.isnan(x["attr_idle_mean"].iloc[0])


@pytest.mark.parametrize("seed", [0, 1, 2, 3])
def test_group_split_never_shares_groups(seed: int) -> None:
    rng = np.random.default_rng(seed)
    groups = rng.integers(0, 80, 400)
    y = np.where(groups % 3 == 0, "DOS", "BENIGN")
    meta = pd.DataFrame(
        {
            "time_quality": ["second"] * 400,
            "event_time": pd.Timestamp("2026-01-01"),
            "dataset_partition": None,
        }
    )
    split = split_data(y, groups, meta, TrainConfig(random_seed=seed))
    sets = [set(groups[s]) for s in (split.train, split.validation, split.test)]
    assert not (sets[0] & sets[1]) and not (sets[0] & sets[2]) and not (sets[1] & sets[2])
    assert len(split.train) + len(split.validation) + len(split.test) == 400


def test_duplicates_and_label_conflicts_are_counted_and_excluded() -> None:
    y = np.array(["A", "A", "A", "B", "B", "C"])
    groups = np.array([1, 1, 2, 2, 3, 4])  # group 2 has conflicting labels
    report, conflict = duplicate_report(y, groups)
    assert report["duplicate_rows"] == 2 and report["label_conflict_groups"] == 1
    assert conflict.tolist() == [False, False, True, True, False, False]


def test_conversation_groups_union_related_flows() -> None:
    meta = pd.DataFrame(
        {
            "src_ip": ["a", "a", "b"],
            "dst_ip": ["x", "x", "x"],
            "dst_port": [80, 80, 80],
            "protocol": ["tcp"] * 3,
            "time_quality": ["second"] * 3,
            "event_time": pd.to_datetime(
                ["2026-01-01T00:00:01Z", "2026-01-01T00:00:30Z", "2026-01-01T00:00:31Z"]
            ),
        }
    )
    groups = build_groups(meta, pd.Series([1, 2, 3]), "conversation")
    assert groups[0] == groups[1] != groups[2]


def test_rare_class_policies_and_downsampling() -> None:
    y = np.array(["BENIGN"] * 100 + ["DOS"] * 10 + ["WORM"] * 2)
    train = np.arange(len(y))
    merged, _keep, report = apply_rare_class_policy(
        y, train, TrainConfig(min_class_support_train=5)
    )
    assert report["rare_classes"] == ["WORM"] and (merged == "OTHER_MALICIOUS").sum() == 2
    _, keep_ex, _ = apply_rare_class_policy(
        y, train, TrainConfig(min_class_support_train=5, rare_class_policy="exclude")
    )
    assert keep_ex.sum() == 110
    sampled, info = downsample_majority(y, train, TrainConfig(max_majority_ratio=2.0))
    assert info["benign_after"] == 20 and len(sampled) == 32


def test_evaluate_matches_sklearn() -> None:
    y_true = np.array(["BENIGN", "DOS", "DOS", "BENIGN", "RECON"])
    y_pred = np.array(["BENIGN", "DOS", "BENIGN", "BENIGN", "DOS"])
    labels = ["BENIGN", "DOS", "RECON"]
    report = evaluate(y_true, y_pred, labels)
    assert report["macro_f1"] == pytest.approx(f1_score(y_true, y_pred, average="macro"))
    assert report["confusion_matrix"]["counts"] == [[2, 0, 0], [1, 1, 0], [0, 1, 0]]
    assert report["binary"]["malicious_recall"] == pytest.approx(2 / 3)
    assert report["binary"]["benign_false_positive_rate"] == 0.0


def test_training_is_reproducible_and_reports_everything() -> None:
    frame, y = _frame()
    first, second = _train(frame, y), _train(frame, y)
    for name in ("random_forest", "logistic_regression", "dummy_stratified", "dummy_most_frequent"):
        assert first.report["models"][name] == second.report["models"][name]
    np.testing.assert_array_equal(
        first.pipeline.predict(first.test_features), second.pipeline.predict(second.test_features)
    )
    report = first.report
    rf_test = report["models"]["random_forest"]["test"]
    assert set(rf_test["per_class"]) == set(report["class_labels"])
    assert {"macro_f1", "weighted_f1", "confusion_matrix", "balanced_accuracy"} <= set(rf_test)
    assert (
        report["test_macro_f1_ci"]["low"]
        <= rf_test["macro_f1"]
        <= report["test_macro_f1_ci"]["high"]
    )
    assert report["permutation_importance"]
    assert rf_test["macro_f1"] > report["models"]["dummy_stratified"]["test"]["macro_f1"]


def test_preprocessing_is_fitted_on_training_rows_only() -> None:
    frame, y = _frame()
    result = _train(frame, y)
    scaler = result.pipeline.named_steps["features"].named_transformers_["num"].named_steps["scale"]
    train_rows = result.report["split"]["after_rare_class_policy"]["train_class_counts"]
    assert scaler.n_samples_seen_ == sum(train_rows.values()) < len(frame)


def test_leaking_feature_triggers_shortcut_warning() -> None:
    frame, y = _frame()
    codes = {"BENIGN": 1.0, "DOS": 2.0, "RECONNAISSANCE": 3.0}
    rng = np.random.default_rng(5)
    frame["attributes"] = [{"leak": codes[label], "noise": float(rng.normal())} for label in y]
    fs = FeatureSet(
        name="leaky",
        version=1,
        event_types=("network_flow",),
        numeric=(),
        derived=(),
        categorical=(),
        attributes=("leak", "noise"),
    )
    features = build_features(frame, fs, require_attributes=True)
    meta = frame[
        [
            "event_id",
            "event_time",
            "time_quality",
            "src_ip",
            "dst_ip",
            "dst_port",
            "protocol",
            "dataset_partition",
        ]
    ]
    result = train_and_evaluate(
        features, y, meta, feature_hash(features), fs.numeric_columns, [], FAST
    )
    shortcuts = result.report["leakage"]["shortcut_features"]
    assert [s["feature"] for s in shortcuts] == ["attr_leak"]
    assert any("suspiciously high" in w for w in result.report["leakage"]["warnings"])


def test_too_few_distinct_groups_fails_clearly() -> None:
    frame, y = _frame()
    value = {"BENIGN": 1, "DOS": 2, "RECONNAISSANCE": 3}
    for col in ("duration_s", "bytes_out", "bytes_in", "packets_out", "packets_in"):
        frame[col] = [value[label] for label in y]  # one group per class: no valid split
    frame["dst_port"] = 80
    with pytest.raises(TrainingError, match="distinct feature-vector groups"):
        _train(frame, y)


def test_too_little_data_fails_clearly() -> None:
    frame, y = _frame(n=10)
    with pytest.raises(TrainingError, match="need at least 20"):
        _train(frame, y)


def test_artifact_roundtrip_and_integrity(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    frame, y = _frame()
    result = _train(frame, y)
    manifest = {"environment": artifacts.environment(), "feature_set": "flow_v1@1"}
    path, sha = artifacts.save(tmp_path, "m", 1, result.pipeline, manifest, {"ok": True})
    loaded, _manifest = artifacts.load(tmp_path, str(path), sha)
    np.testing.assert_array_equal(
        loaded.predict(result.test_features), result.pipeline.predict(result.test_features)
    )
    assert json.loads((path.parent / "report.json").read_text()) == {"ok": True}
    with pytest.raises(FileExistsError):
        artifacts.save(tmp_path, "m", 1, result.pipeline, manifest, {})  # write-once
    with pytest.raises(artifacts.ArtifactError) as wrong_hash:
        artifacts.load(tmp_path, str(path), "0" * 64)
    assert wrong_hash.value.code == "ARTIFACT_INTEGRITY_FAILED"
    with pytest.raises(artifacts.ArtifactError) as outside:
        artifacts.load(tmp_path / "elsewhere", str(path), sha)
    assert outside.value.code == "ARTIFACT_PATH_REJECTED"
    monkeypatch.setattr(artifacts.sklearn, "__version__", "0.1.0")
    with pytest.raises(artifacts.ArtifactError) as version:
        artifacts.load(tmp_path, str(path), sha)
    assert version.value.code == "ARTIFACT_VERSION_MISMATCH"
