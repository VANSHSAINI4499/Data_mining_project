"""Anomaly mining unit tests (TESTING_STRATEGY.md §7, AC-4.1 - AC-4.3)."""

from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from app.ml.anomaly import methods
from app.ml.anomaly.windows import FEATURES, build_windows, robust_stats, robust_z

pytestmark = pytest.mark.unit


def _events(rows: list[dict[str, object]]) -> pd.DataFrame:
    base = {
        "event_type": "auth",
        "src_ip": None,
        "dst_ip": None,
        "dst_port": None,
        "host_name": None,
        "user_name_normalized": None,
        "auth_result": None,
        "bytes_out": None,
        "bytes_in": None,
        "duration_s": None,
    }
    return pd.DataFrame([{**base, **r} for r in rows])


def test_account_window_features_match_hand_computed_values() -> None:
    frame = _events(
        [
            {
                "event_time": "2026-01-01T09:05:00Z",
                "user_name_normalized": "a",
                "auth_result": "success",
                "src_ip": "192.0.2.1",
                "host_name": "h1",
            },
            {
                "event_time": "2026-01-01T09:10:00Z",
                "user_name_normalized": "a",
                "auth_result": "failure",
                "src_ip": "192.0.2.2",
                "host_name": "h1",
            },
            {
                "event_time": "2026-01-01T09:20:00Z",
                "user_name_normalized": "a",
                "auth_result": "failure",
                "src_ip": "192.0.2.2",
                "host_name": "h2",
            },
            {
                "event_time": "2026-01-01T22:00:00Z",
                "user_name_normalized": "a",
                "auth_result": "success",
                "src_ip": "192.0.2.1",
            },
            {
                "event_time": "2026-01-01T09:00:00Z",
                "event_type": "network_flow",
                "src_ip": "192.0.2.9",
            },
        ]
    )
    windows = build_windows(frame, "account", "1h").set_index("window_start")
    assert list(windows.columns) == ["entity_value", *FEATURES["account"]]
    morning = windows.loc[pd.Timestamp("2026-01-01T09:00:00Z")]
    assert morning["event_count"] == 3
    assert (morning["failed_auth_count"], morning["success_auth_count"]) == (2, 1)
    assert morning["failed_auth_ratio"] == pytest.approx(2 / 3)
    assert morning["distinct_src_ips_for_account"] == 2
    assert morning["distinct_hosts_for_account"] == 2
    assert morning["new_src_ip_for_account"] == 2
    assert morning["off_hours_fraction"] == 0.0
    night = windows.loc[pd.Timestamp("2026-01-01T22:00:00Z")]
    assert night["new_src_ip_for_account"] == 0  # 192.0.2.1 seen earlier
    assert night["off_hours_fraction"] == 1.0
    assert len(windows) == 2  # the flow is not an account event; no empty windows are created


def test_host_windows_and_site_timezone() -> None:
    frame = _events(
        [
            {
                "event_time": "2026-01-01T03:30:00Z",
                "event_type": "network_flow",
                "src_ip": "192.0.2.5",
                "dst_ip": "198.51.100.1",
                "dst_port": 443,
                "bytes_out": 100,
                "bytes_in": 50,
                "duration_s": 2.0,
            },
            {
                "event_time": "2026-01-01T03:40:00Z",
                "event_type": "ids_alert",
                "src_ip": "192.0.2.5",
                "dst_ip": "198.51.100.2",
                "dst_port": 22,
            },
        ]
    )
    utc = build_windows(frame, "src_ip", "1h").iloc[0]
    assert (utc["distinct_dst_ips"], utc["distinct_dst_ports"], utc["ids_alert_count"]) == (2, 2, 1)
    assert utc["bytes_out_sum"] == 100 and utc["bytes_null_count"] == 1
    assert utc["off_hours_fraction"] == 1.0  # 03:30 UTC
    india = build_windows(frame, "src_ip", "1h", site_timezone="Asia/Kolkata").iloc[0]
    assert india["off_hours_fraction"] == 0.0  # 09:00 local
    with pytest.raises(ValueError):
        build_windows(frame, "src_ip", "5m")


def test_robust_z_and_zero_mad_fallback() -> None:
    history = pd.DataFrame({"a": [1.0, 2.0, 3.0, 4.0, 5.0], "b": [1.0] * 5})
    median, mad, mean_abs = robust_stats(history)
    z = robust_z(pd.Series({"a": 7.0, "b": 41.0}), median, mad, mean_abs)
    assert z["a"] == pytest.approx(0.6745 * (7 - 3) / 1)
    assert z["b"] == pytest.approx(40.0)  # MAD 0 -> unit scale floor; finite and readable


def test_history_scores_need_enough_baseline_windows() -> None:
    starts = pd.date_range("2026-01-01", periods=30, freq="1h", tz="UTC")
    windows = pd.DataFrame(
        {"entity_value": "x", "window_start": starts, "event_count": [1.0] * 29 + [50.0]}
    )
    cfg = methods.MethodConfig(
        method="robust_zscore",
        entity_type="account",
        window_size="1h",
        features=["event_count"],
        min_baseline_windows=24,
    )
    history = methods.history_scores(windows, cfg)
    assert history.insufficient.iloc[:24].all() and not history.insufficient.iloc[24:].any()
    assert history.scores.iloc[-1] == pytest.approx(49.0)
    assert history.deviations[-1][0]["feature"] == "event_count"


def test_thresholds_percentiles_and_robust_floor() -> None:
    reference = np.linspace(0, 10, 1001)
    q = methods.quantiles(reference)
    assert methods.threshold_from(q, 99.0, "isolation_forest") == pytest.approx(9.9)
    assert methods.percentile_of(5.0, q) == pytest.approx(50.0, abs=0.1)
    flat = methods.quantiles(np.zeros(100))
    assert methods.threshold_from(flat, 99.0, "robust_zscore") == methods.ROBUST_Z_MIN_THRESHOLD


def test_isolation_forest_scores_are_higher_for_outliers() -> None:
    rng = np.random.default_rng(0)
    reference = pd.DataFrame({"f1": rng.normal(10, 1, 500), "f2": rng.normal(5, 1, 500)})
    cfg = methods.MethodConfig(
        method="isolation_forest",
        entity_type="host",
        window_size="1h",
        features=["f1", "f2"],
        n_estimators=100,
    )
    pipeline = methods.fit_isolation_forest(reference, cfg)
    scores = methods.isolation_scores(
        pipeline, pd.DataFrame({"f1": [10.0, 18.0], "f2": [5.0, -3.0]}), ["f1", "f2"]
    )
    assert scores[1] > scores[0]
    again = methods.fit_isolation_forest(reference, cfg)
    np.testing.assert_array_equal(
        scores,
        methods.isolation_scores(
            again, pd.DataFrame({"f1": [10.0, 18.0], "f2": [5.0, -3.0]}), ["f1", "f2"]
        ),
    )


def test_proxy_evaluation_is_labelled_as_proxy() -> None:
    scores = np.array([0.1, 0.2, 0.9, 0.95, np.nan])
    malicious = np.array([False, False, True, False, True])
    report = methods.proxy_evaluation(scores, malicious, threshold=0.8)
    assert report["label"].startswith("proxy evaluation")
    assert report["windows"] == 4 and report["flagged"] == 2
    assert report["recall_of_attack_windows"] == 1.0
    assert 0 < report["pr_auc"] <= 1
