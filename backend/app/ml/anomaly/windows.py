"""Entity-window features ``window_v1`` (ANOMALY_DETECTION.md §2-§3). Pure pandas.

Windows are tumbling, aligned to UTC, and exist only where the entity had at least one event
(no fabricated zero windows). Events with ``time_quality = 'assumed'`` must be excluded by the
caller.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any
from zoneinfo import ZoneInfo

import numpy as np
import pandas as pd

FEATURE_SET = "window_v1"
WINDOW_SIZES = {"15m": timedelta(minutes=15), "1h": timedelta(hours=1), "1d": timedelta(days=1)}
ENTITY_TYPES = ("host", "account", "src_ip")
BUSINESS_HOURS = (7, 19)  # 07:00-19:00 in the site timezone

FEATURES: dict[str, list[str]] = {
    "account": [
        "event_count",
        "failed_auth_count",
        "success_auth_count",
        "failed_auth_ratio",
        "distinct_src_ips_for_account",
        "distinct_hosts_for_account",
        "new_src_ip_for_account",
        "off_hours_fraction",
    ],
    "host": [
        "event_count",
        "distinct_dst_ips",
        "distinct_dst_ports",
        "bytes_out_sum",
        "bytes_in_sum",
        "bytes_null_count",
        "mean_duration_s",
        "new_dst_port_count",
        "ids_alert_count",
        "failed_auth_count",
        "success_auth_count",
        "off_hours_fraction",
    ],
    "src_ip": [
        "event_count",
        "distinct_dst_ips",
        "distinct_dst_ports",
        "bytes_out_sum",
        "bytes_in_sum",
        "bytes_null_count",
        "mean_duration_s",
        "new_dst_port_count",
        "ids_alert_count",
        "failed_auth_count",
        "success_auth_count",
        "failed_auth_ratio",
        "off_hours_fraction",
    ],
}


def entity_column(frame: pd.DataFrame, entity_type: str) -> pd.Series:
    if entity_type == "account":
        return frame["user_name_normalized"].where(frame["event_type"] == "auth")
    if entity_type == "src_ip":
        return frame["src_ip"].where(
            frame["event_type"].isin(["network_flow", "ids_alert", "auth"])
        )
    if entity_type == "host":
        return frame["host_name"].str.lower().fillna(frame["src_ip"])
    raise ValueError(f"unknown entity type {entity_type!r}")


def _off_hours(times: pd.Series, site_timezone: str) -> pd.Series:
    local_hour = times.dt.tz_convert(ZoneInfo(site_timezone)).dt.hour
    start, end = BUSINESS_HOURS
    off: pd.Series = ((local_hour < start) | (local_hour >= end)).astype(float)
    return off


def build_windows(
    events: pd.DataFrame, entity_type: str, window: str, site_timezone: str = "UTC"
) -> pd.DataFrame:
    """One row per (entity, window_start) with the ``window_v1`` features for the entity type.

    ``new_*`` features compare with all earlier windows of the same entity present in
    ``events`` (callers load a baseline look-back before the scored period).
    """
    if window not in WINDOW_SIZES:
        raise ValueError(f"window must be one of {sorted(WINDOW_SIZES)}")
    columns = ["entity_value", "window_start", *FEATURES[entity_type]]
    if events.empty:
        return pd.DataFrame(columns=columns)
    frame = events.copy()
    frame["event_time"] = pd.to_datetime(frame["event_time"], utc=True)
    frame["entity_value"] = entity_column(frame, entity_type)
    frame = frame[frame["entity_value"].notna()]
    if frame.empty:
        return pd.DataFrame(columns=columns)
    size = WINDOW_SIZES[window]
    frame["window_start"] = frame["event_time"].dt.floor(pd.Timedelta(size))
    frame["is_auth"] = frame["event_type"] == "auth"
    frame["failed"] = (frame["is_auth"] & (frame["auth_result"] == "failure")).astype(int)
    frame["success"] = (frame["is_auth"] & (frame["auth_result"] == "success")).astype(int)
    frame["ids"] = (frame["event_type"] == "ids_alert").astype(int)
    frame["off_hours"] = _off_hours(frame["event_time"], site_timezone)
    frame["bytes_null"] = (frame["bytes_out"].isna() & frame["bytes_in"].isna()).astype(int)
    for col in ("bytes_out", "bytes_in", "duration_s"):
        frame[col] = pd.to_numeric(frame[col], errors="coerce")

    grouped = frame.groupby(["entity_value", "window_start"], sort=True)
    out = pd.DataFrame(
        {
            "event_count": grouped.size(),
            "failed_auth_count": grouped["failed"].sum(),
            "success_auth_count": grouped["success"].sum(),
            "distinct_dst_ips": grouped["dst_ip"].nunique(),
            "distinct_dst_ports": grouped["dst_port"].nunique(),
            "bytes_out_sum": grouped["bytes_out"].sum(min_count=1),
            "bytes_in_sum": grouped["bytes_in"].sum(min_count=1),
            "bytes_null_count": grouped["bytes_null"].sum(),
            "mean_duration_s": grouped["duration_s"].mean(),
            "ids_alert_count": grouped["ids"].sum(),
            "distinct_src_ips_for_account": grouped["src_ip"].nunique(),
            "distinct_hosts_for_account": grouped["host_name"].nunique(),
            "off_hours_fraction": grouped["off_hours"].mean(),
        }
    ).reset_index()
    attempts = out["failed_auth_count"] + out["success_auth_count"]
    out["failed_auth_ratio"] = out["failed_auth_count"] / attempts.replace(0, np.nan)

    # "new" values: never seen for this entity in any earlier window present in the frame.
    new_ports: dict[tuple[Any, Any], int] = {}
    new_ips: dict[tuple[Any, Any], int] = {}
    for entity, rows in frame.sort_values("event_time").groupby("entity_value", sort=False):
        seen_ports: set[Any] = set()
        seen_ips: set[Any] = set()
        for start, win in rows.groupby("window_start", sort=True):
            ports = set(win["dst_port"].dropna())
            ips = set(win.loc[win["is_auth"], "src_ip"].dropna())
            new_ports[(entity, start)] = len(ports - seen_ports)
            new_ips[(entity, start)] = len(ips - seen_ips)
            seen_ports |= ports
            seen_ips |= ips
    keys = list(zip(out["entity_value"], out["window_start"], strict=True))
    out["new_dst_port_count"] = [new_ports.get(k, 0) for k in keys]
    out["new_src_ip_for_account"] = [new_ips.get(k, 0) for k in keys]
    return out[columns]


def robust_stats(values: pd.DataFrame) -> tuple[pd.Series, pd.Series, pd.Series]:
    """Median, MAD, and mean absolute deviation per column (NaNs ignored)."""
    median = values.median()
    mad = (values - median).abs().median()
    mean_abs = (values - median).abs().mean()
    return median, mad, mean_abs


def robust_z(row: pd.Series, median: pd.Series, mad: pd.Series, mean_abs: pd.Series) -> pd.Series:
    """0.6745 * (x - median) / MAD.

    When MAD is 0 (a baseline with no spread, common for low-volume entities), deviations are
    measured in units of max(mean absolute deviation, 10 % of |median|, 1) so scores stay
    finite and readable instead of exploding.
    """
    z = 0.6745 * (row - median) / mad.where(mad > 0)
    floor_scale = pd.concat([mean_abs, 0.1 * median.abs()], axis=1).max(axis=1).clip(lower=1.0)
    fallback = (row - median) / floor_scale
    return z.where(mad > 0, fallback).fillna(0.0)
