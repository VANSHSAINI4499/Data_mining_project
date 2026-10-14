"""Versioned feature sets (ML_CLASSIFICATION.md §4). Pure functions over pandas DataFrames.

The event frame has canonical columns (``duration_s``, ``bytes_out``, ...) plus an
``attributes`` column of dicts. Identifiers, times, IPs, and labels are never features: the
denylist below makes training fail if one sneaks in.
"""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from app.core.config import REPO_ROOT

FEATURE_SET_DIR = REPO_ROOT / "config" / "feature_sets"

DENYLIST_EXACT = frozenset(
    {
        "event_id",
        "raw_record_id",
        "record_number",
        "batch_id",
        "source_id",
        "source_event_id",
        "event_fingerprint",
        "src_ip",
        "dst_ip",
        "src_port",
        "event_time",
        "event_end_time",
        "date_key",
        "event_hour",
        "ingested_at",
        "label_raw",
        "is_attack",
        "attack_category",
        "label",
        "attack_cat",
        "id",
        "flow_id",
        "timestamp",
    }
)
DENYLIST_PATTERN = re.compile(
    r"(^|_)(label|attack_cat|timestamp|flow_id|src_ip|dst_ip|source_ip|destination_ip)($|_)"
)
MIN_DURATION_S = 0.001


class FeatureError(Exception):
    """A feature set cannot be built from the given data (training fails with this message)."""


@dataclass(frozen=True)
class FeatureSet:
    name: str
    version: int
    event_types: tuple[str, ...]
    numeric: tuple[str, ...]
    derived: tuple[str, ...]
    categorical: tuple[str, ...]
    attributes: tuple[str, ...]
    include_raw_dst_port: bool = False
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def tag(self) -> str:
        return f"{self.name}@{self.version}"

    @property
    def numeric_columns(self) -> list[str]:
        cols = [*self.numeric, *self.derived, *(f"attr_{a}" for a in self.attributes)]
        if self.include_raw_dst_port:
            cols.append("dst_port")
        return cols

    @property
    def categorical_columns(self) -> list[str]:
        return list(self.categorical)


def denylisted(names: list[str]) -> list[str]:
    bad = []
    for name in names:
        bare = name.removeprefix("attr_")
        if name == "dst_port":
            continue  # allowed only when explicitly enabled (include_raw_dst_port)
        if bare in DENYLIST_EXACT or DENYLIST_PATTERN.search(bare):
            bad.append(name)
    return bad


@lru_cache
def _load_raw(name: str, directory: Path = FEATURE_SET_DIR) -> dict[str, Any]:
    path = directory / f"{name}.toml"
    if not path.is_file():
        raise FeatureError(f"unknown feature set {name!r}")
    with path.open("rb") as fh:
        return tomllib.load(fh)


def load_feature_set(name: str, include_raw_dst_port: bool = False) -> FeatureSet:
    data = dict(_load_raw(name))
    if "extends" in data:
        base = _load_raw(data["extends"])
        for key in ("numeric", "derived", "categorical"):
            data.setdefault(key, base.get(key, []))
        data["attributes"] = [*base.get("attributes", []), *data.get("attributes", [])]
    fs = FeatureSet(
        name=data["name"],
        version=int(data["version"]),
        event_types=tuple(data.get("event_types", ["network_flow"])),
        numeric=tuple(data.get("numeric", [])),
        derived=tuple(data.get("derived", [])),
        categorical=tuple(data.get("categorical", [])),
        attributes=tuple(data.get("attributes", [])),
        include_raw_dst_port=include_raw_dst_port,
    )
    bad = denylisted([*fs.numeric_columns, *fs.categorical_columns])
    if bad:
        raise FeatureError(f"feature set {fs.tag} contains denylisted features: {bad}")
    return fs


def _num(frame: pd.DataFrame, column: str) -> pd.Series:
    if column not in frame:
        return pd.Series(np.nan, index=frame.index, dtype="float64")
    return pd.to_numeric(frame[column], errors="coerce").astype("float64")


def _protocol_bucket(value: Any) -> str:
    if isinstance(value, str) and value in ("tcp", "udp", "icmp"):
        return value
    return "other" if isinstance(value, str) and value else "missing"


def _port_class(value: Any) -> str:
    if value is None or (isinstance(value, float) and np.isnan(value)):
        return "none"
    port = int(value)
    if port < 1024:
        return "well_known"
    if port < 49152:
        return "registered"
    return "dynamic"


def build_features(
    frame: pd.DataFrame, fs: FeatureSet, *, require_attributes: bool
) -> pd.DataFrame:
    """Return a feature matrix (index aligned with ``frame``) for ``fs``.

    ``require_attributes``: when training, an allow-listed attribute absent from *every* row is
    an error (the feature set does not fit this data); at inference it is simply NaN.
    """
    out = pd.DataFrame(index=frame.index)
    for col in fs.numeric:
        out[col] = _num(frame, col)
    if fs.derived:
        bo, bi = _num(frame, "bytes_out"), _num(frame, "bytes_in")
        po, pi = _num(frame, "packets_out"), _num(frame, "packets_in")
        duration = _num(frame, "duration_s").clip(lower=MIN_DURATION_S)
        derived = {
            "total_bytes": bo + bi,
            "total_packets": po + pi,
            "bytes_per_packet_out": bo / po.replace(0, np.nan),
            "bytes_per_packet_in": bi / pi.replace(0, np.nan),
            "out_in_byte_ratio": (bo + 1) / (bi + 1),
            "packets_per_second": (po + pi) / duration,
            "bytes_per_second": (bo + bi) / duration,
        }
        for name in fs.derived:
            if name not in derived:
                raise FeatureError(f"unknown derived feature {name!r}")
            out[name] = derived[name]
    if fs.attributes:
        attrs = frame["attributes"] if "attributes" in frame else pd.Series([{}] * len(frame))
        missing_everywhere = []
        for name in fs.attributes:
            values = attrs.map(lambda a, n=name: a.get(n) if isinstance(a, dict) else None)
            series = pd.to_numeric(values, errors="coerce").astype("float64")
            if require_attributes and series.isna().all():
                missing_everywhere.append(name)
            out[f"attr_{name}"] = series
        if missing_everywhere:
            raise FeatureError(
                f"feature set {fs.tag}: attributes missing from every row: {missing_everywhere}"
            )
    if fs.include_raw_dst_port:
        out["dst_port"] = _num(frame, "dst_port")
    if "protocol" in fs.categorical:
        out["protocol"] = frame.get("protocol", pd.Series(None, index=frame.index)).map(
            _protocol_bucket
        )
    if "dst_port_class" in fs.categorical:
        ports = _num(frame, "dst_port")
        out["dst_port_class"] = ports.map(_port_class)
    out = out.replace([np.inf, -np.inf], np.nan)
    return out[[*fs.numeric_columns, *fs.categorical_columns]]


def feature_hash(features: pd.DataFrame) -> pd.Series:
    """Group key for exact and rounding-level duplicates (6 significant digits)."""
    rounded = features.copy()
    for col in rounded.columns:
        if pd.api.types.is_float_dtype(rounded[col]):
            rounded[col] = rounded[col].map(lambda v: None if pd.isna(v) else float(f"{v:.6g}"))
    return pd.util.hash_pandas_object(rounded.astype("object"), index=False).astype("uint64")


def missing_fraction(features: pd.DataFrame) -> pd.Series:
    return features.isna().mean(axis=1)
