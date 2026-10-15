"""PSI helpers (ANOMALY_DETECTION.md §11)."""

from __future__ import annotations

import numpy as np

from app.ml import drift


def test_identical_distributions_have_zero_psi() -> None:
    values = list(np.random.default_rng(1).normal(size=2000))
    assert drift.psi_numeric(values, values) == 0.0
    shares = drift.category_shares(["A", "B", "B"])
    assert drift.psi_categorical(shares, shares) == 0.0


def test_shifted_distribution_exceeds_warning_threshold() -> None:
    rng = np.random.default_rng(2)
    ref = list(rng.normal(0, 1, 5000))
    same = list(rng.normal(0, 1, 5000))
    shifted = list(rng.normal(1.5, 1, 5000))
    assert drift.psi_numeric(ref, same) < 0.1
    assert drift.psi_numeric(ref, shifted) > drift.PSI_WARNING


def test_bins_are_fixed_from_reference_and_handle_constants() -> None:
    assert drift.bin_edges([]) == []
    assert drift.bin_edges([3.0] * 50) == [3.0]
    # All current values above every reference value land in the last bin.
    assert drift.psi_numeric([1.0, 2.0, 3.0, 4.0] * 50, [100.0] * 50) > drift.PSI_WARNING


def test_new_category_counts_as_drift() -> None:
    ref = drift.category_shares(["BENIGN"] * 95 + ["RECONNAISSANCE"] * 5)
    cur = drift.category_shares(["BENIGN"] * 50 + ["DOS"] * 50)
    assert set(cur) == {"BENIGN", "DOS"}
    assert drift.psi_categorical(ref, cur) > drift.PSI_WARNING
