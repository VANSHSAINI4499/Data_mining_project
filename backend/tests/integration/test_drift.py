"""Drift reports through the API and worker (AC-8.2)."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings
from app.core.security import Role
from app.devtools.synthetic import write
from app.jobs.registry import HANDLERS
from app.jobs.worker import Worker
from tests.conftest import LoggedIn
from tests.integration.ingestion_helpers import ingest

pytestmark = pytest.mark.integration

CONFIG: dict[str, Any] = {
    "name": "src_ip_drift_test",
    "method": "robust_zscore",
    "entity_type": "src_ip",
    "window_size": "1h",
    "reference_start": "2026-01-01T00:00:00Z",
    "reference_end": "2026-01-08T00:00:00Z",
    "min_baseline_windows": 10,
}


def _work(factory: sessionmaker[Session]) -> None:
    worker = Worker(factory, get_settings(), HANDLERS)
    while worker.run_once():
        pass


def test_drift_reports_are_informational(
    login: Callable[..., LoggedIn],
    session_factory: sessionmaker[Session],
    seeded: Session,
    import_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(get_settings(), "artifact_dir", import_root / "artifacts")
    paths = write(import_root / "syn", seed=42, days=10)
    assert ingest(session_factory, paths["events"], "synthetic").status == "completed"
    admin = login("root", Role.ADMIN)
    h = admin.headers()
    resp = admin.client.post("/api/v1/anomalies/training-runs", json=CONFIG, headers=h)
    assert resp.status_code == 202, resp.text
    _work(session_factory)
    model = admin.client.get("/api/v1/models", params={"name": CONFIG["name"]}).json()[0]
    assert model["latest_drift"] is None
    model_id = model["model_id"]

    resp = admin.client.post(
        f"/api/v1/models/{model_id}/drift-reports",
        json={"from": "2026-01-08T00:00:00Z", "to": "2026-01-11T00:00:00Z"},
        headers=h,
    )
    assert resp.status_code == 202, resp.text
    tiny = admin.client.post(
        f"/api/v1/models/{model_id}/drift-reports",
        json={"from": "2026-01-10T00:00:00Z", "to": "2026-01-10T02:00:00Z"},
        headers=h,
    )
    assert tiny.status_code == 202
    _work(session_factory)

    reports = admin.client.get(f"/api/v1/models/{model_id}/drift-reports").json()
    assert len(reports) == 2
    by_period = {r["period_end"][:13]: r for r in reports}
    full = by_period["2026-01-11T00"]
    assert full["status"] in ("ok", "warning")
    assert set(full["metrics"]["feature_psi"]) >= {"event_count", "distinct_dst_ports"}
    assert full["metrics"]["reference_period"]["from"].startswith("2026-01-01")
    assert all(w for w in full["warnings"])
    assert "never retrains" in full["note"]
    assert by_period["2026-01-10T02"]["status"] == "insufficient_data"

    # The model itself is unchanged: still a candidate with the same threshold.
    detail = admin.client.get(f"/api/v1/models/{model_id}").json()
    assert detail["status"] == "candidate"
    assert detail["threshold"] == model["threshold"]
    assert detail["latest_drift"]["status"] == "insufficient_data"

    bad = admin.client.post(
        f"/api/v1/models/{model_id}/drift-reports",
        json={"from": "2026-01-11T00:00:00Z", "to": "2026-01-10T00:00:00Z"},
        headers=h,
    )
    assert bad.status_code == 422
