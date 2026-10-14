"""Anomaly mining through the API and worker (AC-4.2 - AC-4.6)."""

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

BASE_CONFIG: dict[str, Any] = {
    "entity_type": "account",
    "window_size": "1h",
    "reference_start": "2026-01-01T00:00:00Z",
    "reference_end": "2026-01-09T00:00:00Z",
    "min_baseline_windows": 10,
    "iforest": {"n_estimators": 100},
}
SCORE = {"from": "2026-01-09T00:00:00Z", "to": "2026-01-11T00:00:00Z"}
PLANTED = ("mallory", "2026-01-10T03:00:00Z")


def _run_worker(factory: sessionmaker[Session]) -> None:
    worker = Worker(factory, get_settings(), HANDLERS)
    while worker.run_once():
        pass


@pytest.fixture
def loaded(
    session_factory: sessionmaker[Session],
    seeded: Session,
    import_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(get_settings(), "artifact_dir", import_root / "artifacts")
    paths = write(import_root / "syn", seed=42, days=10)
    assert ingest(session_factory, paths["events"], "synthetic").status == "completed"


def _train_promote_score(
    admin: LoggedIn, factory: sessionmaker[Session], name: str, method: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    body = {**BASE_CONFIG, "name": name, "method": method}
    resp = admin.client.post("/api/v1/anomalies/training-runs", json=body, headers=admin.headers())
    assert resp.status_code == 202, resp.text
    _run_worker(factory)
    run = admin.client.get(f"/api/v1/anomalies/training-runs/{resp.json()['id']}").json()
    assert run["status"] == "succeeded", run["error"]
    models = admin.client.get("/api/v1/models", params={"name": name}).json()
    promoted = admin.client.post(
        f"/api/v1/models/{models[0]['model_id']}/promote", headers=admin.headers()
    )
    assert promoted.status_code == 200, promoted.text
    scoring = admin.client.post(
        "/api/v1/anomalies/scoring-runs", json={**SCORE, "name": name}, headers=admin.headers()
    )
    assert scoring.status_code == 202
    _run_worker(factory)
    flagged = admin.client.get(
        "/api/v1/anomalies", params={"model_id": models[0]["model_id"], "is_flagged": "true"}
    ).json()
    return run, flagged


def _is_planted(item: dict[str, Any]) -> bool:
    return (item["entity_value"], item["window_start"].replace("+00:00", "Z")) == PLANTED


def test_robust_zscore_flags_the_planted_anomaly(
    login: Callable[..., LoggedIn], session_factory: sessionmaker[Session], loaded: None
) -> None:
    admin = login("root", Role.ADMIN)
    run, flagged = _train_promote_score(admin, session_factory, "acct_robustz", "robust_zscore")
    assert run["metrics"]["threshold"]["value"] >= 3.0
    assert run["metrics"]["proxy_evaluation"]
    assert flagged["interpretation"].startswith("Unusual behaviour is not necessarily malicious")
    planted = [i for i in flagged["items"] if _is_planted(i)]
    assert planted, flagged["items"]
    assert all(i["score_is_probability"] is False for i in flagged["items"])

    detail = admin.client.get(f"/api/v1/anomalies/{planted[0]['result_id']}").json()
    assert detail["feature_snapshot"]["event_count"] == 40
    assert detail["top_deviations"][0]["against"] == "entity history"
    assert detail["baseline"]["windows"] >= 10
    assert detail["history"]  # earlier windows of the same entity
    assert detail["seasonal_comparison"] == "insufficient_history_for_seasonal_comparison"
    assert detail["linked_events"]["params"]["user_name"] == "mallory"
    events = admin.client.get(
        detail["linked_events"]["endpoint"], params=detail["linked_events"]["params"]
    ).json()
    assert len(events["items"]) == 40


def test_isolation_forest_trains_and_reports_its_limits(
    login: Callable[..., LoggedIn], session_factory: sessionmaker[Session], loaded: None
) -> None:
    admin = login("root", Role.ADMIN)
    run, _flagged = _train_promote_score(admin, session_factory, "acct_iforest", "isolation_forest")
    warnings = run["metrics"]["warnings"]
    assert any("Isolation Forest results are unreliable" in w for w in warnings)
    assert run["metrics"]["reference"]["windows"] < 256


def test_invalid_anomaly_configs(login: Callable[..., LoggedIn], seeded: Session) -> None:
    admin = login("root", Role.ADMIN)
    bad = [
        {**BASE_CONFIG, "name": "x1", "method": "magic"},
        {**BASE_CONFIG, "name": "x1", "method": "robust_zscore", "entity_type": "planet"},
        {
            **BASE_CONFIG,
            "name": "x1",
            "method": "robust_zscore",
            "reference_end": "2025-01-01T00:00:00Z",
        },
        {**BASE_CONFIG, "name": "x1", "method": "robust_zscore", "threshold_percentile": 50},
        {
            **BASE_CONFIG,
            "name": "x1",
            "method": "robust_zscore",
            "reference_start": "2026-01-01T00:00:00",
        },
    ]
    for body in bad:
        assert (
            admin.client.post(
                "/api/v1/anomalies/training-runs", json=body, headers=admin.headers()
            ).status_code
            == 422
        ), body


def test_too_short_reference_blocks_promotion(
    login: Callable[..., LoggedIn], session_factory: sessionmaker[Session], loaded: None
) -> None:
    admin = login("root", Role.ADMIN)
    body = {
        **BASE_CONFIG,
        "name": "short_ref",
        "method": "robust_zscore",
        "reference_start": "2026-01-01T00:00:00Z",
        "reference_end": "2026-01-04T00:00:00Z",
        "min_baseline_windows": 3,
    }
    admin.client.post("/api/v1/anomalies/training-runs", json=body, headers=admin.headers())
    _run_worker(session_factory)
    models = admin.client.get("/api/v1/models", params={"name": "short_ref"}).json()
    resp = admin.client.post(
        f"/api/v1/models/{models[0]['model_id']}/promote", headers=admin.headers()
    )
    assert resp.status_code == 409
    assert "reference period is shorter" in " ".join(resp.json()["gate_problems"])
