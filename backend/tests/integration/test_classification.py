"""Classification end to end through the API and worker (AC-3.4 - AC-3.7, AC-3.10)."""

from __future__ import annotations

import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings
from app.core.security import Role
from app.devtools.synthetic import write
from app.jobs.registry import HANDLERS
from app.jobs.worker import Worker
from app.models import ClassificationResult, MlModel, MlTrainingRun
from app.services import models as models_service
from tests.conftest import LoggedIn
from tests.integration.ingestion_helpers import ingest

pytestmark = pytest.mark.integration

FAST_CONFIG: dict[str, Any] = {
    "random_seed": 7,
    "min_class_support_train": 5,
    "bootstrap_resamples": 50,
    "models": {"random_forest": {"n_estimators": [30], "max_depth": [0], "min_samples_leaf": [1]}},
}


def _run_worker(factory: sessionmaker[Session]) -> None:
    worker = Worker(factory, get_settings(), HANDLERS)
    while worker.run_once():
        pass


@pytest.fixture
def batch_id(
    session_factory: sessionmaker[Session],
    seeded: Session,
    import_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> str:
    monkeypatch.setattr(get_settings(), "artifact_dir", import_root / "artifacts")
    paths = write(import_root / "syn", seed=42, days=6)
    outcome = ingest(session_factory, paths["events"], "synthetic")
    assert outcome.status == "completed"
    return str(outcome.batch_id)


def _train(
    admin: LoggedIn, factory: sessionmaker[Session], batch: str, **overrides: Any
) -> dict[str, Any]:
    body = {**FAST_CONFIG, "snapshot": {"batch_ids": [batch]}, **overrides}
    resp = admin.client.post(
        "/api/v1/classification/training-runs", json=body, headers=admin.headers()
    )
    assert resp.status_code == 202, resp.text
    _run_worker(factory)
    run = admin.client.get(f"/api/v1/classification/training-runs/{resp.json()['id']}").json()
    return dict(run)


def _model_for(db: Session, run_id: str) -> MlModel:
    with db.begin():
        model = db.scalar(select(MlModel).where(MlModel.training_run_id == uuid.UUID(run_id)))
        assert model is not None
        db.expunge(model)
        return model


def test_train_promote_score_and_query(
    login: Callable[..., LoggedIn],
    session_factory: sessionmaker[Session],
    batch_id: str,
    db: Session,
) -> None:
    admin = login("root", Role.ADMIN)
    run = _train(admin, session_factory, batch_id)
    assert run["status"] == "succeeded", run.get("error")
    snapshot = run["dataset_snapshot"]
    assert len(snapshot["snapshot_hash"]) == 64 and snapshot["rows"] > 0
    assert snapshot["excluded"].get("no_label", 0) == 0
    metrics = run["metrics"]
    assert set(metrics["models"]) == {
        "dummy_most_frequent",
        "dummy_stratified",
        "logistic_regression",
        "random_forest",
    }
    assert metrics["comparison"] == {"skipped": "no active model"}
    assert run["environment"]["scikit_learn"]

    model = _model_for(db, run["run_id"])
    assert model.status == "candidate" and model.version == 1
    detail = admin.client.get(f"/api/v1/models/{model.model_id}").json()
    assert detail["manifest"]["artifact_sha256"] == model.artifact_sha256
    assert detail["promotion_gate"]["eligible"] is True, detail["promotion_gate"]

    promoted = admin.client.post(
        f"/api/v1/models/{model.model_id}/promote", headers=admin.headers()
    )
    assert promoted.status_code == 200 and promoted.json()["status"] == "active"
    again = admin.client.post(f"/api/v1/models/{model.model_id}/promote", headers=admin.headers())
    assert again.status_code == 409

    scoring = admin.client.post(
        "/api/v1/classification/scoring-runs",
        json={"batch_ids": [batch_id]},
        headers=admin.headers(),
    )
    assert scoring.status_code == 202
    _run_worker(session_factory)
    sr = admin.client.get(f"/api/v1/classification/scoring-runs/{scoring.json()['id']}").json()
    assert sr["status"] == "succeeded" and sr["rows_scored"] > 0
    assert sr["rows_skipped"]["incompatible_event_type"] > 0  # auth/dns/ids events are skipped
    with db.begin():
        stored = db.scalar(select(func.count()).select_from(ClassificationResult))
    assert stored == sr["rows_scored"]

    # re-scoring the same scope inserts nothing new (idempotent)
    admin.client.post(
        "/api/v1/classification/scoring-runs",
        json={"batch_ids": [batch_id]},
        headers=admin.headers(),
    )
    _run_worker(session_factory)
    with db.begin():
        assert db.scalar(select(func.count()).select_from(ClassificationResult)) == stored

    results = admin.client.get(
        "/api/v1/classification/results", params={"predicted_category": "reconnaissance"}
    ).json()
    assert results["items"] and all(r["score_is_calibrated"] is False for r in results["items"])
    summary = admin.client.get("/api/v1/classification/summary").json()
    assert summary["scored_scope_confusion_matrix"]["note"].startswith("ground truth vs.")

    rng = {"from": "2026-01-01T00:00:00Z", "to": "2026-01-08T00:00:00Z"}
    recon = admin.client.get(
        "/api/v1/events", params={**rng, "predicted_category": "RECONNAISSANCE"}
    )
    assert recon.status_code == 200 and recon.json()["items"]
    assert all(e["predicted_category"] == "RECONNAISSANCE" for e in recon.json()["items"])
    event_id = recon.json()["items"][0]["event_id"]
    event = admin.client.get(f"/api/v1/events/{event_id}").json()
    cls = event["model_outputs"]["classifications"]
    assert cls[0]["model"]["status"] == "active" and cls[0]["score_is_calibrated"] is False
    dist = admin.client.get(
        "/api/v1/analytics/distribution", params={**rng, "dimension": "predicted_category"}
    ).json()
    assert {i["value"] for i in dist["items"]} >= {"RECONNAISSANCE", "(not scored)"}

    # a second run compares itself with the active model on its own test split
    second = _train(admin, session_factory, batch_id)
    assert second["metrics"]["comparison"]["evaluated_on"] == "candidate test split"
    assert _model_for(db, second["run_id"]).version == 2


def test_prediction_filters_need_an_active_model(
    login: Callable[..., LoggedIn], batch_id: str
) -> None:
    viewer = login("vic")
    resp = viewer.client.get(
        "/api/v1/events",
        params={
            "from": "2026-01-01T00:00:00Z",
            "to": "2026-01-08T00:00:00Z",
            "predicted_category": "DOS",
        },
    )
    assert resp.status_code == 422


def test_invalid_training_configs_are_rejected(
    login: Callable[..., LoggedIn], seeded: Session
) -> None:
    admin = login("root", Role.ADMIN)
    for body in (
        {"snapshot": {"batch_ids": []}},
        {"snapshot": {"batch_ids": [str(uuid.uuid4())]}, "feature_set": "nope"},
        {"snapshot": {"batch_ids": [str(uuid.uuid4())]}, "split_strategy": "random"},
        {"snapshot": {"batch_ids": [str(uuid.uuid4())]}, "unknown_key": 1},
        {"snapshot": {"batch_ids": [str(uuid.uuid4())]}, "include_feedback_labels": True},
    ):
        resp = admin.client.post(
            "/api/v1/classification/training-runs", json=body, headers=admin.headers()
        )
        assert resp.status_code == 422, body
    analyst = login("ana", Role.ANALYST)
    resp = analyst.client.post(
        "/api/v1/classification/training-runs",
        json={"snapshot": {"batch_ids": [str(uuid.uuid4())]}},
        headers=analyst.headers(),
    )
    assert resp.status_code == 403


def test_training_on_empty_snapshot_fails_the_run(
    login: Callable[..., LoggedIn],
    session_factory: sessionmaker[Session],
    seeded: Session,
    db: Session,
) -> None:
    admin = login("root", Role.ADMIN)
    run = _train(admin, session_factory, str(uuid.uuid4()))
    assert run["status"] == "failed"
    assert "no labelled events" in run["error"]["message"]


def test_promotion_gate_rules(
    login: Callable[..., LoggedIn],
    session_factory: sessionmaker[Session],
    batch_id: str,
    db: Session,
) -> None:
    admin = login("root", Role.ADMIN)
    run = _train(admin, session_factory, batch_id)
    model = _model_for(db, run["run_id"])
    with db.begin():
        stored = db.get(MlTrainingRun, uuid.UUID(run["run_id"]))
        assert stored is not None
        stored_model = db.get(MlModel, model.model_id)
        assert stored_model is not None
        assert models_service.gate_problems(stored_model, stored, False) == []
        stored.leakage_checks = {"failures": [], "warnings": ["possible shortcut feature: x"]}
        problems = models_service.gate_problems(stored_model, stored, False)
        assert problems == ["leakage warnings must be acknowledged with a note first"]
        metrics = dict(stored.metrics or {})
        models = dict(metrics["models"])
        models["dummy_stratified"] = {"test": {"macro_f1": 1.0}}
        stored.metrics = {**metrics, "models": models}
        assert any(
            "does not beat" in p for p in models_service.gate_problems(stored_model, stored, False)
        )
    blocked = admin.client.post(f"/api/v1/models/{model.model_id}/promote", headers=admin.headers())
    assert blocked.status_code == 409 and blocked.json()["gate_problems"]
    ack = admin.client.post(
        f"/api/v1/classification/training-runs/{run['run_id']}/acknowledge-warnings",
        json={"note": "reviewed: synthetic data artefact"},
        headers=admin.headers(),
    )
    assert ack.status_code == 200
    rejected = admin.client.post(
        f"/api/v1/models/{model.model_id}/reject",
        json={"reason": "fails baseline"},
        headers=admin.headers(),
    )
    assert rejected.json()["status"] == "rejected"


def test_tampered_artifact_fails_scoring(
    login: Callable[..., LoggedIn],
    session_factory: sessionmaker[Session],
    batch_id: str,
    db: Session,
) -> None:
    admin = login("root", Role.ADMIN)
    run = _train(admin, session_factory, batch_id)
    model = _model_for(db, run["run_id"])
    admin.client.post(f"/api/v1/models/{model.model_id}/promote", headers=admin.headers())
    Path(model.artifact_path).write_bytes(b"not a model")
    resp = admin.client.post(
        "/api/v1/classification/scoring-runs",
        json={"batch_ids": [batch_id]},
        headers=admin.headers(),
    )
    _run_worker(session_factory)
    sr = admin.client.get(f"/api/v1/classification/scoring-runs/{resp.json()['id']}").json()
    assert sr["status"] == "failed" and sr["error"]["code"] == "ARTIFACT_INTEGRITY_FAILED"
