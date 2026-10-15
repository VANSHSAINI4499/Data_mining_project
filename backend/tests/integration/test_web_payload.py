"""Web payload classifier through the registry, CLI, and API; network-flow model isolation."""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings
from app.core.security import Role
from app.models import MlModel, MlTrainingRun
from app.services import classification, web_payload
from app.services.actors import CLI_ACTOR
from tests.conftest import LoggedIn
from tests.unit.test_web_payload import synthetic_rows, write_csv

pytestmark = pytest.mark.integration


@pytest.fixture
def dataset_dir(import_root: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(get_settings(), "artifact_dir", import_root / "artifacts")
    folder = import_root / "external" / "httpparams"
    folder.mkdir(parents=True)
    write_csv(folder / "payload_full.csv", synthetic_rows())
    write_csv(
        folder / "payload_test_lexical.csv",
        [("a normal sentence about servers", "norm"), ("select a from b", "sqli")],
    )
    return folder


def test_train_register_promote_and_classify(
    login: Callable[..., LoggedIn],
    db: Session,
    session_factory: sessionmaker[Session],
    seeded: Session,
    dataset_dir: Path,
) -> None:
    result = web_payload.train_from_directory(
        session_factory, get_settings(), CLI_ACTOR, dataset_dir, seed=5
    )
    report = result["report"]
    assert report["task"] == "web_payload_classification"
    assert set(report["timings_seconds"]) >= {
        "preprocessing",
        "training",
        "validation",
        "evaluation",
        "total_including_save",
    }
    assert report["latency"]["batch_size"] > 0 and report["model_size_bytes"] > 0
    assert report["lexical_out_of_distribution"]["rows"] == 2
    with db.begin():
        model = db.scalar(select(MlModel).where(MlModel.model_id == result["model_id"]))
        assert model is not None
        assert (model.name, model.task, model.status) == (
            "web_attack_classifier",
            "web_payload_classification",
            "candidate",
        )
        run = db.get(MlTrainingRun, model.training_run_id)
        assert run is not None and run.dataset_snapshot["rows"] == 420

    admin = login("root", Role.ADMIN)
    detail = admin.client.get(f"/api/v1/models/{result['model_id']}").json()
    assert detail["promotion_gate"] == {"eligible": True, "problems": []}
    assert detail["metrics_summary"]["input"] == "single HTTP parameter value (text)"
    assert (
        admin.client.post(
            f"/api/v1/models/{result['model_id']}/promote", headers=admin.headers()
        ).status_code
        == 200
    )

    analyst = login("ana", Role.ANALYST)
    resp = analyst.client.post(
        "/api/v1/web-payloads/classify",
        json={"payloads": ["calle mayor 5", "3' or 3=3 -- sol", ""]},
        headers=analyst.headers(),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert [r["predicted_class"] for r in body["results"][:2]] == ["BENIGN", "SQLI"]
    assert body["results"][2]["empty_input"] is True
    assert body["model"]["name"] == "web_attack_classifier"
    assert "individual HTTP parameter values" in body["note"]

    too_many = analyst.client.post(
        "/api/v1/web-payloads/classify", json={"payloads": ["x"] * 101}, headers=analyst.headers()
    )
    assert too_many.status_code == 422
    empty = analyst.client.post(
        "/api/v1/web-payloads/classify", json={"payloads": []}, headers=analyst.headers()
    )
    assert empty.status_code == 422
    viewer = login("val", Role.VIEWER)
    denied = viewer.client.post(
        "/api/v1/web-payloads/classify", json={"payloads": ["x"]}, headers=viewer.headers()
    )
    assert denied.status_code == 403

    # The web model is never usable for network-flow scoring or drift checks.
    with pytest.raises(Exception, match="classif"):
        classification.start_scoring(
            db,
            CLI_ACTOR,
            {"from": "2026-01-01T00:00:00Z", "to": "2026-01-02T00:00:00Z"},
            model.model_id,
            enqueue=False,
        )
    admin = login("root2", Role.ADMIN)
    drift = admin.client.post(
        f"/api/v1/models/{result['model_id']}/drift-reports",
        json={"from": "2026-01-01T00:00:00Z", "to": "2026-01-02T00:00:00Z"},
        headers=admin.headers(),
    )
    assert drift.status_code == 422


def test_classify_without_active_model_is_404(
    login: Callable[..., LoggedIn], seeded: Session
) -> None:
    analyst = login("ana", Role.ANALYST)
    resp = analyst.client.post(
        "/api/v1/web-payloads/classify", json={"payloads": ["x"]}, headers=analyst.headers()
    )
    assert resp.status_code == 404 and "no active model" in resp.json()["detail"]


def test_dataset_outside_import_root_is_rejected(
    session_factory: sessionmaker[Session],
    import_root: Path,
    tmp_path_factory: pytest.TempPathFactory,
) -> None:
    outside = tmp_path_factory.mktemp("outside")
    write_csv(outside / "payload_full.csv", synthetic_rows(10))
    with pytest.raises(Exception, match="import root"):
        web_payload.train_from_directory(session_factory, get_settings(), CLI_ACTOR, outside)


@pytest.mark.dataset
def test_real_httpparams_dataset(
    session_factory: sessionmaker[Session],
    seeded: Session,
    import_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Runs only with CTI_DATASET_DIR pointing at data/external (pytest -m dataset)."""
    base = os.environ.get("CTI_DATASET_DIR")
    source = Path(base) / "httpparams" if base else None
    if source is None or not (source / "payload_full.csv").is_file():
        pytest.skip("HTTPParamsDataset not present under CTI_DATASET_DIR/httpparams")
    monkeypatch.setattr(get_settings(), "import_root", source.resolve().parent)
    monkeypatch.setattr(get_settings(), "artifact_dir", import_root / "artifacts")
    result = web_payload.train_from_directory(session_factory, get_settings(), CLI_ACTOR, source)
    test = result["report"]["models"][result["report"]["primary_model"]]["test"]
    assert result["snapshot"]["excluded"] == {"declared_length_mismatch": 15}
    assert test["macro_f1"] > 0.9 and test["rows"] > 5000
