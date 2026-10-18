"""Background scoring of stored HTTP query parameters with the web payload model."""

from __future__ import annotations

import shutil
import uuid
from collections.abc import Callable
from pathlib import Path

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings
from app.core.security import Role
from app.jobs.registry import HANDLERS
from app.jobs.worker import Worker
from app.models import FactSecurityEvent, MlModel, WebPayloadResult
from app.services import models as models_service
from app.services import web_payload
from app.services.actors import CLI_ACTOR
from tests.conftest import LoggedIn
from tests.integration.ingestion_helpers import ingest
from tests.integration.test_web_access_adapter import SAMPLE
from tests.unit.test_web_payload import synthetic_rows, write_csv

pytestmark = pytest.mark.integration

SCOPE = {"from": "2026-10-01T00:00:00+00:00", "to": "2026-11-01T00:00:00+00:00"}


@pytest.fixture
def trained(
    session_factory: sessionmaker[Session],
    seeded: Session,
    import_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> uuid.UUID:
    monkeypatch.setattr(get_settings(), "artifact_dir", import_root / "artifacts")
    folder = import_root / "external" / "httpparams"
    folder.mkdir(parents=True)
    write_csv(folder / "payload_full.csv", synthetic_rows())
    result = web_payload.train_from_directory(
        session_factory, get_settings(), CLI_ACTOR, folder, seed=5
    )
    return uuid.UUID(result["model_id"])


@pytest.fixture
def access_log(session_factory: sessionmaker[Session], seeded: Session, import_root: Path) -> None:
    path = import_root / "access.log"
    shutil.copyfile(SAMPLE, path)
    assert ingest(session_factory, path, "web-server").records_loaded == 11


def _run_worker(factory: sessionmaker[Session]) -> None:
    worker = Worker(factory, get_settings(), HANDLERS)
    while worker.run_once():
        pass


def test_score_stored_query_params_via_api_and_worker(
    login: Callable[..., LoggedIn],
    db: Session,
    session_factory: sessionmaker[Session],
    trained: uuid.UUID,
    access_log: None,
) -> None:
    with session_factory() as session:
        models_service.promote(session, CLI_ACTOR, trained)

    viewer = login("val", Role.VIEWER)
    denied = viewer.client.post(
        "/api/v1/web-payloads/scoring-runs", json=SCOPE, headers=viewer.headers()
    )
    assert denied.status_code == 403

    analyst = login("ana", Role.ANALYST)
    no_scope = analyst.client.post(
        "/api/v1/web-payloads/scoring-runs", json={}, headers=analyst.headers()
    )
    assert no_scope.status_code == 422
    resp = analyst.client.post(
        "/api/v1/web-payloads/scoring-runs", json=SCOPE, headers=analyst.headers()
    )
    assert resp.status_code == 202, resp.text
    run_id = resp.json()["id"]
    assert resp.json()["links"]["scoring-run"].endswith(f"/web-payloads/scoring-runs/{run_id}")
    _run_worker(session_factory)

    run = viewer.client.get(f"/api/v1/web-payloads/scoring-runs/{run_id}").json()
    assert run["status"] == "succeeded" and run["evaluation_only"] is False
    # Sample log: 11 HTTP events, 5 with a query string carrying 7 non-empty values.
    assert run["rows_scored"] == 7
    assert run["rows_skipped"]["http_events_in_scope"] == 11
    assert run["rows_skipped"]["no_query_params"] == 6
    assert run["rows_skipped"]["malformed_query_params"] == 0

    with db.begin():
        stored = list(db.scalars(select(WebPayloadResult).order_by(WebPayloadResult.result_id)))
        events = int(db.scalar(select(func.count()).select_from(FactSecurityEvent)) or 0)
    assert len(stored) == 7 and events == 11  # predictions never add or change events
    assert {r.param_name for r in stored} == {"category", "page", "q", "sort", "file", "host"}
    assert all(r.score_kind and set(r.class_scores) >= {"BENIGN", "SQLI"} for r in stored)

    results = viewer.client.get("/api/v1/web-payloads/results").json()
    assert results["model"]["model_id"] == str(trained)
    assert len(results["items"]) == 7 and "not probabilities" in results["note"]
    traversal = next(i for i in results["items"] if i["param_name"] == "file")
    # The value shown comes from the stored event, not a copy in the result row.
    assert traversal["param_value"] == "../../../etc/passwd"
    assert traversal["url"].startswith("/download") and traversal["score_is_calibrated"] is False

    page = viewer.client.get("/api/v1/web-payloads/results?limit=3").json()
    assert len(page["items"]) == 3 and page["next_cursor"]
    rest = viewer.client.get(
        f"/api/v1/web-payloads/results?limit=10&cursor={page['next_cursor']}"
    ).json()
    assert len(rest["items"]) == 4
    attack_only = viewer.client.get("/api/v1/web-payloads/results?attack_like_only=true").json()
    assert all(i["is_attack_like"] for i in attack_only["items"])
    assert viewer.client.get("/api/v1/web-payloads/results?bogus=1").status_code == 422

    summary = viewer.client.get("/api/v1/web-payloads/summary").json()
    assert sum(c["parameters"] for c in summary["predictions_by_class"]) == 7

    event_id = traversal["event_id"]
    detail = viewer.client.get(f"/api/v1/events/{event_id}").json()
    outputs = detail["model_outputs"]["web_payload_classifications"]
    assert [(o["param_name"], o["param_index"]) for o in outputs] == [("file", 0)]
    assert outputs[0]["model"]["name"] == "web_attack_classifier"

    # Re-scoring the same scope stores nothing new (idempotent).
    again = web_payload.start_scoring(db, CLI_ACTOR, SCOPE, None, enqueue=False)
    done = web_payload.run_scoring(session_factory, get_settings(), again.scoring_run_id)
    assert done.rows_scored == 0 and done.rows_skipped["http_events_in_scope"] == 11
    with db.begin():
        assert db.scalar(select(func.count()).select_from(WebPayloadResult)) == 7


def test_candidate_model_scoring_is_evaluation_only(
    db: Session, session_factory: sessionmaker[Session], trained: uuid.UUID, access_log: None
) -> None:
    run = web_payload.start_scoring(db, CLI_ACTOR, SCOPE, trained, enqueue=False)
    assert run.evaluation_only is True
    done = web_payload.run_scoring(session_factory, get_settings(), run.scoring_run_id)
    assert done.status == "succeeded" and done.rows_scored == 7


def test_scoring_requires_a_web_payload_model(
    db: Session, seeded: Session, trained: uuid.UUID
) -> None:
    with pytest.raises(Exception, match="no active model"):
        web_payload.start_scoring(db, CLI_ACTOR, SCOPE, None, enqueue=False)
    with db.begin():
        model = db.get(MlModel, trained)
        assert model is not None
        model.task = "classification"  # simulate a network-flow model id being passed
    with pytest.raises(Exception, match="not a web payload"):
        web_payload.start_scoring(db, CLI_ACTOR, SCOPE, trained, enqueue=False)


def test_unknown_scoring_run_is_404(login: Callable[..., LoggedIn], seeded: Session) -> None:
    viewer = login("val", Role.VIEWER)
    resp = viewer.client.get(f"/api/v1/web-payloads/scoring-runs/{uuid.uuid4()}")
    assert resp.status_code == 404
    assert viewer.client.get("/api/v1/web-payloads/results").status_code == 404
