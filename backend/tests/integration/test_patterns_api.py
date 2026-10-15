"""Pattern mining through the API and worker on the synthetic scenario (AC-8.3)."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

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


def test_mining_recovers_planted_bruteforce(
    login: Callable[..., LoggedIn],
    session_factory: sessionmaker[Session],
    seeded: Session,
    import_root: Path,
) -> None:
    paths = write(import_root / "syn", seed=42, days=10)
    assert ingest(session_factory, paths["events"], "synthetic").status == "completed"
    analyst = login("ana", Role.ANALYST)
    resp = analyst.client.post(
        "/api/v1/correlation/pattern-runs",
        json={
            "entity_type": "account",
            "from": "2026-01-01T00:00:00Z",
            "to": "2026-01-11T00:00:00Z",
            "min_support": 1,
        },
        headers=analyst.headers(),
    )
    assert resp.status_code == 202, resp.text
    worker = Worker(session_factory, get_settings(), HANDLERS)
    while worker.run_once():
        pass
    runs = analyst.client.get("/api/v1/correlation/pattern-runs").json()
    assert len(runs) == 1 and runs[0]["candidates"] >= 1
    run = analyst.client.get(f"/api/v1/correlation/pattern-runs/{runs[0]['run_id']}").json()
    top = run["candidates"][0]
    assert top["pattern"] == ["auth:failure", "auth:success"]
    assert top["example_entities"] == ["svc-backup"]
    assert top["draft_rule"]["steps"][0]["min_count"] == 25  # planted failures
    assert top["draft_rule"]["enabled"] is False
    assert "never enabled automatically" in top["status"]

    # Nothing was added to the rule set; an admin can create the draft explicitly.
    rules = analyst.client.get("/api/v1/correlation/rules").json()
    assert all(r["rule_key"] != "mined_bruteforce" for r in rules)
    admin = login("root", Role.ADMIN)
    created = admin.client.post(
        "/api/v1/correlation/rules",
        json={
            "key": "mined_bruteforce",
            "name": "Mined brute force",
            "description": "candidate from pattern mining",
            **top["draft_rule"],
        },
        headers=admin.headers(),
    )
    assert created.status_code == 201, created.text
    assert created.json()["enabled"] is False

    bad = admin.client.post(
        "/api/v1/correlation/pattern-runs",
        json={
            "entity_type": "account",
            "from": "2026-01-11T00:00:00Z",
            "to": "2026-01-01T00:00:00Z",
        },
        headers=admin.headers(),
    )
    assert bad.status_code == 422
