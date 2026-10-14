"""Dashboard overview: empty-state honesty and consistency with direct queries (AC-6.x)."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from pathlib import Path

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from app.core.security import Role
from app.devtools.synthetic import write
from app.models import FactSecurityEvent, IngestionBatch
from app.services import correlation
from app.services.actors import CLI_ACTOR
from tests.conftest import LoggedIn
from tests.integration.ingestion_helpers import ingest

pytestmark = pytest.mark.integration

RANGE = {"from": "2026-01-01T00:00:00Z", "to": "2026-01-11T00:00:00Z"}


def test_overview_is_empty_without_data(login: Callable[..., LoggedIn], seeded: Session) -> None:
    viewer = login("val", Role.VIEWER)
    body = viewer.client.get("/api/v1/dashboard/overview", params=RANGE).json()
    for name in (
        "events",
        "ingestion",
        "models",
        "alerts",
        "anomalies",
        "threat_intel",
        "data_quality",
    ):
        assert body[name]["is_empty"] is True, name
        assert body[name]["as_of"]
    assert body["events"]["total"] == 0 and body["alerts"]["open_total"] == 0


def test_overview_matches_database(
    login: Callable[..., LoggedIn],
    db: Session,
    session_factory: sessionmaker[Session],
    seeded: Session,
    import_root: Path,
) -> None:
    paths = write(import_root / "syn", seed=42, days=10)
    assert ingest(session_factory, paths["events"], "synthetic").status == "completed"
    correlation.run_correlation(
        db,
        CLI_ACTOR,
        datetime.fromisoformat("2026-01-01T00:00:00+00:00"),
        datetime.fromisoformat("2026-01-11T00:00:00+00:00"),
    )
    viewer = login("val", Role.VIEWER)
    body = viewer.client.get("/api/v1/dashboard/overview", params=RANGE).json()

    with db.begin():
        by_type = dict(
            db.execute(
                select(FactSecurityEvent.event_type, func.count()).group_by(
                    FactSecurityEvent.event_type
                )
            ).all()
        )
        batches = dict(
            db.execute(
                select(IngestionBatch.status, func.count()).group_by(IngestionBatch.status)
            ).all()
        )
    assert body["events"]["by_type"] == by_type
    assert body["events"]["total"] == sum(by_type.values()) == 1582
    assert body["ingestion"]["batches_by_status"] == batches
    alerts = viewer.client.get("/api/v1/alerts", params={"limit": 500}).json()["items"]
    assert body["alerts"]["open_total"] == len(alerts) > 0
    severities = {
        s: sum(1 for a in alerts if a["severity"] == s)
        for s in ("critical", "high", "medium", "low")
    }
    assert body["alerts"]["open_by_severity"] == severities
    assert body["models"]["is_empty"] is True  # nothing trained in this test
    assert body["threat_intel"] == body["threat_intel"] | {"active_indicators": 0, "matches": 0}

    outside = viewer.client.get(
        "/api/v1/dashboard/overview",
        params={"from": "2025-01-01T00:00:00Z", "to": "2025-02-01T00:00:00Z"},
    ).json()
    assert outside["events"]["is_empty"] is True
    bad = viewer.client.get(
        "/api/v1/dashboard/overview", params={"from": RANGE["to"], "to": RANGE["from"]}
    )
    assert bad.status_code == 422
