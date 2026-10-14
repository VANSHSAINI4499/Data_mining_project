"""Synthetic scenario generator (AC-2.9) and its ingestion."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import REPO_ROOT
from app.devtools.synthetic import generate, write
from app.models import EventGroundTruth, FactSecurityEvent
from tests.integration.ingestion_helpers import ingest

pytestmark = pytest.mark.integration


def test_same_seed_is_byte_identical_and_different_seed_differs(tmp_path: Path) -> None:
    first = write(tmp_path / "a", seed=7, days=5)
    second = write(tmp_path / "b", seed=7, days=5)
    for key in first:
        assert first[key].read_bytes() == second[key].read_bytes()
    assert generate(seed=8, days=5)[0] != generate(seed=7, days=5)[0]
    with pytest.raises(ValueError):
        generate(days=2)


def test_committed_sample_matches_generator() -> None:
    sample = REPO_ROOT / "data" / "samples" / "synthetic-seed42"
    events, indicators, expected = generate(seed=42, days=10, flows_per_hour=8)
    assert (sample / "events.jsonl").read_text(encoding="utf-8") == events
    assert (sample / "synthetic_indicators.csv").read_text(encoding="utf-8") == indicators
    assert (sample / "expected.json").read_text(encoding="utf-8") == expected


def test_synthetic_events_ingest_cleanly_and_match_expected(
    session_factory: sessionmaker[Session], seeded: Session, import_root: Path, db: Session
) -> None:
    paths = write(import_root / "syn", seed=42, days=10)
    expected = json.loads(paths["expected"].read_text(encoding="utf-8"))
    outcome = ingest(session_factory, paths["events"], "synthetic")
    assert outcome.status == "completed"
    assert outcome.records_rejected == 0 and outcome.records_duplicate == 0
    assert outcome.records_loaded == expected["event_count"]
    with db.begin():
        by_type = dict(
            db.execute(
                select(FactSecurityEvent.event_type, func.count()).group_by(
                    FactSecurityEvent.event_type
                )
            ).all()
        )
        statuses = set(db.scalars(select(EventGroundTruth.mapping_status)))
    assert by_type == expected["events_by_type"]
    assert statuses == {"mapped"}
    patterns = {p["pattern"] for p in expected["planted"]}
    assert patterns == {
        "bruteforce_then_success",
        "recon_then_attack",
        "anomalous_account",
        "indicator_matches",
        "repeated_ids_signature",
    }
