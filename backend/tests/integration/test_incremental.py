"""Incremental processing with watermarks and inbox ingestion (AC-8.1)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings
from app.devtools.synthetic import write
from app.models import IndicatorMatch, ProcessingWatermark
from app.services import inbox, incremental, threat_intel
from app.services.actors import CLI_ACTOR
from tests.integration.ingestion_helpers import ingest

pytestmark = pytest.mark.integration


def _split(events: Path, out: Path) -> tuple[Path, Path]:
    """Split the scenario by event time: before 2026-01-08 and from then on."""
    first, second = [], []
    for line in events.read_text(encoding="utf-8").splitlines(keepends=True):
        (first if json.loads(line)["event_time"] < "2026-01-08" else second).append(line)
    a, b = out / "part1.jsonl", out / "part2.jsonl"
    a.write_text("".join(first), encoding="utf-8")
    b.write_text("".join(second), encoding="utf-8")
    return a, b


@pytest.fixture
def scenario(seeded: Session, import_root: Path, db: Session) -> dict[str, Path]:
    paths = write(import_root / "syn", seed=42, days=10)
    a, b = _split(paths["events"], import_root)
    feed_id = threat_intel.feed_id_for_key(db, "local-csv")
    run = threat_intel.start_import(
        db,
        get_settings(),
        CLI_ACTOR,
        feed_id=feed_id,
        fmt="csv",
        filename="indicators.csv",
        data=paths["indicators"].read_bytes(),
        enqueue=False,
    )
    return {"part1": a, "part2": b, "feed_run": Path(str(run.feed_run_id))}


def _matches(db: Session) -> int:
    with db.begin():
        return int(db.scalar(select(func.count()).select_from(IndicatorMatch)) or 0)


def test_second_run_processes_only_new_batches(
    session_factory: sessionmaker[Session], db: Session, scenario: dict[str, Path]
) -> None:
    import uuid

    settings = get_settings()
    threat_intel.run_import(session_factory, settings, uuid.UUID(str(scenario["feed_run"])))
    assert ingest(session_factory, scenario["part1"], "synthetic").status == "completed"

    first = {r["consumer"]: r for r in incremental.run_all(session_factory, settings, CLI_ACTOR)}
    assert first["indicator_matching"]["new_batches"] == 1
    assert first["classifier_scoring"]["status"] == "skipped_no_active_classifier"
    assert first["correlation"]["status"] == "processed"
    after_first = _matches(db)

    again = {r["consumer"]: r for r in incremental.run_all(session_factory, settings, CLI_ACTOR)}
    assert again["indicator_matching"] == {
        "consumer": "indicator_matching",
        "new_batches": 0,
        "status": "up_to_date",
    }
    assert again["correlation"]["status"] == "up_to_date"
    # Without an active classifier the scoring consumer keeps waiting for the same batch.
    assert again["classifier_scoring"]["new_batches"] == 1
    assert _matches(db) == after_first

    assert ingest(session_factory, scenario["part2"], "synthetic").status == "completed"
    third = {r["consumer"]: r for r in incremental.run_all(session_factory, settings, CLI_ACTOR)}
    assert third["indicator_matching"]["new_batches"] == 1
    assert third["indicator_matching"]["matches_created"] == _matches(db) - after_first > 0
    assert third["correlation"]["alerts_created"] >= 1

    with db.begin():
        mark = db.get(ProcessingWatermark, "indicator_matching")
        assert mark is not None and mark.details["batches_processed_total"] == 2


def test_watch_imports_each_file_once(
    session_factory: sessionmaker[Session], seeded: Session, import_root: Path
) -> None:
    settings = get_settings()
    folder = import_root / "inbox"
    folder.mkdir()
    source = write(import_root / "syn", seed=42, days=4)["events"]
    (folder / "day1.jsonl").write_bytes(source.read_bytes())
    (folder / "partial.jsonl.part").write_text("{}", encoding="utf-8")

    first = inbox.poll_once(
        session_factory, settings, CLI_ACTOR, folder, source_key="synthetic", adapter=None
    )
    assert [(r.file, r.status) for r in first] == [("day1.jsonl", "completed")]
    assert (folder / "processed" / "day1.jsonl").exists()
    assert (folder / "partial.jsonl.part").exists()  # in-progress files are left alone

    assert (
        inbox.poll_once(
            session_factory, settings, CLI_ACTOR, folder, source_key="synthetic", adapter=None
        )
        == []
    )

    (folder / "again.jsonl").write_bytes(source.read_bytes())
    dup = inbox.poll_once(
        session_factory, settings, CLI_ACTOR, folder, source_key="synthetic", adapter=None
    )
    assert [(r.file, r.status) for r in dup] == [("again.jsonl", "duplicate")]

    (folder / "bad.exe").write_text("nope", encoding="utf-8")
    bad = inbox.poll_once(
        session_factory, settings, CLI_ACTOR, folder, source_key="synthetic", adapter=None
    )
    assert bad[0].status == "rejected" and (folder / "failed" / "bad.exe").exists()

    with pytest.raises(Exception, match="import root"):
        inbox.poll_once(
            session_factory,
            settings,
            CLI_ACTOR,
            import_root.parent / "elsewhere",
            source_key="synthetic",
            adapter=None,
        )
