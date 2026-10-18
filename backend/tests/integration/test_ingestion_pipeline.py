"""End-to-end ingestion through the loader (AC-2.3, AC-2.4, AC-2.5, AC-2.6, AC-2.11)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings
from app.core.errors import (
    NotFoundError,
    UnsupportedMediaTypeError,
    ValidationFailedError,
)
from app.models import (
    DataQualityResult,
    EventGroundTruth,
    FactSecurityEvent,
    IngestionBatch,
    RawRecord,
    RejectedRecord,
)
from app.services import data_quality, ingestion
from app.services.actors import CLI_ACTOR
from app.services.ingestion import BatchOptions, process_batch
from tests.integration.ingestion_helpers import (
    add_source,
    event_count,
    ingest,
    write_jsonl,
)

pytestmark = pytest.mark.integration


def flow(i: int, **extra: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "event_type": "network_flow",
        "event_time": f"2026-01-05T10:00:{i % 60:02d}Z",
        "src_ip": "192.0.2.10",
        "dst_ip": "198.51.100.7",
        "src_port": 40000 + i,
        "dst_port": 22,
        "protocol": "tcp",
        "bytes_out": 100 + i,
    }
    row.update(extra)
    return row


MIXED = [
    flow(1, label_raw="BENIGN"),
    flow(2, label_raw="BRUTE_FORCE", is_attack=True),
    flow(3, label_raw="Mystery Label"),
    {
        "event_type": "auth",
        "event_time": "2026-01-05T10:01:00Z",
        "user_name": "Alice",
        "auth_result": "failure",
        "src_ip": "203.0.113.5",
        "service": "sshd",
        "extra_field": "x",
    },
    {
        "event_type": "network_flow",
        "event_time": "not a time",
        "src_ip": "192.0.2.1",
        "dst_ip": "192.0.2.2",
    },
    "{broken json",
    flow(1, label_raw="BENIGN"),  # exact duplicate of the first record
]


def _batch(db: Session, batch_id: Any) -> IngestionBatch:
    with db.begin():
        batch = db.get(IngestionBatch, batch_id)
        assert batch is not None
        db.expunge(batch)
        return batch


def test_mixed_file_is_loaded_preserved_and_reconciled(
    session_factory: sessionmaker[Session], seeded: Session, import_root: Path, db: Session
) -> None:
    path = write_jsonl(import_root / "mixed.jsonl", MIXED)
    outcome = ingest(session_factory, path, "synthetic")
    assert outcome.status == "completed_with_errors"
    assert (
        outcome.records_total,
        outcome.records_loaded,
        outcome.records_rejected,
        outcome.records_duplicate,
    ) == (7, 4, 2, 1)

    batch = _batch(db, outcome.batch_id)
    assert batch.last_committed_record == 7
    assert batch.label_mapping_version == "canonical@1"
    assert batch.timezone_assumption is None  # all timestamps carried a timezone
    with db.begin():
        raws = db.scalars(
            select(RawRecord)
            .where(RawRecord.batch_id == outcome.batch_id)
            .order_by(RawRecord.record_number)
        ).all()
        assert [r.record_number for r in raws] == list(range(1, 8))
        assert raws[5].raw_payload is None and raws[5].raw_text == "{broken json"

        rejects = db.scalars(
            select(RejectedRecord)
            .where(RejectedRecord.batch_id == outcome.batch_id)
            .order_by(RejectedRecord.record_number)
        ).all()
        assert [(r.record_number, r.error_code) for r in rejects] == [
            (5, "INVALID_TIMESTAMP"),
            (6, "MALFORMED_JSON"),
        ]

        auth = db.scalar(select(FactSecurityEvent).where(FactSecurityEvent.event_type == "auth"))
        assert auth is not None
        assert auth.user_name_normalized == "alice"
        assert auth.attributes == {"extra_field": "x"}
        assert auth.adapter_version == "canonical_jsonl@1.0"
        raw = db.get(RawRecord, auth.raw_record_id)
        assert raw is not None and raw.record_number == 4  # lineage back to the raw record

        truths = {t.label_raw: t for t in db.scalars(select(EventGroundTruth)).all()}
        assert truths["BENIGN"].attack_category_id == 1
        assert (
            truths["BRUTE_FORCE"].is_attack is True
            and truths["BRUTE_FORCE"].mapping_status == "mapped"
        )
        assert truths["Mystery Label"].mapping_status == "unmapped"
        assert truths["Mystery Label"].attack_category_id is None

        checks = {
            r.check_name: r.status
            for r in db.scalars(
                select(DataQualityResult).where(DataQualityResult.batch_id == outcome.batch_id)
            ).all()
        }
    assert checks["counter_reconciliation"] == "pass"
    assert checks["rejection_ratio"] == "fail"  # 2/7 > 20 %
    assert checks["unmapped_labels"] == "warn"
    assert checks["default_partition_empty"] == "pass"


def test_reimporting_the_same_file_is_a_duplicate_batch(
    session_factory: sessionmaker[Session], seeded: Session, import_root: Path, db: Session
) -> None:
    path = write_jsonl(import_root / "a.jsonl", [flow(1), flow(2)])
    first = ingest(session_factory, path, "synthetic")
    second = ingest(session_factory, path, "synthetic")
    assert second.status == "duplicate"
    assert _batch(db, second.batch_id).duplicate_of == first.batch_id
    assert event_count(db) == 2


def test_overlapping_records_in_a_new_file_are_counted_as_duplicates(
    session_factory: sessionmaker[Session], seeded: Session, import_root: Path, db: Session
) -> None:
    ingest(session_factory, write_jsonl(import_root / "a.jsonl", [flow(1), flow(2)]), "synthetic")
    outcome = ingest(
        session_factory, write_jsonl(import_root / "b.jsonl", [flow(2), flow(3)]), "synthetic"
    )
    assert (outcome.records_loaded, outcome.records_duplicate) == (1, 1)
    assert event_count(db) == 3


def test_failed_chunk_is_resumable_without_duplicates(
    session_factory: sessionmaker[Session],
    seeded: Session,
    import_root: Path,
    db: Session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(get_settings(), "ingest_chunk_size", 2)
    path = write_jsonl(import_root / "c.jsonl", [flow(i) for i in range(1, 6)])
    with session_factory() as session:
        batch, _ = ingestion.create_cli_batch(
            session,
            get_settings(),
            CLI_ACTOR,
            source_key="synthetic",
            adapter_name=None,
            path=path,
            options=BatchOptions(),
        )
    calls = {"n": 0}

    def cancel_on_second_chunk() -> None:
        calls["n"] += 1
        if calls["n"] == 2:
            raise RuntimeError("simulated interruption")

    failed = process_batch(
        session_factory, get_settings(), batch.batch_id, check_cancel=cancel_on_second_chunk
    )
    assert failed.status == "failed"
    assert failed.error is not None and failed.error["code"] == "CANCELLED"
    assert failed.error["last_committed_record"] == 2
    assert event_count(db) == 2

    with session_factory() as session:
        ingestion.retry_batch(session, CLI_ACTOR, batch.batch_id)
    done = process_batch(session_factory, get_settings(), batch.batch_id)
    assert done.status == "completed"
    assert (done.records_total, done.records_loaded, done.records_duplicate) == (5, 5, 0)
    assert event_count(db) == 5
    assert _batch(db, batch.batch_id).batch_metadata["resumed_after_record"] == 2


def test_completed_batch_reprocessing_is_a_no_op(
    session_factory: sessionmaker[Session], seeded: Session, import_root: Path, db: Session
) -> None:
    outcome = ingest(session_factory, write_jsonl(import_root / "d.jsonl", [flow(1)]), "synthetic")
    again = process_batch(session_factory, get_settings(), outcome.batch_id)
    assert again.status == "completed" and again.records_total == 1
    assert event_count(db) == 1


def test_high_rejection_ratio_fails_batch(
    session_factory: sessionmaker[Session], seeded: Session, import_root: Path, db: Session
) -> None:
    rows: list[dict[str, Any] | str] = ["not json"] * 10_000 + [flow(1)]
    outcome = ingest(session_factory, write_jsonl(import_root / "bad.jsonl", rows), "synthetic")
    assert outcome.status == "failed"
    assert outcome.error is not None and outcome.error["code"] == "ADAPTER_MISMATCH_SUSPECTED"
    # Raw records already committed are kept for diagnosis.
    with db.begin():
        kept = db.scalar(
            select(RawRecord.record_number)
            .where(RawRecord.batch_id == outcome.batch_id)
            .order_by(RawRecord.record_number.desc())
        )
    assert kept == 10_000


def test_naive_timestamps_need_a_timezone(
    session_factory: sessionmaker[Session], seeded: Session, import_root: Path, db: Session
) -> None:
    add_source(db, "no-tz", "canonical_jsonl", timezone=None)
    path = write_jsonl(import_root / "naive.jsonl", [flow(1, event_time="2026-01-05 10:00:00")])
    failed = ingest(session_factory, path, "no-tz")
    assert failed.status == "failed"
    assert failed.error is not None and failed.error["code"] == "TIMEZONE_NOT_CONFIGURED"

    ok = ingest(
        session_factory,
        write_jsonl(import_root / "naive2.jsonl", [flow(2, event_time="2026-01-05 10:00:00")]),
        "no-tz",
        options=BatchOptions(timezone="Asia/Kolkata"),
    )
    assert ok.status == "completed"
    batch = _batch(db, ok.batch_id)
    assert batch.timezone_assumption == "Asia/Kolkata"
    with db.begin():
        stored = db.scalar(
            select(FactSecurityEvent.event_time).where(FactSecurityEvent.batch_id == ok.batch_id)
        )
    assert stored is not None and stored.isoformat() == "2026-01-05T04:30:00+00:00"


def test_nul_bytes_are_escaped_not_lost(
    session_factory: sessionmaker[Session], seeded: Session, import_root: Path, db: Session
) -> None:
    path = write_jsonl(
        import_root / "nul.jsonl", [{**flow(1), "note": "a\u0000b", "user_name": "bo\u0000b"}]
    )
    outcome = ingest(session_factory, path, "synthetic")
    assert outcome.status == "completed"
    with db.begin():
        raw = db.scalar(select(RawRecord).where(RawRecord.batch_id == outcome.batch_id))
        event = db.scalar(
            select(FactSecurityEvent).where(FactSecurityEvent.batch_id == outcome.batch_id)
        )
    assert raw is not None and raw.raw_nul_escaped and raw.raw_payload["note"] == "a\\x00b"
    assert event is not None and event.user_name == "bob"  # NUL removed from canonical text


def test_path_outside_import_root_is_refused(
    session_factory: sessionmaker[Session],
    seeded: Session,
    import_root: Path,
    tmp_path_factory: pytest.TempPathFactory,
) -> None:
    outside = write_jsonl(tmp_path_factory.mktemp("elsewhere") / "x.jsonl", [flow(1)])
    with pytest.raises(ValidationFailedError, match="outside the import root"):
        ingest(session_factory, outside, "synthetic")
    with pytest.raises(NotFoundError):
        ingest(session_factory, import_root / "missing.jsonl", "synthetic")


def test_binary_and_wrong_extension_are_refused(
    session_factory: sessionmaker[Session], seeded: Session, import_root: Path
) -> None:
    binary = import_root / "bin.jsonl"
    binary.write_bytes(b"\x00\x01\x02binary")
    with pytest.raises(UnsupportedMediaTypeError, match="binary"):
        ingest(session_factory, binary, "synthetic")
    archive = import_root / "data.zip"
    archive.write_bytes(b"PK")
    with pytest.raises(UnsupportedMediaTypeError, match="not allowed"):
        ingest(session_factory, archive, "synthetic")


def test_changed_file_is_detected_before_loading(
    session_factory: sessionmaker[Session], seeded: Session, import_root: Path
) -> None:
    path = write_jsonl(import_root / "e.jsonl", [flow(1)])
    with session_factory() as session:
        batch, _ = ingestion.create_cli_batch(
            session,
            get_settings(),
            CLI_ACTOR,
            source_key="synthetic",
            adapter_name=None,
            path=path,
            options=BatchOptions(),
        )
    write_jsonl(path, [flow(2)])
    outcome = process_batch(session_factory, get_settings(), batch.batch_id)
    assert outcome.status == "failed"
    assert outcome.error is not None and outcome.error["code"] == "FILE_CHANGED"


def test_data_quality_rerun_replaces_results(
    session_factory: sessionmaker[Session], seeded: Session, import_root: Path, db: Session
) -> None:
    outcome = ingest(session_factory, write_jsonl(import_root / "f.jsonl", [flow(1)]), "synthetic")
    first = data_quality.run_checks(db, outcome.batch_id)
    second = data_quality.run_checks(db, outcome.batch_id)
    assert len(first) == len(second)
    assert {r.check_name for r in second} >= {
        "counter_reconciliation",
        "rejection_ratio",
        "default_partition_empty",
        "duplicate_ratio",
    }


def _seed(factory: sessionmaker[Session]) -> None:
    from app.services.reference import seed_reference

    with factory() as session:
        seed_reference(session, CLI_ACTOR)


@pytest.mark.parametrize("writers", [1, 2, 3])
def test_parallel_writers_dedup_across_in_flight_chunks(
    committed_db: sessionmaker[Session],
    import_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    writers: int,
) -> None:
    # Real pooled connections (committed_db), so writers really run on separate connections.
    session_factory = committed_db
    _seed(committed_db)
    # One record per chunk, so a duplicate lands in a chunk written concurrently with the
    # chunk holding the first copy; the later chunk must see it as a duplicate.
    monkeypatch.setattr(get_settings(), "ingest_chunk_size", 1)
    monkeypatch.setattr(get_settings(), "ingest_writers", writers)
    rows = [
        flow(1, label_raw="BENIGN"),
        flow(1, label_raw="BENIGN"),
        flow(2, label_raw="BRUTE_FORCE", is_attack=True),
        "not json",
        flow(2, label_raw="BRUTE_FORCE", is_attack=True),
        flow(3, label_raw="Mystery Label"),
    ]
    outcome = ingest(session_factory, write_jsonl(import_root / "p.jsonl", rows), "synthetic")
    assert outcome.status == "completed_with_errors"
    assert (
        outcome.records_total,
        outcome.records_loaded,
        outcome.records_rejected,
        outcome.records_duplicate,
    ) == (6, 3, 1, 2)
    with committed_db() as db, db.begin():
        assert db.scalar(select(func.count()).select_from(FactSecurityEvent)) == 3
        assert db.scalar(select(func.count()).select_from(EventGroundTruth)) == 3
        batch = db.get(IngestionBatch, outcome.batch_id)
        assert batch is not None and batch.last_committed_record == 6
        assert batch.batch_metadata["unmapped_labels"] == {"Mystery Label": 1}
        numbers = list(
            db.scalars(
                select(RawRecord.record_number)
                .where(RawRecord.batch_id == outcome.batch_id)
                .order_by(RawRecord.record_number)
            )
        )
    assert numbers == [1, 2, 3, 4, 5, 6]


def test_failed_middle_chunk_commits_only_earlier_chunks(
    committed_db: sessionmaker[Session],
    import_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session_factory = committed_db
    _seed(committed_db)
    monkeypatch.setattr(get_settings(), "ingest_chunk_size", 2)
    monkeypatch.setattr(get_settings(), "ingest_writers", 3)
    real_insert = ingestion._insert_chunk

    def failing_insert(session: Session, batch: Any, rows: Any, category_ids: Any) -> Any:
        if rows.chunk[0].raw.record_number == 3:  # second chunk: records 3-4
            raise RuntimeError("simulated database failure")
        return real_insert(session, batch, rows, category_ids)

    monkeypatch.setattr(ingestion, "_insert_chunk", failing_insert)
    path = write_jsonl(import_root / "m.jsonl", [flow(i) for i in range(1, 9)])
    with pytest.raises(RuntimeError, match="simulated database failure"):
        ingest(session_factory, path, "synthetic")
    # Only the first chunk committed; chunks 3 and 4 (written concurrently) rolled back.
    with committed_db() as db, db.begin():
        assert db.scalar(select(func.count()).select_from(FactSecurityEvent)) == 2
        batch = db.scalars(select(IngestionBatch)).one()
        assert batch.last_committed_record == 2 and batch.records_total == 2
        kept = db.scalar(
            select(func.max(RawRecord.record_number)).where(RawRecord.batch_id == batch.batch_id)
        )
    assert kept == 2
