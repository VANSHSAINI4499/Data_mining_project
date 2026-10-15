"""Nginx/Apache access-log adapter (combined + common formats)."""

from __future__ import annotations

import shutil
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import REPO_ROOT
from app.ingestion.adapters.web import iso_time, query_params
from app.models import FactSecurityEvent, RejectedRecord
from tests.integration.ingestion_helpers import ingest

pytestmark = pytest.mark.integration

SAMPLE = REPO_ROOT / "data" / "samples" / "web-access" / "access_sample.log"


def test_time_and_query_parsing() -> None:
    assert iso_time("15/Oct/2026:10:12:01 +0530") == "2026-10-15T10:12:01+05:30"
    assert iso_time("15/Okt/2026:10:12:01 +0000") is None
    assert iso_time("2026-10-15 10:12:01") is None
    assert query_params("/s?q=1%27+or+1%3D1--&empty=&x=%3Cb%3E") == [
        ["q", "1' or 1=1--"],
        ["empty", ""],
        ["x", "<b>"],
    ]
    assert query_params("/plain/path") == []
    assert len(query_params("/?" + "&".join(f"p{i}=v" for i in range(80)))) == 50


def test_sample_access_log(
    session_factory: sessionmaker[Session], db: Session, seeded: Session, import_root: Path
) -> None:
    path = import_root / "access.log"
    shutil.copyfile(SAMPLE, path)
    outcome = ingest(session_factory, path, "web-server")
    assert outcome.status in ("completed", "completed_with_errors")
    # 12 lines: 1 garbage line rejected; the two identical favicon requests are both kept.
    assert (
        outcome.records_total,
        outcome.records_loaded,
        outcome.records_rejected,
        outcome.records_duplicate,
    ) == (12, 11, 1, 0)
    with db.begin():
        events = list(db.scalars(select(FactSecurityEvent).order_by(FactSecurityEvent.event_id)))
        rejected = db.scalars(select(RejectedRecord)).one()
    assert rejected.record_number == 12 and rejected.error_code == "INVALID_VALUE"
    assert {e.event_type for e in events} == {"http"}
    first = events[0]
    assert first.event_time == datetime(2026, 10, 15, 10, 0, 1, tzinfo=UTC)
    assert str(first.src_ip).split("/")[0] == "192.0.2.10" and first.url == "/index.html"
    assert first.bytes_in == 5120
    assert first.attributes["method"] == "GET" and first.attributes["status"] == 200
    assert first.attributes["log_format"] == "combined"

    login = next(e for e in events if e.url == "/login")
    assert login.user_name == "alice" and login.attributes["method"] == "POST"
    sqli = next(e for e in events if e.url and e.url.startswith("/search?q=1"))
    assert sqli.attributes["query_params"][0] == ["q", "1' OR '1'='1' --"]
    assert sqli.attributes["user_agent"] == "sqlmap/1.8"
    traversal = next(e for e in events if e.url and e.url.startswith("/download"))
    assert traversal.attributes["query_params"] == [["file", "../../../etc/passwd"]]
    tls = next(e for e in events if e.attributes.get("request_unparsed"))
    assert tls.url is None and tls.attributes["status"] == 400
    common = next(e for e in events if e.url == "/api/v1/items")
    assert common.attributes["log_format"] == "common" and common.attributes["referer"] is None
    assert sum(1 for e in events if e.url == "/favicon.ico") == 2


def test_overlapping_logs_deduplicate(
    session_factory: sessionmaker[Session], seeded: Session, import_root: Path
) -> None:
    lines = SAMPLE.read_text(encoding="utf-8").splitlines(keepends=True)
    (import_root / "a.log").write_text("".join(lines[:9]), encoding="utf-8")
    (import_root / "b.log").write_text("".join(lines[5:11]), encoding="utf-8")
    first = ingest(session_factory, import_root / "a.log", "web-server")
    second = ingest(session_factory, import_root / "b.log", "web-server")
    assert first.records_loaded == 9
    # Lines 6-9 overlap (including both identical favicon lines); 10-11 are new.
    assert (second.records_loaded, second.records_duplicate) == (2, 4)


def test_variant_mismatch_is_rejected(
    session_factory: sessionmaker[Session], seeded: Session, import_root: Path
) -> None:
    from app.services.ingestion import BatchOptions

    path = import_root / "c.log"
    shutil.copyfile(SAMPLE, path)
    outcome = ingest(session_factory, path, "web-server", options=BatchOptions(variant="common"))
    # Only the single common-format line is accepted; combined lines are rejected with a reason.
    assert outcome.records_loaded == 1 and outcome.records_rejected == 11
