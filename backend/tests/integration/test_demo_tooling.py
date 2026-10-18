"""Demo tooling: the local target site, the log generator, and live tailing into the pipeline."""

from __future__ import annotations

import uuid
from argparse import Namespace
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from app import cli
from app.devtools import demo_traffic
from app.devtools.demo_site import create_demo_app
from app.models import Alert, FactSecurityEvent, WebPayloadResult
from app.services import models as models_service
from app.services.actors import CLI_ACTOR
from tests.integration.test_web_payload_scoring import access_log, trained  # noqa: F401

pytestmark = pytest.mark.integration


def test_demo_site_escapes_and_logs(tmp_path: Path) -> None:
    log = tmp_path / "demo.log"
    client = TestClient(create_demo_app(log))

    attack = client.get("/search", params={"q": "<script>alert(1)</script>"})
    assert attack.status_code == 200
    assert "<script>alert(1)</script>" not in attack.text  # echoed HTML-escaped, never executed
    assert "&lt;script&gt;" in attack.text

    client.get("/ping", params={"host": "127.0.0.1; cat /etc/passwd"})
    client.get("/", params={})
    lines = log.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 3
    # Query strings are URL-encoded in the log, as a browser would send them.
    assert any("/search?q=%3Cscript%3E" in line for line in lines)
    assert any("/ping?host=127.0.0.1%3B" in line for line in lines)
    assert all(line.count('"') >= 4 for line in lines)  # request + referer + user-agent + req_id


def test_demo_traffic_is_deterministic_and_parseable() -> None:
    first: list[str] = []
    second: list[str] = []
    report = demo_traffic.generate(first.append, count=50, attack_ratio=0.2, seed=7)
    demo_traffic.generate(second.append, count=50, attack_ratio=0.2, seed=7)
    assert report == {"total": 50, "attack_payloads": 10, "benign": 40}
    assert first == second  # same seed -> identical output

    import io

    from app.ingestion.adapters.web import NginxAccessAdapter
    from app.ingestion.records import BatchContext

    adapter = NginxAccessAdapter(BatchContext(source_key="web-server", timezone="UTC"))
    raws = list(adapter.read(io.BytesIO("".join(first).encode())))
    assert len(raws) == 50 and not any(r.problem for r in raws)


def test_tail_ingests_appended_lines_and_raises_alerts(
    monkeypatch: pytest.MonkeyPatch,
    session_factory: sessionmaker[Session],
    db: Session,
    import_root: Path,
    trained: uuid.UUID,  # noqa: F811
) -> None:
    monkeypatch.setattr(cli, "get_session_factory", lambda: session_factory)
    with session_factory() as session:
        models_service.promote(session, CLI_ACTOR, trained)

    log = import_root / "demo" / "live.log"
    log.parent.mkdir(parents=True, exist_ok=True)
    # One attacker (198.51.100.23) sends several SQLi/other payloads; plenty of benign traffic.
    written = demo_traffic.generate(
        lambda line: log.open("a", encoding="utf-8", newline="\n").write(line),
        count=60,
        attack_ratio=0.3,
        seed=11,
    )
    assert written["attack_payloads"] == 18

    args = Namespace(
        log=str(log), source="web-server", interval=1.0, from_end=False, once=True, process=True
    )
    assert cli.cmd_tail(args) == 0

    with db.begin():
        events = db.scalar(select(func.count()).select_from(FactSecurityEvent)) or 0
        scored = db.scalar(select(func.count()).select_from(WebPayloadResult)) or 0
        alerts = list(db.scalars(select(Alert.title)))
    assert events == 60  # every appended line ingested exactly once
    assert scored > 0  # query parameters classified by the promoted model
    assert any(t.startswith("Repeated attack-like web request parameters") for t in alerts)


def test_tail_from_end_skips_existing_lines(
    monkeypatch: pytest.MonkeyPatch,
    session_factory: sessionmaker[Session],
    db: Session,
    import_root: Path,
    seeded: Session,
) -> None:
    monkeypatch.setattr(cli, "get_session_factory", lambda: session_factory)
    log = import_root / "demo" / "pre.log"
    log.parent.mkdir(parents=True, exist_ok=True)
    demo_traffic.generate(
        lambda line: log.open("a", encoding="utf-8", newline="\n").write(line),
        count=10,
        attack_ratio=0.0,
        seed=3,
    )
    args = Namespace(
        log=str(log), source="web-server", interval=1.0, from_end=True, once=True, process=False
    )
    assert cli.cmd_tail(args) == 0
    with db.begin():
        assert (db.scalar(select(func.count()).select_from(FactSecurityEvent)) or 0) == 0
