from __future__ import annotations

import io
import json
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app import cli
from app.models import AppUser, AuditLog, Job

pytestmark = pytest.mark.integration


@pytest.fixture
def cli_db(
    committed_db: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> sessionmaker[Session]:
    monkeypatch.setattr(cli, "get_session_factory", lambda: committed_db)
    return committed_db


def test_create_admin_from_stdin(
    cli_db: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO("a-very-long-admin-passphrase\n"))
    assert cli.main(["create-admin", "--username", "Root", "--password-stdin"]) == 0
    assert "created admin 'root'" in capsys.readouterr().out
    with cli_db() as session:
        user = session.scalar(select(AppUser).where(AppUser.username == "root"))
        assert user is not None and user.role == "admin"
        audit = session.scalars(select(AuditLog).where(AuditLog.action == "user.create")).one()
        assert audit.actor_type == "cli"


def test_create_admin_rejects_weak_password(
    cli_db: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO("short\n"))
    assert cli.main(["create-admin", "--username", "root", "--password-stdin"]) == 2
    assert "password" in capsys.readouterr().err


def test_diagnostic_job_and_worker_once(
    cli_db: sessionmaker[Session], capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["diagnostic-job", "--steps", "2"]) == 0
    job_id = json.loads(capsys.readouterr().out)["job_id"]
    assert cli.main(["worker", "--once"]) == 0
    assert "ran one job" in capsys.readouterr().out
    with cli_db() as session:
        job = session.scalar(select(Job).where(Job.job_id == job_id))
        assert job is not None and job.status == "succeeded"


def test_worker_healthcheck(tmp_path: Path) -> None:
    beat = tmp_path / "beat"
    assert cli.main(["worker-healthcheck", "--heartbeat-file", str(beat)]) == 1
    beat.write_text("now")
    assert cli.main(["worker-healthcheck", "--heartbeat-file", str(beat)]) == 0


def test_threat_intel_and_correlation_commands(
    cli_db: sessionmaker[Session],
    import_root: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert cli.main(["seed-reference"]) == 0
    assert "correlation rules: 5 created" in capsys.readouterr().out
    out = import_root / "syn"
    assert cli.main(["generate-synthetic", "--out", str(out)]) == 0
    assert cli.main(["ingest", "--source", "synthetic", str(out / "events.jsonl")]) == 0
    capsys.readouterr()
    indicators = str(out / "synthetic_indicators.csv")
    assert cli.main(["ti-import", "--feed", "local-csv", "--format", "csv", indicators]) == 0
    assert json.loads(capsys.readouterr().out.strip().splitlines()[-1])["created"] == 5
    with pytest.raises(SystemExit):
        cli.main(["match-indicators", "--from", "2026-01-01T00:00:00Z"])
    rng = ["--from", "2026-01-01T00:00:00Z", "--to", "2026-01-11T00:00:00Z"]
    assert cli.main(["match-indicators", *rng]) == 0
    assert json.loads(capsys.readouterr().out)["matches_created"] > 0
    assert cli.main(["correlate", *rng]) == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["rules"]["ti_match_active"]["alerts_created"] >= 1
    assert summary["rules"]["bruteforce_then_success"]["alerts_created"] == 1
    with pytest.raises(SystemExit):
        cli.main(["correlate", "--from", "2026-01-01T00:00:00", "--to", "2026-01-02T00:00:00"])
