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
