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


def test_retention_dry_run_then_execute(
    cli_db: sessionmaker[Session],
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import uuid
    from datetime import timedelta

    from app.core import clock
    from app.core.config import get_settings
    from app.models import AuthSession, IngestionBatch

    settings = get_settings()
    monkeypatch.setattr(settings, "upload_dir", tmp_path / "uploads")
    settings.upload_dir.mkdir()
    upload = settings.upload_dir / "old.jsonl"
    upload.write_text("{}\n", encoding="utf-8")
    elsewhere = tmp_path / "import-root-file.jsonl"
    elsewhere.write_text("{}\n", encoding="utf-8")
    long_ago = clock.now() - timedelta(days=400)
    with cli_db() as session:
        from app.services.actors import CLI_ACTOR
        from app.services.reference import seed_reference

        seed_reference(session, CLI_ACTOR)
    with cli_db() as session, session.begin():
        from app.models import DimSource

        source_id = session.scalar(
            select(DimSource.source_id).where(DimSource.source_key == "synthetic")
        )
        user = AppUser(user_id=uuid.uuid4(), username="olduser", password_hash="x", role="viewer")
        session.add(user)
        session.flush()
        session.add(
            AuthSession(
                session_id=uuid.uuid4(),
                user_id=user.user_id,
                token_hash="t" * 64,
                csrf_token_hash="c" * 64,
                expires_at=long_ago,
                last_seen_at=long_ago,
            )
        )
        for path in (upload, elsewhere):
            session.add(
                IngestionBatch(
                    batch_id=uuid.uuid4(),
                    source_id=source_id,
                    adapter="canonical_jsonl",
                    adapter_version="1.0",
                    original_filename=path.name,
                    stored_path=str(path),
                    file_sha256=uuid.uuid4().hex * 2,
                    file_size_bytes=3,
                    status="completed",
                    finished_at=long_ago,
                )
            )
        session.add(
            Job(
                job_id=uuid.uuid4(),
                job_type="diagnostic",
                status="succeeded",
                params={},
                finished_at=long_ago,
            )
        )
    capsys.readouterr()
    assert cli.main(["retention", "apply", "--dry-run"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["dry_run"] is True
    assert report["counts"]["uploaded_files"] == 1
    assert report["counts"]["expired_sessions"] == 1
    assert report["counts"]["jobs"] == 1
    assert upload.exists()

    assert cli.main(["retention", "apply", "--execute"]) == 0
    assert json.loads(capsys.readouterr().out)["counts"]["uploaded_files"] == 1
    assert not upload.exists() and elsewhere.exists()
    with cli_db() as session:
        assert session.scalar(select(AuthSession).where(AuthSession.expires_at == long_ago)) is None
        actions = set(session.scalars(select(AuditLog.action)))
        assert {"retention.dry_run", "retention.applied"} <= actions
    with pytest.raises(SystemExit):
        cli.main(["retention", "apply"])
