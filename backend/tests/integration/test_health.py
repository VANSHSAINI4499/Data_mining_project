from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Connection, create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings
from app.core.db import get_session

pytestmark = pytest.mark.integration


def test_liveness(client: TestClient) -> None:
    resp = client.get("/api/v1/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"
    assert resp.json()["version"]


def test_ready_when_db_up_and_migrated(client: TestClient) -> None:
    resp = client.get("/api/v1/health/ready")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "ready"
    assert {c["status"] for c in body["checks"].values()} == {"ok"}


def test_not_ready_when_migrations_behind(client: TestClient, connection: Connection) -> None:
    connection.execute(text("UPDATE alembic_version SET version_num = 'not-a-revision'"))
    resp = client.get("/api/v1/health/ready")
    assert resp.status_code == 503
    assert resp.headers["content-type"].startswith("application/problem+json")
    body = resp.json()
    assert body["checks"]["migrations"]["detail"] == "migrations_behind"
    assert body["checks"]["database"]["status"] == "ok"


def test_not_ready_when_database_unreachable(client: TestClient) -> None:
    dead = create_engine(
        "postgresql+psycopg://nobody:nothing@127.0.0.1:1/none", connect_args={"connect_timeout": 2}
    )
    factory = sessionmaker(bind=dead)

    def _session() -> Iterator[Session]:
        with factory() as session:
            yield session

    client.app.dependency_overrides[get_session] = _session  # type: ignore[attr-defined]
    resp = client.get("/api/v1/health/ready")
    assert resp.status_code == 503
    checks = resp.json()["checks"]
    assert checks["database"]["status"] == "fail"
    assert "nobody" not in resp.text and "nothing" not in resp.text  # no credentials leaked
    dead.dispose()


def test_not_ready_when_upload_dir_unwritable(
    client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    blocker = tmp_path / "file-not-dir"
    blocker.write_text("x")
    monkeypatch.setattr(get_settings(), "upload_dir", blocker / "uploads")
    resp = client.get("/api/v1/health/ready")
    assert resp.status_code == 503
    assert resp.json()["checks"]["upload_dir"]["status"] == "fail"


def test_database_sessions_use_utc(db: Session) -> None:
    with db.begin():
        assert db.execute(text("SHOW timezone")).scalar_one() == "UTC"
