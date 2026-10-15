"""Shared fixtures.

Integration tests use a real PostgreSQL database from ``CTI_TEST_DATABASE_URL`` (read from the
environment or the repository ``.env``). The schema is rebuilt with Alembic once per session;
each test then runs inside a transaction that is rolled back (``db``), or — for tests that need
data visible across connections, such as concurrent workers — commits and is cleaned up by
truncation (``committed_db``).
"""

from __future__ import annotations

import os
import tempfile
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest
from dotenv import dotenv_values

REPO_ROOT = Path(__file__).resolve().parents[2]
_dotenv = dotenv_values(REPO_ROOT / ".env")
TEST_DATABASE_URL = os.environ.get("CTI_TEST_DATABASE_URL") or _dotenv.get("CTI_TEST_DATABASE_URL")
# Captured before it is overridden below, to make sure tests never target the app database.
APP_DATABASE_URL = os.environ.get("CTI_DATABASE_URL") or _dotenv.get("CTI_DATABASE_URL")
TEST_SECRET_KEY = "test-secret-key-0123456789abcdef-0123456789abcdef"
_TMP = Path(tempfile.mkdtemp(prefix="cti-tests-"))

# Configure the application *before* any app module reads settings.
os.environ["CTI_ENV"] = "test"
os.environ["CTI_SECRET_KEY"] = TEST_SECRET_KEY
os.environ["CTI_UPLOAD_DIR"] = str(_TMP / "uploads")
os.environ["CTI_ARTIFACT_DIR"] = str(_TMP / "artifacts")
os.environ["CTI_LOG_LEVEL"] = "WARNING"
if TEST_DATABASE_URL:
    os.environ["CTI_DATABASE_URL"] = TEST_DATABASE_URL

from alembic import command  # noqa: E402
from alembic.config import Config  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import Connection, Engine, create_engine, text  # noqa: E402
from sqlalchemy.engine import make_url  # noqa: E402
from sqlalchemy.orm import Session, sessionmaker  # noqa: E402

from app.core import clock  # noqa: E402
from app.core.config import get_settings  # noqa: E402
from app.core.db import SESSION_OPTIONS, get_session  # noqa: E402
from app.core.security import Role  # noqa: E402
from app.services import users as users_service  # noqa: E402
from app.services.actors import CLI_ACTOR  # noqa: E402

BACKEND_DIR = REPO_ROOT / "backend"
APP_TABLES = (
    "processing_watermark",
    "drift_report",
    "pattern_mining_run",
    "event_ground_truth",
    "fact_security_event",
    "data_quality_result",
    "rejected_record",
    "raw_record",
    "ingestion_batch",
    "dim_asset",
    "dim_source",
    "dim_attack_category",
    "auth_session",
    "audit_log",
    "job",
    "app_user",
)
DEFAULT_PASSWORD = "correct-horse-battery-staple"


def alembic_config(url: str) -> Config:
    cfg = Config(str(BACKEND_DIR / "alembic.ini"))
    cfg.set_main_option("sqlalchemy.url", url)
    cfg.attributes["configure_logger"] = False
    return cfg


class UnsafeTestDatabaseError(RuntimeError):
    pass


def assert_safe_test_database(test_url: str, app_url: str | None) -> None:
    """Refuse to run destructive fixtures against anything but a dedicated test database.

    The session fixture drops the ``public`` schema, so a mistyped ``CTI_TEST_DATABASE_URL``
    must never be able to point at development or production data.
    """
    test = make_url(test_url)
    name = test.database or ""
    if "test" not in name.lower():
        raise UnsafeTestDatabaseError(
            f"refusing to use database {name!r} for tests: its name must contain 'test'"
        )
    if app_url:
        app = make_url(app_url)
        same_server = (test.host or "localhost", test.port or 5432) == (
            app.host or "localhost",
            app.port or 5432,
        )
        if same_server and app.database == name:
            raise UnsafeTestDatabaseError(
                "CTI_TEST_DATABASE_URL points at the same database as CTI_DATABASE_URL"
            )


def require_db() -> str:
    if not TEST_DATABASE_URL:
        pytest.skip("CTI_TEST_DATABASE_URL is not set (see TESTING_STRATEGY.md §2)")
    assert_safe_test_database(TEST_DATABASE_URL, APP_DATABASE_URL)
    return TEST_DATABASE_URL


@pytest.fixture(autouse=True)
def _reset_clock() -> Iterator[None]:
    yield
    clock.set_clock(None)


@pytest.fixture(scope="session")
def engine() -> Iterator[Engine]:
    url = require_db()
    eng = create_engine(url, connect_args=SESSION_OPTIONS)
    with eng.begin() as conn:
        conn.execute(text("DROP SCHEMA public CASCADE"))
        conn.execute(text("CREATE SCHEMA public"))
    command.upgrade(alembic_config(url), "head")
    yield eng
    eng.dispose()


@pytest.fixture
def connection(engine: Engine) -> Iterator[Connection]:
    conn = engine.connect()
    outer = conn.begin()
    try:
        yield conn
    finally:
        outer.rollback()
        conn.close()


@pytest.fixture
def session_factory(connection: Connection) -> sessionmaker[Session]:
    """Sessions joined to the test's outer transaction: service ``begin()``s become savepoints."""
    return sessionmaker(
        bind=connection, join_transaction_mode="create_savepoint", expire_on_commit=False
    )


@pytest.fixture
def db(session_factory: sessionmaker[Session]) -> Iterator[Session]:
    with session_factory() as session:
        yield session


@pytest.fixture
def committed_db(engine: Engine) -> Iterator[sessionmaker[Session]]:
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    try:
        yield factory
    finally:
        with engine.begin() as conn:
            conn.execute(text(f"TRUNCATE {', '.join(APP_TABLES)} CASCADE"))


@pytest.fixture
def client(session_factory: sessionmaker[Session]) -> Iterator[TestClient]:
    from app.main import create_app

    app = create_app(get_settings())

    def _session() -> Iterator[Session]:
        with session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = _session
    with TestClient(app, base_url="http://testserver") as test_client:
        yield test_client


@pytest.fixture
def make_user(db: Session) -> Callable[..., str]:
    def _make(username: str, role: Role = Role.VIEWER, password: str = DEFAULT_PASSWORD) -> str:
        users_service.create_user(db, CLI_ACTOR, username, password, role)
        return username

    return _make


class LoggedIn:
    def __init__(self, client: TestClient, csrf: str, username: str) -> None:
        self.client = client
        self.csrf = csrf
        self.username = username

    def headers(self) -> dict[str, str]:
        return {"X-CSRF-Token": self.csrf}


@pytest.fixture
def login(client: TestClient, make_user: Callable[..., str]) -> Callable[..., LoggedIn]:
    def _login(username: str, role: Role = Role.VIEWER) -> LoggedIn:
        make_user(username, role)
        client.cookies.clear()
        resp = client.post(
            "/api/v1/auth/login", json={"username": username, "password": DEFAULT_PASSWORD}
        )
        assert resp.status_code == 200, resp.text
        return LoggedIn(client, resp.json()["csrf_token"], username)

    return _login
