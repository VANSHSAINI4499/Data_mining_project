"""Database role separation: SECURITY DEFINER functions and the app-role grant command."""

from __future__ import annotations

import secrets
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import psycopg
import pytest
from sqlalchemy import Connection, text

from app.services import db_roles
from tests.conftest import require_db

pytestmark = pytest.mark.integration


def _libpq(url: str) -> str:
    return url.replace("postgresql+psycopg://", "postgresql://", 1)


def test_definer_functions_are_locked_down(connection: Connection) -> None:
    rows = connection.execute(
        text(
            "SELECT p.proname, p.prosecdef, p.proconfig, "
            "has_function_privilege('public', p.oid, 'EXECUTE') AS public_exec "
            "FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "
            "WHERE n.nspname = 'public' AND p.proname IN "
            "('ensure_event_partitions', 'prune_audit_log')"
        )
    ).all()
    assert {r.proname for r in rows} == {"ensure_event_partitions", "prune_audit_log"}
    for r in rows:
        assert r.prosecdef is True
        assert r.proconfig == ["search_path=public, pg_temp"]
        assert r.public_exec is False


def test_prune_audit_log_refuses_recent_cutoffs(connection: Connection) -> None:
    now = datetime.now(UTC)
    old, recent = now - timedelta(days=400), now - timedelta(days=10)
    for when in (old, recent):
        connection.execute(
            text(
                "INSERT INTO audit_log (occurred_at, actor_type, actor_label, action, outcome) "
                "VALUES (:t, 'system', 'system', 'test.prune', 'success')"
            ),
            {"t": when},
        )
    with (
        pytest.raises(Exception, match="newer than the minimum retention"),
        connection.begin_nested(),
    ):
        connection.execute(text("SELECT prune_audit_log(:c)"), {"c": now - timedelta(days=30)})
    deleted = connection.execute(
        text("SELECT prune_audit_log(:c)"), {"c": now - timedelta(days=365)}
    ).scalar_one()
    assert deleted >= 1
    remaining = connection.execute(
        text("SELECT occurred_at FROM audit_log WHERE action = 'test.prune'")
    ).scalars()
    assert [t.date() for t in remaining] == [recent.date()]


def test_grant_statements_quote_identifiers() -> None:
    stmts = db_roles.grant_statements("cti_app", "cti")
    rendered = [repr(s) for s in stmts]
    assert any("REVOKE UPDATE, DELETE, TRUNCATE ON" in r and "audit_log" in r for r in rendered)
    assert any("REVOKE CREATE ON SCHEMA public" in r for r in rendered)
    assert any("prune_audit_log(timestamptz)" in r for r in rendered)


def test_grant_refuses_unsafe_or_missing_roles(engine: object) -> None:
    url = require_db()
    with pytest.raises(db_roles.RoleSetupError, match="invalid role name"):
        db_roles.grant_app_role(url, "Bad-Name; drop")
    with pytest.raises(db_roles.RoleSetupError, match="does not exist"):
        db_roles.grant_app_role(url, f"cti_missing_{uuid.uuid4().hex[:8]}")
    with psycopg.connect(_libpq(url)) as conn:
        row = conn.execute("SELECT current_user").fetchone()
    assert row is not None
    with pytest.raises(db_roles.RoleSetupError, match="must differ from the schema owner"):
        db_roles.grant_app_role(url, str(row[0]))


@pytest.fixture
def app_role(engine: object) -> Iterator[tuple[str, str]]:
    """A temporary login role; needs CREATEROLE on the test connection's role."""
    url = require_db()
    with psycopg.connect(_libpq(url), autocommit=True) as conn:
        can = conn.execute(
            "SELECT rolcreaterole OR rolsuper FROM pg_roles WHERE rolname = current_user"
        ).fetchone()
        if not (can and can[0]):
            pytest.skip("the test database role lacks CREATEROLE; end-to-end role test not run")
        name, password = f"cti_app_test_{uuid.uuid4().hex[:8]}", secrets.token_urlsafe(24)
        conn.execute(
            psycopg.sql.SQL("CREATE ROLE {} LOGIN PASSWORD {}").format(
                psycopg.sql.Identifier(name), psycopg.sql.Literal(password)
            )
        )
        try:
            yield name, password
        finally:
            db = conn.execute("SELECT current_database()").fetchone()
            assert db is not None
            conn.execute(psycopg.sql.SQL("DROP OWNED BY {}").format(psycopg.sql.Identifier(name)))
            conn.execute(psycopg.sql.SQL("DROP ROLE {}").format(psycopg.sql.Identifier(name)))


def test_app_role_is_dml_only_end_to_end(app_role: tuple[str, str]) -> None:
    name, password = app_role
    owner_url = require_db()
    report = db_roles.grant_app_role(owner_url, name)
    assert report.problems == [], report.as_dict()
    info = psycopg.conninfo.conninfo_to_dict(_libpq(owner_url))
    info.update(user=name, password=password)
    with psycopg.connect(**info) as conn:
        conn.execute("SELECT count(*) FROM fact_security_event")
        # Partition creation works through the SECURITY DEFINER function.
        conn.execute("SELECT ensure_event_partitions(%s, %s)", ("2031-01-01", "2031-01-02"))
        conn.execute(
            "INSERT INTO audit_log (actor_type, actor_label, action, outcome) "
            "VALUES ('system', 'system', 'test.role', 'success')"
        )
        for forbidden in (
            "CREATE TABLE not_allowed (id int)",
            "UPDATE audit_log SET action = 'x' WHERE action = 'test.role'",
            "DELETE FROM audit_log WHERE action = 'test.role'",
            "DELETE FROM alembic_version",
            "DROP TABLE dim_source",
        ):
            with pytest.raises(psycopg.errors.InsufficientPrivilege), conn.transaction():
                conn.execute(forbidden)  # type: ignore[arg-type]
        conn.rollback()
