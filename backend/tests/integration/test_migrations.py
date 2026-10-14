"""Migration tests (TESTING_STRATEGY.md §5) on a dedicated scratch database."""

from __future__ import annotations

import datetime as dt
from collections.abc import Iterator

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import Engine, create_engine, inspect, text
from sqlalchemy.engine import make_url

from app.models import Base
from app.models.autogen import include_name, include_object
from tests.conftest import alembic_config, require_db

pytestmark = pytest.mark.integration

EXPECTED_TABLES = {
    "app_user",
    "auth_session",
    "audit_log",
    "job",
    "dim_date",
    "alembic_version",
    "dim_source",
    "dim_asset",
    "dim_attack_category",
    "ingestion_batch",
    "raw_record",
    "rejected_record",
    "fact_security_event",
    "fact_security_event_default",
    "event_ground_truth",
    "data_quality_result",
}


@pytest.fixture(scope="module")
def scratch_url() -> Iterator[str]:
    base = make_url(require_db())
    name = f"{base.database}_migrations"
    admin = create_engine(base.set(database="postgres"), isolation_level="AUTOCOMMIT")
    with admin.connect() as conn:
        conn.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        conn.execute(text(f'CREATE DATABASE "{name}"'))
    url = base.set(database=name).render_as_string(hide_password=False)
    try:
        yield url
    finally:
        with admin.connect() as conn:
            conn.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        admin.dispose()


@pytest.fixture
def scratch_engine(scratch_url: str) -> Iterator[Engine]:
    eng = create_engine(scratch_url)
    yield eng
    eng.dispose()


def _tables(engine: Engine) -> set[str]:
    return set(inspect(engine).get_table_names())


def test_upgrade_from_empty_creates_baseline_tables(
    scratch_url: str, scratch_engine: Engine
) -> None:
    command.downgrade(alembic_config(scratch_url), "base")
    command.upgrade(alembic_config(scratch_url), "head")
    assert _tables(scratch_engine) >= EXPECTED_TABLES


def test_downgrade_to_base_and_upgrade_again(scratch_url: str, scratch_engine: Engine) -> None:
    cfg = alembic_config(scratch_url)
    command.upgrade(cfg, "head")
    command.downgrade(cfg, "base")
    assert _tables(scratch_engine) <= {"alembic_version"}
    with scratch_engine.connect() as conn:
        leftovers = conn.execute(
            text("SELECT count(*) FROM pg_proc WHERE proname = 'ensure_event_partitions'")
        ).scalar_one()
        seq = conn.execute(
            text("SELECT to_regclass('fact_security_event_event_id_seq')")
        ).scalar_one()
    assert leftovers == 0 and seq is None
    command.upgrade(cfg, "head")
    assert _tables(scratch_engine) >= EXPECTED_TABLES


def test_models_match_migrated_schema(scratch_url: str, scratch_engine: Engine) -> None:
    command.upgrade(alembic_config(scratch_url), "head")
    with scratch_engine.connect() as conn:
        ctx = MigrationContext.configure(
            conn,
            opts={
                "compare_type": True,
                "include_name": include_name,
                "include_object": include_object,
            },
        )
        diff = compare_metadata(ctx, Base.metadata)
    assert diff == []


def test_dim_date_is_seeded(scratch_url: str, scratch_engine: Engine) -> None:
    command.upgrade(alembic_config(scratch_url), "head")
    expected_days = (dt.date(2040, 12, 31) - dt.date(2000, 1, 1)).days + 1
    with scratch_engine.connect() as conn:
        count = conn.execute(text("SELECT count(*) FROM dim_date")).scalar_one()
        row = conn.execute(
            text(
                "SELECT date_key, day_of_week, is_weekend FROM dim_date "
                "WHERE calendar_date = DATE '2026-10-17'"
            )
        ).one()
    assert count == expected_days
    assert tuple(row) == (20261017, 6, True)  # a Saturday


def test_data_survives_upgrade_from_previous_head(scratch_url: str, scratch_engine: Engine) -> None:
    # With a single revision the "previous head" is the baseline itself; this test exercises the
    # pattern so later revisions extend it with real data checks.
    cfg = alembic_config(scratch_url)
    command.upgrade(cfg, "head")
    with scratch_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO app_user (user_id, username, password_hash, role) "
                "VALUES (gen_random_uuid(), 'survivor', 'x', 'viewer')"
            )
        )
    command.upgrade(cfg, "head")
    with scratch_engine.connect() as conn:
        assert (
            conn.execute(
                text("SELECT count(*) FROM app_user WHERE username = 'survivor'")
            ).scalar_one()
            == 1
        )
