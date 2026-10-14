"""Monthly partitioning of fact_security_event (DATABASE_DESIGN.md §7)."""

from __future__ import annotations

import pytest
from sqlalchemy import Connection, text

pytestmark = pytest.mark.integration


def _partitions(conn: Connection) -> set[str]:
    rows = conn.execute(
        text(
            "SELECT inhrelid::regclass::text FROM pg_inherits "
            "WHERE inhparent = 'fact_security_event'::regclass"
        )
    )
    return {r[0] for r in rows}


def _ensure(conn: Connection, start: str, end: str) -> int:
    return int(
        conn.execute(
            text(
                "SELECT ensure_event_partitions(CAST(:a AS timestamptz), CAST(:b AS timestamptz))"
            ),
            {"a": start, "b": end},
        ).scalar_one()
    )


def test_default_partition_exists(connection: Connection) -> None:
    assert "fact_security_event_default" in _partitions(connection)


def test_creates_missing_utc_months_once(connection: Connection) -> None:
    assert _ensure(connection, "2015-01-22T00:00:00Z", "2015-03-01T00:00:00Z") == 3
    assert {
        "fact_security_event_y2015m01",
        "fact_security_event_y2015m02",
        "fact_security_event_y2015m03",
    } <= _partitions(connection)
    assert _ensure(connection, "2015-02-10T00:00:00Z", "2015-02-11T00:00:00Z") == 0


def test_month_boundaries_are_utc(connection: Connection) -> None:
    # 2017-07-31T23:30-02:00 is 2017-08-01T01:30Z: it belongs to the August partition.
    _ensure(connection, "2017-07-31T23:30:00-02:00", "2017-07-31T23:30:00-02:00")
    assert "fact_security_event_y2017m08" in _partitions(connection)


def test_rejects_inverted_range(connection: Connection) -> None:
    with pytest.raises(Exception, match="invalid range"):
        _ensure(connection, "2020-02-01T00:00:00Z", "2020-01-01T00:00:00Z")
