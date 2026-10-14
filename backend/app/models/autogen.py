"""Autogenerate/drift-check filters shared by migrations/env.py and the migration tests.

Some database objects are deliberately managed outside the ORM metadata and must not show up
as drift: monthly partitions of ``fact_security_event`` (created at runtime by the
``ensure_event_partitions`` SQL function) and the internal per-partition foreign keys
PostgreSQL creates for a foreign key that references a partitioned table.
"""

from __future__ import annotations


def include_name(name: str | None, type_: str, parent_names: object) -> bool:
    """Exclude objects managed outside the ORM metadata from autogenerate comparisons.

    Monthly partitions of fact_security_event are created at runtime by
    ensure_event_partitions(); they are not separate ORM tables.
    """
    is_partition = type_ == "table" and bool(name) and str(name).startswith("fact_security_event_")
    return not is_partition


def include_object(
    obj: object, name: str | None, type_: str, reflected: bool, compare_to: object
) -> bool:
    """PostgreSQL implements a foreign key that references a partitioned table with internal
    per-partition constraints; reflection reports those, but they are not separate objects."""
    if type_ == "foreign_key_constraint" and reflected:
        referred = getattr(getattr(obj, "referred_table", None), "name", "")
        if str(referred).startswith("fact_security_event_"):
            return False
    return True
