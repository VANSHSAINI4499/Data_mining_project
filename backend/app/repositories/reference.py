"""Queries for reference dimensions (attack categories, sources)."""

from __future__ import annotations

from decimal import Decimal

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.models import DimAttackCategory, DimSource


def upsert_attack_category(
    session: Session,
    *,
    attack_category_id: int,
    code: str,
    name: str,
    description: str,
    is_benign: bool,
    severity_weight: Decimal,
) -> tuple[int, int]:
    """Insert or update by id. Returns (created, updated) as 0/1."""
    existing = session.get(DimAttackCategory, attack_category_id)
    if existing is None:
        session.add(
            DimAttackCategory(
                attack_category_id=attack_category_id,
                code=code,
                name=name,
                description=description,
                is_benign=is_benign,
                severity_weight=severity_weight,
            )
        )
        session.flush()
        return 1, 0
    changed = (
        existing.code,
        existing.name,
        existing.description,
        existing.is_benign,
        existing.severity_weight,
    ) != (code, name, description, is_benign, severity_weight)
    if changed:
        existing.code, existing.name, existing.description = code, name, description
        existing.is_benign, existing.severity_weight = is_benign, severity_weight
    return 0, int(changed)


def insert_source_if_missing(session: Session, **values: object) -> bool:
    stmt = (
        insert(DimSource)
        .values(**values)
        .on_conflict_do_nothing(index_elements=["source_key"])
        .returning(DimSource.source_id)
    )
    return session.execute(stmt).first() is not None


def list_categories(session: Session) -> list[DimAttackCategory]:
    return list(
        session.scalars(select(DimAttackCategory).order_by(DimAttackCategory.attack_category_id))
    )


def category_ids_by_code(session: Session) -> dict[str, int]:
    rows = session.execute(select(DimAttackCategory.code, DimAttackCategory.attack_category_id))
    return {code: cid for code, cid in rows}
