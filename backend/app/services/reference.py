"""Reference data seeding from versioned TOML in ``config/reference`` (``cti seed-reference``)."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from sqlalchemy.orm import Session

from app.core.config import REPO_ROOT
from app.core.errors import ValidationFailedError
from app.repositories import reference as reference_repo
from app.services import audit
from app.services.actors import Actor

REFERENCE_DIR = REPO_ROOT / "config" / "reference"


@dataclass(frozen=True)
class SeedResult:
    categories_created: int
    categories_updated: int
    sources_created: int
    sources_existing: int


def _load(path: Path) -> dict[str, Any]:
    with path.open("rb") as fh:
        return tomllib.load(fh)


def validate_timezone(name: str) -> str:
    try:
        ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise ValidationFailedError(f"unknown IANA timezone {name!r}") from exc
    return name


def seed_reference(
    session: Session, actor: Actor, reference_dir: Path = REFERENCE_DIR
) -> SeedResult:
    categories = _load(reference_dir / "attack_categories.toml")["category"]
    sources = _load(reference_dir / "sources.toml")["source"]
    for src in sources:
        if src.get("default_timezone"):
            validate_timezone(src["default_timezone"])

    with session.begin():
        cat_created = cat_updated = 0
        for cat in categories:
            created, updated = reference_repo.upsert_attack_category(
                session,
                attack_category_id=int(cat["id"]),
                code=cat["code"],
                name=cat["name"],
                description=cat["description"],
                is_benign=bool(cat["is_benign"]),
                severity_weight=Decimal(str(cat["severity_weight"])),
            )
            cat_created += created
            cat_updated += updated
        src_created = src_existing = 0
        for src in sources:
            if reference_repo.insert_source_if_missing(session, **src):
                src_created += 1
            else:
                src_existing += 1
        result = SeedResult(cat_created, cat_updated, src_created, src_existing)
        audit.record(session, actor, "reference.seed", details=result.__dict__)
    return result
