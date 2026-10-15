"""Reference data seeding (AC-2.1)."""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.errors import ValidationFailedError
from app.models import AuditLog, DimAttackCategory, DimSource
from app.services.actors import CLI_ACTOR
from app.services.reference import REFERENCE_DIR, seed_reference

pytestmark = pytest.mark.integration

EXPECTED_CODES = {
    "BENIGN",
    "DOS",
    "DDOS",
    "RECONNAISSANCE",
    "BRUTE_FORCE",
    "WEB_ATTACK",
    "BOTNET",
    "INFILTRATION",
    "EXPLOIT",
    "BACKDOOR",
    "SHELLCODE",
    "WORM",
    "FUZZING",
    "ANALYSIS",
    "GENERIC",
    "OTHER_MALICIOUS",
}


def test_seed_creates_taxonomy_and_sources(db: Session) -> None:
    result = seed_reference(db, CLI_ACTOR)
    assert result.categories_created == 16 and result.sources_created == 4
    codes = set(db.scalars(select(DimAttackCategory.code)))
    assert codes == EXPECTED_CODES
    benign = db.scalar(select(DimAttackCategory).where(DimAttackCategory.code == "BENIGN"))
    assert benign is not None and benign.is_benign and benign.attack_category_id == 1
    cic = db.scalar(select(DimSource).where(DimSource.source_key == "cicids2017"))
    assert cic is not None and cic.default_timezone is None  # must be configured by a user
    assert db.scalar(select(func.count()).where(AuditLog.action == "reference.seed")) == 1


def test_seed_is_idempotent_and_preserves_user_edits(db: Session) -> None:
    seed_reference(db, CLI_ACTOR)
    with db.begin():
        src = db.scalar(select(DimSource).where(DimSource.source_key == "cicids2017"))
        assert src is not None
        src.default_timezone = "America/Halifax"
    again = seed_reference(db, CLI_ACTOR)
    assert (again.categories_created, again.categories_updated) == (0, 0)
    assert (again.sources_created, again.sources_existing) == (0, 4)
    assert db.scalar(select(func.count()).select_from(DimAttackCategory)) == 16
    src = db.scalar(select(DimSource).where(DimSource.source_key == "cicids2017"))
    assert src is not None and src.default_timezone == "America/Halifax"


def test_invalid_timezone_in_config_is_rejected(db: Session, tmp_path: Path) -> None:
    (tmp_path / "attack_categories.toml").write_text(
        (REFERENCE_DIR / "attack_categories.toml").read_text(encoding="utf-8"), encoding="utf-8"
    )
    (tmp_path / "sources.toml").write_text(
        'version = 1\n[[source]]\nsource_key = "x1"\nname = "x"\nsource_type = "other"\n'
        'default_timezone = "Mars/Olympus"\n',
        encoding="utf-8",
    )
    with pytest.raises(ValidationFailedError, match="timezone"):
        seed_reference(db, CLI_ACTOR, tmp_path)
