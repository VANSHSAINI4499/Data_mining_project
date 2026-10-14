"""Fixtures shared by integration tests."""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.services.actors import CLI_ACTOR
from app.services.reference import seed_reference


@pytest.fixture
def import_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(get_settings(), "import_root", tmp_path)
    return tmp_path


@pytest.fixture
def seeded(db: Session) -> Session:
    seed_reference(db, CLI_ACTOR)
    return db
