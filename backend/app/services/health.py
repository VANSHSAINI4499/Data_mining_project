"""Readiness checks (API_SPECIFICATION.md §5.1). Outputs never include secrets or URLs."""

from __future__ import annotations

import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.config import Settings

ALEMBIC_INI = Path(__file__).resolve().parents[2] / "alembic.ini"


@dataclass
class Readiness:
    ready: bool
    checks: dict[str, dict[str, Any]] = field(default_factory=dict)


def expected_heads() -> set[str]:
    return set(ScriptDirectory.from_config(Config(str(ALEMBIC_INI))).get_heads())


def _check_dir(path: Path) -> dict[str, Any]:
    try:
        path.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=path, prefix=".ready-", delete=True):
            pass
    except OSError as exc:
        return {"status": "fail", "detail": f"not writable ({exc.__class__.__name__})"}
    return {"status": "ok"}


def check_readiness(session: Session, settings: Settings) -> Readiness:
    checks: dict[str, dict[str, Any]] = {}
    current: set[str] = set()
    try:
        with session.begin():
            session.execute(text("SELECT 1"))
            checks["database"] = {"status": "ok"}
            has_table = session.execute(text("SELECT to_regclass('alembic_version') IS NOT NULL"))
            if has_table.scalar_one():
                current = set(session.scalars(text("SELECT version_num FROM alembic_version")))
    except SQLAlchemyError as exc:
        checks["database"] = {"status": "fail", "detail": f"unreachable ({exc.__class__.__name__})"}

    if checks["database"]["status"] == "ok":
        heads = expected_heads()
        if current == heads:
            checks["migrations"] = {"status": "ok", "revision": sorted(current)}
        else:
            checks["migrations"] = {
                "status": "fail",
                "detail": "migrations_behind",
                "current": sorted(current),
                "expected": sorted(heads),
            }
    else:
        checks["migrations"] = {"status": "unknown", "detail": "database unavailable"}

    checks["upload_dir"] = _check_dir(settings.upload_dir)
    checks["artifact_dir"] = _check_dir(settings.artifact_dir)
    return Readiness(all(c["status"] == "ok" for c in checks.values()), checks)
