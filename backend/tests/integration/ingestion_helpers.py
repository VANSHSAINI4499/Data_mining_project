"""Shared helpers for ingestion integration tests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings
from app.models import DimSource, FactSecurityEvent
from app.services import data_quality
from app.services.actors import CLI_ACTOR
from app.services.ingestion import BatchOptions, BatchOutcome, create_cli_batch, process_batch


def write_jsonl(path: Path, rows: list[dict[str, Any] | str]) -> Path:
    lines = [r if isinstance(r, str) else json.dumps(r) for r in rows]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def add_source(session: Session, key: str, adapter: str, timezone: str | None = "UTC") -> int:
    with session.begin():
        source = DimSource(
            source_key=key,
            name=key,
            source_type="other",
            default_adapter=adapter,
            default_timezone=timezone,
        )
        session.add(source)
        session.flush()
        return source.source_id


def ingest(
    factory: sessionmaker[Session],
    path: Path,
    source_key: str,
    adapter: str | None = None,
    options: BatchOptions | None = None,
) -> BatchOutcome:
    settings = get_settings()
    with factory() as session:
        batch, duplicate = create_cli_batch(
            session,
            settings,
            CLI_ACTOR,
            source_key=source_key,
            adapter_name=adapter,
            path=path,
            options=options or BatchOptions(),
        )
    if duplicate:
        return BatchOutcome(batch.batch_id, "duplicate", 0, 0, 0, 0)
    return process_batch(factory, settings, batch.batch_id, on_complete=data_quality.run_checks)


def event_count(session: Session, **filters: Any) -> int:
    stmt = select(func.count()).select_from(FactSecurityEvent)
    for name, value in filters.items():
        stmt = stmt.where(getattr(FactSecurityEvent, name) == value)
    with session.begin():
        return int(session.scalar(stmt) or 0)
