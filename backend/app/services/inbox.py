"""Inbox-folder ingestion for ``cti watch`` (Phase 8).

Files dropped into the inbox (inside ``CTI_IMPORT_ROOT``) are imported once: after
processing, each file moves to ``processed/`` or ``failed/`` next to it, so a later poll does
not see it again. Re-importing identical content is still caught by the file-hash duplicate
check of the ingestion pipeline.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings
from app.core.errors import DomainError, ValidationFailedError
from app.models import IngestionBatch
from app.services import data_quality
from app.services.actors import Actor
from app.services.ingestion import BatchOptions, create_cli_batch, process_batch

SKIP_SUFFIXES = (".part", ".tmp", ".crdownload")


@dataclass
class InboxResult:
    file: str
    status: str
    batch_id: str | None
    detail: dict[str, Any]


def _resolve_inbox(settings: Settings, inbox: Path) -> Path:
    root = settings.import_root.resolve()
    path = (inbox if inbox.is_absolute() else Path.cwd() / inbox).resolve()
    if not path.is_relative_to(root):
        raise ValidationFailedError(f"inbox must be inside the import root {root}")
    path.mkdir(parents=True, exist_ok=True)
    return path


def _move(path: Path, folder: str) -> Path:
    target_dir = path.parent / folder
    target_dir.mkdir(exist_ok=True)
    target = target_dir / path.name
    counter = 1
    while target.exists():
        target = target_dir / f"{path.stem}.{counter}{path.suffix}"
        counter += 1
    shutil.move(str(path), str(target))
    return target


def _record_move(factory: sessionmaker[Session], batch_id: Any, target: Path) -> None:
    # Keep the batch pointing at the file's new location so a failed batch can be retried.
    with factory() as session, session.begin():
        batch = session.get(IngestionBatch, batch_id, with_for_update=True)
        if batch is not None:
            batch.stored_path = str(target)


def poll_once(
    factory: sessionmaker[Session],
    settings: Settings,
    actor: Actor,
    inbox: Path,
    *,
    source_key: str,
    adapter: str | None,
) -> list[InboxResult]:
    folder = _resolve_inbox(settings, inbox)
    results: list[InboxResult] = []
    files = sorted(
        p
        for p in folder.iterdir()
        if p.is_file() and not p.name.startswith(".") and p.suffix.lower() not in SKIP_SUFFIXES
    )
    for path in files:
        try:
            with factory() as session:
                batch, duplicate = create_cli_batch(
                    session,
                    settings,
                    actor,
                    source_key=source_key,
                    adapter_name=adapter,
                    path=path,
                    options=BatchOptions(),
                )
            if duplicate:
                _record_move(factory, batch.batch_id, _move(path, "processed"))
                results.append(
                    InboxResult(
                        path.name,
                        "duplicate",
                        str(batch.batch_id),
                        {"duplicate_of": str(batch.duplicate_of)},
                    )
                )
                continue
            outcome = process_batch(
                factory, settings, batch.batch_id, on_complete=data_quality.run_checks
            )
            moved = _move(path, "failed" if outcome.status == "failed" else "processed")
            _record_move(factory, outcome.batch_id, moved)
            results.append(
                InboxResult(
                    path.name,
                    outcome.status,
                    str(outcome.batch_id),
                    {"records_loaded": outcome.records_loaded, "moved_to": moved.parent.name},
                )
            )
        except DomainError as exc:
            _move(path, "failed")
            results.append(InboxResult(path.name, "rejected", None, {"error": exc.detail}))
    return results
