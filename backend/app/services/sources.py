"""Data source management (API_SPECIFICATION.md §5.4)."""

from __future__ import annotations

from typing import Any

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.errors import ConflictError, FieldError, NotFoundError, ValidationFailedError
from app.ingestion.adapters import get_adapter_class
from app.models import DimSource, FactSecurityEvent, IngestionBatch
from app.models.warehouse import RELIABILITY, SOURCE_TYPES
from app.services import audit
from app.services.actors import Actor
from app.services.reference import validate_timezone

MUTABLE = ("name", "default_adapter", "default_timezone", "reliability", "description", "is_active")


def _validate(values: dict[str, Any]) -> None:
    problems: list[FieldError] = []
    if "source_type" in values and values["source_type"] not in SOURCE_TYPES:
        problems.append(FieldError("source_type", "invalid_choice", f"one of {list(SOURCE_TYPES)}"))
    if values.get("reliability") is not None and values["reliability"] not in RELIABILITY:
        problems.append(FieldError("reliability", "invalid_choice", "A-F"))
    adapter = values.get("default_adapter")
    if adapter is not None and get_adapter_class(adapter) is None:
        problems.append(FieldError("default_adapter", "unknown_adapter", adapter[:50]))
    tz = values.get("default_timezone")
    if tz is not None:
        try:
            validate_timezone(tz)
        except ValidationFailedError:
            problems.append(FieldError("default_timezone", "unknown_timezone", "IANA name"))
    if problems:
        raise ValidationFailedError("invalid source", errors=problems)


def list_sources(session: Session) -> list[DimSource]:
    with session.begin():
        rows = list(session.scalars(select(DimSource).order_by(DimSource.source_key)))
        for r in rows:
            session.expunge(r)
        return rows


def get_source(session: Session, source_id: int) -> tuple[DimSource, dict[str, int]]:
    with session.begin():
        source = session.get(DimSource, source_id)
        if source is None:
            raise NotFoundError(f"source {source_id} not found")
        batches = session.scalar(
            select(func.count())
            .select_from(IngestionBatch)
            .where(IngestionBatch.source_id == source_id)
        )
        events = session.scalar(
            select(func.count())
            .select_from(FactSecurityEvent)
            .where(FactSecurityEvent.source_id == source_id)
        )
        session.expunge(source)
        return source, {"batches": int(batches or 0), "events": int(events or 0)}


def create_source(session: Session, actor: Actor, values: dict[str, Any]) -> DimSource:
    _validate(values)
    try:
        with session.begin():
            source = DimSource(**values)
            session.add(source)
            session.flush()
            audit.record(
                session,
                actor,
                "source.create",
                target_type="dim_source",
                target_id=source.source_id,
                details={"source_key": source.source_key},
            )
            session.expunge(source)
            return source
    except IntegrityError as exc:
        raise ConflictError(
            f"source {values.get('source_key')!r} already exists or is invalid"
        ) from exc


def update_source(
    session: Session, actor: Actor, source_id: int, values: dict[str, Any]
) -> DimSource:
    _validate(values)
    with session.begin():
        source = session.get(DimSource, source_id, with_for_update=True)
        if source is None:
            raise NotFoundError(f"source {source_id} not found")
        changes = {}
        for key, value in values.items():
            if key in MUTABLE and getattr(source, key) != value:
                changes[key] = {"old": getattr(source, key), "new": value}
                setattr(source, key, value)
        if changes:
            audit.record(
                session,
                actor,
                "source.update",
                target_type="dim_source",
                target_id=source_id,
                details={"changes": changes},
            )
        session.flush()
        session.expunge(source)
        return source
