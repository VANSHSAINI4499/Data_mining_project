"""Asset inventory import (SCD Type 2) and listing (DATA_INGESTION.md §4.8).

The first known version of an asset is assumed valid from 2000-01-01 (the start of the
warehouse calendar) so that historical events can be linked to it; later changes close the
current version and open a new one at import time. This assumption is recorded in the import
result and in the documentation.
"""

from __future__ import annotations

import io
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core import clock
from app.core.errors import FieldError, ValidationFailedError
from app.core.pagination import DEFAULT_LIMIT, decode_cursor, encode_cursor
from app.ingestion.errors import BatchFatalError
from app.ingestion.normalize import FieldError as NormalizeFieldError
from app.ingestion.normalize import clean_text, is_missing, parse_ip
from app.ingestion.readers import DelimitedReader, ReadStats
from app.models import DimAsset
from app.services import audit
from app.services.actors import Actor

HISTORY_START = datetime(2000, 1, 1, tzinfo=UTC)
CRITICALITY = frozenset({"low", "medium", "high", "critical", "unknown"})
TRACKED = ("hostname", "ip_address", "criticality", "owner", "environment")
MAX_ASSET_ROWS = 100_000


@dataclass
class AssetImportResult:
    created: int = 0
    updated: int = 0
    unchanged: int = 0
    rejected: list[dict[str, Any]] = field(default_factory=list)


def _parse_row(row: dict[str, str]) -> dict[str, Any]:
    asset_id = (row.get("asset_id") or "").strip()
    if not asset_id or len(asset_id) > 128:
        raise ValueError("asset_id is required (max 128 characters)")
    ip = row.get("ip_address")
    try:
        ip_value = None if is_missing(ip) else parse_ip(ip)
    except NormalizeFieldError as exc:
        raise ValueError(exc.detail) from exc
    criticality = (row.get("criticality") or "unknown").strip().lower() or "unknown"
    if criticality not in CRITICALITY:
        raise ValueError(f"criticality must be one of {sorted(CRITICALITY)}")

    def text(name: str, limit: int) -> str | None:
        value = row.get(name)
        return None if is_missing(value) else clean_text(value, limit, strip_controls=True)[0]

    return {
        "asset_id": asset_id,
        "hostname": (text("hostname", 255) or "").lower() or None,
        "ip_address": ip_value,
        "criticality": criticality,
        "owner": text("owner", 255),
        "environment": text("environment", 64),
    }


def import_assets_csv(session: Session, actor: Actor, data: bytes) -> AssetImportResult:
    reader = DelimitedReader(io.BytesIO(data), ("utf-8",), ReadStats())
    try:
        columns = reader.read_header()
    except BatchFatalError as exc:
        raise ValidationFailedError(exc.detail) from exc
    if "asset_id" not in columns:
        raise ValidationFailedError(
            "asset inventory CSV needs an asset_id column",
            errors=[FieldError("file", "missing_column", "asset_id")],
        )
    result = AssetImportResult()
    now = clock.now()
    with session.begin():
        for raw in reader.records():
            if raw.record_number > MAX_ASSET_ROWS:
                raise ValidationFailedError(f"more than {MAX_ASSET_ROWS} rows")
            if raw.problem is not None or not isinstance(raw.payload, dict):
                result.rejected.append(
                    {
                        "row": raw.record_number,
                        "reason": raw.problem.code if raw.problem else "invalid",
                    }
                )
                continue
            try:
                values = _parse_row(raw.payload)
            except ValueError as exc:
                result.rejected.append({"row": raw.record_number, "reason": str(exc)[:200]})
                continue
            current = session.scalar(
                select(DimAsset)
                .where(DimAsset.asset_id == values["asset_id"], DimAsset.is_current.is_(True))
                .with_for_update()
            )
            if current is None:
                session.add(DimAsset(**values, valid_from=HISTORY_START, is_current=True))
                result.created += 1
                continue
            existing = {k: getattr(current, k) for k in TRACKED}
            existing["ip_address"] = (
                str(existing["ip_address"]).split("/")[0] if existing["ip_address"] else None
            )
            if existing == {k: values[k] for k in TRACKED}:
                result.unchanged += 1
                continue
            current.valid_to = now
            current.is_current = False
            session.flush()
            session.add(DimAsset(**values, valid_from=now, is_current=True))
            result.updated += 1
        session.flush()
        audit.record(
            session,
            actor,
            "assets.import",
            details={
                "created": result.created,
                "updated": result.updated,
                "unchanged": result.unchanged,
                "rejected": len(result.rejected),
            },
        )
    return result


def list_assets(
    session: Session,
    *,
    criticality: str | None,
    q: str | None,
    cursor: str | None,
    limit: int = DEFAULT_LIMIT,
) -> tuple[list[DimAsset], str | None]:
    key = decode_cursor(cursor, frozenset({"asset_id"}))
    stmt = select(DimAsset).where(DimAsset.is_current.is_(True)).order_by(DimAsset.asset_id)
    if criticality:
        stmt = stmt.where(DimAsset.criticality == criticality)
    if q:
        prefix = q.lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        stmt = stmt.where(
            DimAsset.asset_id.ilike(prefix, escape="\\")
            | DimAsset.hostname.ilike(prefix, escape="\\")
        )
    if key:
        stmt = stmt.where(DimAsset.asset_id > key["asset_id"])
    with session.begin():
        rows = list(session.scalars(stmt.limit(limit + 1)))
        for r in rows:
            session.expunge(r)
    items = rows[:limit]
    nxt = encode_cursor({"asset_id": items[-1].asset_id}) if len(rows) > limit else None
    return items, nxt
