"""Read-only audit history (API_SPECIFICATION.md §5.18). There is no write or delete path here."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.core.pagination import decode_cursor, encode_cursor
from app.models import AppUser, AuditLog

CURSOR_KEYS = frozenset({"id"})


def list_records(
    session: Session,
    *,
    actor_user_id: uuid.UUID | None,
    action: str | None,
    target_type: str | None,
    target_id: str | None,
    outcome: str | None,
    start: datetime | None,
    end: datetime | None,
    cursor: str | None,
    limit: int,
) -> dict[str, Any]:
    after = decode_cursor(cursor, CURSOR_KEYS)
    stmt = select(AuditLog, AppUser.username).outerjoin(
        AppUser, AppUser.user_id == AuditLog.actor_user_id
    )
    conds = []
    if actor_user_id is not None:
        conds.append(AuditLog.actor_user_id == actor_user_id)
    if action:
        # Exact action, or a prefix such as "alert." to see a whole family.
        conds.append(
            or_(AuditLog.action == action, AuditLog.action.startswith(action))
            if action.endswith(".")
            else AuditLog.action == action
        )
    if target_type:
        conds.append(AuditLog.target_type == target_type)
    if target_id:
        conds.append(AuditLog.target_id == target_id)
    if outcome:
        conds.append(AuditLog.outcome == outcome)
    if start is not None:
        conds.append(AuditLog.occurred_at >= start)
    if end is not None:
        conds.append(AuditLog.occurred_at < end)
    if after is not None:
        conds.append(AuditLog.audit_id < int(after["id"]))
    with session.begin():
        rows = session.execute(
            stmt.where(*conds).order_by(AuditLog.audit_id.desc()).limit(limit + 1)
        ).all()
        actions = list(
            session.scalars(select(AuditLog.action).distinct().order_by(AuditLog.action))
        )
    items = [
        {
            "audit_id": a.audit_id,
            "occurred_at": a.occurred_at,
            "actor_type": a.actor_type,
            "actor_user_id": a.actor_user_id,
            "actor": username or a.actor_label,
            "action": a.action,
            "target_type": a.target_type,
            "target_id": a.target_id,
            "outcome": a.outcome,
            "request_id": a.request_id,
            "ip_address": str(a.ip_address) if a.ip_address is not None else None,
            "details": a.details,
        }
        for a, username in rows[:limit]
    ]
    next_cursor = encode_cursor({"id": rows[limit - 1][0].audit_id}) if len(rows) > limit else None
    return {"items": items, "next_cursor": next_cursor, "limit": limit, "known_actions": actions}
