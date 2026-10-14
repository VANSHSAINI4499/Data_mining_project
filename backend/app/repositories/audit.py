"""Append-only writes to audit_log (reads arrive with the audit API in a later phase)."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy.orm import Session

from app.models import AuditLog


def add_audit_record(
    session: Session,
    *,
    actor_type: str,
    actor_user_id: uuid.UUID | None,
    actor_label: str | None,
    action: str,
    outcome: str,
    target_type: str | None,
    target_id: str | None,
    request_id: str | None,
    ip_address: str | None,
    details: dict[str, Any],
) -> AuditLog:
    record = AuditLog(
        actor_type=actor_type,
        actor_user_id=actor_user_id,
        actor_label=actor_label,
        action=action,
        outcome=outcome,
        target_type=target_type,
        target_id=target_id,
        request_id=request_id,
        ip_address=ip_address,
        details=details,
    )
    session.add(record)
    return record
