"""Audit trail helper (SECURITY_REQUIREMENTS.md §7).

``record`` must be called inside the caller's transaction so the audit row commits or rolls
back together with the change it describes. ``record_standalone`` is for events that are not
part of a state change (e.g., an authorization denial).
"""

from __future__ import annotations

from typing import Any, Literal

from sqlalchemy.orm import Session

from app.core.logging import client_ip_var, request_id_var
from app.repositories import audit as audit_repo
from app.services.actors import Actor

Outcome = Literal["success", "denied", "error"]


def record(
    session: Session,
    actor: Actor,
    action: str,
    *,
    outcome: Outcome = "success",
    target_type: str | None = None,
    target_id: object | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    audit_repo.add_audit_record(
        session,
        actor_type=actor.actor_type,
        actor_user_id=actor.user_id,
        actor_label=actor.label,
        action=action,
        outcome=outcome,
        target_type=target_type,
        target_id=None if target_id is None else str(target_id),
        request_id=request_id_var.get(),
        ip_address=client_ip_var.get(),
        details=details or {},
    )


def record_standalone(
    session: Session,
    actor: Actor,
    action: str,
    *,
    outcome: Outcome,
    target_type: str | None = None,
    target_id: object | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    with session.begin():
        record(
            session,
            actor,
            action,
            outcome=outcome,
            target_type=target_type,
            target_id=target_id,
            details=details,
        )
