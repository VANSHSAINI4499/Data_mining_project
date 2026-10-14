"""Alerts, cases, and analyst feedback endpoints (API_SPECIFICATION.md §5.14-§5.15)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Query, status
from pydantic import Field

from app.api.deps import Analyst, Viewer, allow_query_params
from app.core.db import DbSession
from app.core.pagination import DEFAULT_LIMIT, MAX_LIMIT
from app.schemas.common import RequestModel
from app.services import investigations

router = APIRouter(tags=["investigations"])

AlertStatus = Literal["new", "acknowledged", "in_review", "escalated", "dismissed", "closed"]
Severity = Literal["low", "medium", "high", "critical"]
Disposition = Literal[
    "confirmed_incident", "false_positive", "benign_true_positive", "inconclusive"
]
Verdict = Literal["true_positive", "false_positive", "benign_unusual", "needs_more_info"]
TargetType = Literal["event", "classification_result", "anomaly_result", "indicator_match", "alert"]


class AlertPatch(RequestModel):
    status: Literal["acknowledged", "in_review", "dismissed"] | None = None
    assigned_to: uuid.UUID | None = None
    dismiss_reason: str | None = Field(default=None, min_length=3, max_length=1000)
    verdict: Verdict | None = None


class NewCase(RequestModel):
    title: str = Field(min_length=3, max_length=300)
    severity: Severity
    summary: str | None = Field(default=None, max_length=10_000)


class EscalateBody(RequestModel):
    case_id: uuid.UUID | None = None
    new_case: NewCase | None = None


class CasePatch(RequestModel):
    status: Literal["investigating", "closed"] | None = None
    disposition: Disposition | None = None
    title: str | None = Field(default=None, min_length=3, max_length=300)
    severity: Severity | None = None
    summary: str | None = Field(default=None, max_length=10_000)
    assigned_to: uuid.UUID | None = None


class NoteBody(RequestModel):
    body: str = Field(min_length=1, max_length=10_000)


class LinkBody(RequestModel):
    alert_id: uuid.UUID


class FeedbackBody(RequestModel):
    target_type: TargetType
    target_id: str = Field(min_length=1, max_length=64)
    verdict: Verdict
    corrected_category: str | None = Field(default=None, max_length=64)
    comment: str | None = Field(default=None, max_length=10_000)


@router.get(
    "/alerts",
    dependencies=[
        Depends(
            allow_query_params(
                "status",
                "rule_key",
                "min_risk",
                "entity_type",
                "entity_value",
                "from",
                "to",
                "assigned_to",
                "sort",
                "cursor",
                "limit",
            )
        )
    ],
)
def list_alerts(
    principal: Viewer,
    session: DbSession,
    status_: Annotated[list[AlertStatus] | None, Query(alias="status")] = None,
    rule_key: Annotated[str | None, Query(max_length=64)] = None,
    min_risk: Annotated[int | None, Query(ge=0, le=100)] = None,
    entity_type: Literal["account", "src_ip", "dst_ip", "host"] | None = None,
    entity_value: Annotated[str | None, Query(max_length=256)] = None,
    start: Annotated[datetime | None, Query(alias="from")] = None,
    end: Annotated[datetime | None, Query(alias="to")] = None,
    assigned_to: uuid.UUID | None = None,
    sort: Literal["risk_score", "last_event_time"] = "risk_score",
    cursor: Annotated[str | None, Query(max_length=20)] = None,
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = DEFAULT_LIMIT,
) -> dict[str, Any]:
    return investigations.list_alerts(
        session,
        statuses=list(status_) if status_ else None,
        rule_key=rule_key,
        min_risk=min_risk,
        entity_type=entity_type,
        entity_value=entity_value,
        start=start,
        end=end,
        assigned_to=assigned_to,
        sort=sort,
        cursor=cursor,
        limit=limit,
    )


@router.get("/alerts/{alert_id}")
def get_alert(alert_id: uuid.UUID, principal: Viewer, session: DbSession) -> dict[str, Any]:
    return investigations.get_alert(session, alert_id)


@router.patch("/alerts/{alert_id}")
def update_alert(
    alert_id: uuid.UUID, body: AlertPatch, principal: Analyst, session: DbSession
) -> dict[str, Any]:
    return investigations.update_alert(
        session,
        principal.actor,
        alert_id,
        status=body.status,
        assigned_to=body.assigned_to,
        dismiss_reason=body.dismiss_reason,
        verdict=body.verdict,
    )


@router.post("/alerts/{alert_id}/escalate")
def escalate(
    alert_id: uuid.UUID, body: EscalateBody, principal: Analyst, session: DbSession
) -> dict[str, Any]:
    return investigations.escalate(
        session,
        principal.actor,
        alert_id,
        body.case_id,
        body.new_case.model_dump() if body.new_case else None,
    )


@router.get(
    "/cases",
    dependencies=[Depends(allow_query_params("status", "disposition", "assigned_to", "limit"))],
)
def list_cases(
    principal: Viewer,
    session: DbSession,
    status_: Annotated[
        Literal["open", "investigating", "closed"] | None, Query(alias="status")
    ] = None,
    disposition: Disposition | None = None,
    assigned_to: uuid.UUID | None = None,
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = DEFAULT_LIMIT,
) -> list[dict[str, Any]]:
    return investigations.list_cases(
        session, status=status_, disposition=disposition, assigned_to=assigned_to, limit=limit
    )


@router.post("/cases", status_code=status.HTTP_201_CREATED)
def create_case(body: NewCase, principal: Analyst, session: DbSession) -> dict[str, Any]:
    case = investigations.create_case(
        session, principal.actor, body.title, body.severity, body.summary
    )
    return investigations.get_case(session, case.case_id)


@router.get("/cases/{case_id}")
def get_case(case_id: uuid.UUID, principal: Viewer, session: DbSession) -> dict[str, Any]:
    return investigations.get_case(session, case_id)


@router.patch("/cases/{case_id}")
def update_case(
    case_id: uuid.UUID, body: CasePatch, principal: Analyst, session: DbSession
) -> dict[str, Any]:
    return investigations.update_case(
        session, principal.actor, case_id, body.model_dump(exclude_unset=True)
    )


@router.get("/cases/{case_id}/timeline")
def case_timeline(
    case_id: uuid.UUID, principal: Viewer, session: DbSession
) -> list[dict[str, Any]]:
    return investigations.timeline(session, case_id)


@router.post("/cases/{case_id}/notes", status_code=status.HTTP_201_CREATED)
def add_note(
    case_id: uuid.UUID, body: NoteBody, principal: Analyst, session: DbSession
) -> dict[str, Any]:
    return investigations.add_note(session, principal.actor, case_id, body.body)


@router.post("/cases/{case_id}/alerts")
def link_alert(
    case_id: uuid.UUID, body: LinkBody, principal: Analyst, session: DbSession
) -> dict[str, Any]:
    return investigations.link_alert(session, principal.actor, case_id, body.alert_id)


@router.post("/feedback", status_code=status.HTTP_201_CREATED)
def create_feedback(body: FeedbackBody, principal: Analyst, session: DbSession) -> dict[str, Any]:
    return investigations.create_feedback(session, principal.actor, body.model_dump())


@router.get(
    "/feedback",
    dependencies=[
        Depends(allow_query_params("target_type", "target_id", "verdict", "analyst_id", "limit"))
    ],
)
def list_feedback(
    principal: Viewer,
    session: DbSession,
    target_type: TargetType | None = None,
    target_id: Annotated[str | None, Query(max_length=64)] = None,
    verdict: Verdict | None = None,
    analyst_id: uuid.UUID | None = None,
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = DEFAULT_LIMIT,
) -> list[dict[str, Any]]:
    return investigations.list_feedback(
        session,
        target_type=target_type,
        target_id=target_id,
        verdict=verdict,
        analyst_id=analyst_id,
        limit=limit,
    )


@router.get("/feedback/summary")
def feedback_summary(principal: Viewer, session: DbSession) -> dict[str, Any]:
    return investigations.feedback_summary(session)
