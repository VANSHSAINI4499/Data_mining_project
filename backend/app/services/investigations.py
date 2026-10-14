"""Alerts, cases, timelines, and analyst feedback (ATTACK_CORRELATION.md §7-§8)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import Text, and_, cast, func, select
from sqlalchemy.orm import Session

from app.core import clock
from app.core.errors import ConflictError, FieldError, NotFoundError, ValidationFailedError
from app.models import (
    Alert,
    AlertEvidence,
    AnalystFeedback,
    AnomalyResult,
    AppUser,
    CaseAlert,
    CaseTimelineEntry,
    ClassificationResult,
    CorrelationRule,
    DimAttackCategory,
    FactSecurityEvent,
    IncidentCase,
    IndicatorMatch,
    MlModel,
)
from app.services import audit
from app.services.actors import Actor

# Allowed manual transitions (escalation and closing happen through case operations).
ALERT_TRANSITIONS = {
    "new": {"acknowledged", "dismissed"},
    "acknowledged": {"in_review", "dismissed"},
    "in_review": {"dismissed"},
}
CASE_TRANSITIONS = {"open": {"investigating", "closed"}, "investigating": {"closed"}}
EVIDENCE_CATEGORY = {
    "event": "observed",
    "classification_result": "model_output",
    "anomaly_result": "model_output",
    "indicator_match": "threat_intel_match",
}


def _alert_out(a: Alert, rule: CorrelationRule | None = None) -> dict[str, Any]:
    out = {
        "alert_id": a.alert_id,
        "status": a.status,
        "title": a.title,
        "primary_entity_type": a.primary_entity_type,
        "primary_entity_value": a.primary_entity_value,
        "risk_score": a.risk_score,
        "severity": a.risk_breakdown.get("severity"),
        "first_event_time": a.first_event_time,
        "last_event_time": a.last_event_time,
        "evidence_count": a.evidence_count,
        "assigned_to": a.assigned_to,
        "case_id": a.case_id,
        "related_alert_id": a.related_alert_id,
        "dismiss_reason": a.dismiss_reason,
        "created_at": a.created_at,
        "updated_at": a.updated_at,
        "kind": "hypothesis",
        "rule_id": a.rule_id,
    }
    if rule is not None:
        out["rule"] = {
            "rule_key": rule.rule_key,
            "version": rule.version,
            "name": rule.name,
            "description": rule.description,
        }
    return out


def list_alerts(
    session: Session,
    *,
    statuses: list[str] | None,
    rule_key: str | None,
    min_risk: int | None,
    entity_type: str | None,
    entity_value: str | None,
    start: datetime | None,
    end: datetime | None,
    assigned_to: uuid.UUID | None,
    sort: str,
    cursor: str | None,
    limit: int,
) -> dict[str, Any]:
    stmt = select(Alert, CorrelationRule).join(
        CorrelationRule, CorrelationRule.rule_id == Alert.rule_id
    )
    if statuses:
        stmt = stmt.where(Alert.status.in_(statuses))
    if rule_key:
        stmt = stmt.where(CorrelationRule.rule_key == rule_key)
    if min_risk is not None:
        stmt = stmt.where(Alert.risk_score >= min_risk)
    if entity_type:
        stmt = stmt.where(Alert.primary_entity_type == entity_type)
    if entity_value:
        stmt = stmt.where(Alert.primary_entity_value == entity_value)
    if start:
        stmt = stmt.where(Alert.last_event_time >= start)
    if end:
        stmt = stmt.where(Alert.first_event_time < end)
    if assigned_to:
        stmt = stmt.where(Alert.assigned_to == assigned_to)
    offset = int(cursor) if cursor and cursor.isdigit() else 0
    order = (
        (Alert.risk_score.desc(), Alert.last_event_time.desc(), Alert.alert_id)
        if sort == "risk_score"
        else (Alert.last_event_time.desc(), Alert.alert_id)
    )
    with session.begin():
        rows = session.execute(stmt.order_by(*order).offset(offset).limit(limit + 1)).all()
        items = [_alert_out(a, r) for a, r in rows[:limit]]
    return {
        "items": items,
        "next_cursor": str(offset + limit) if len(rows) > limit else None,
        "limit": limit,
        "note": "alerts are hypotheses for review, not confirmed incidents",
    }


def _evidence_rows(session: Session, alert_id: uuid.UUID, limit: int) -> list[dict[str, Any]]:
    rows = list(
        session.scalars(
            select(AlertEvidence)
            .where(AlertEvidence.alert_id == alert_id)
            .order_by(AlertEvidence.event_time, AlertEvidence.evidence_ref)
            .limit(limit)
        )
    )
    derived = {
        "classification_result": (ClassificationResult.result_id, ClassificationResult.event_id),
        "indicator_match": (IndicatorMatch.match_id, IndicatorMatch.event_id),
    }
    event_of: dict[tuple[str, int], int] = {}
    for kind, (ref_col, event_col) in derived.items():
        refs = [e.evidence_ref for e in rows if e.evidence_type == kind]
        if refs:
            for ref, event_id in session.execute(
                select(ref_col, event_col).where(ref_col.in_(refs))
            ):
                event_of[(kind, ref)] = event_id
    out = []
    for e in rows:
        item = {
            "evidence_type": e.evidence_type,
            "category": EVIDENCE_CATEGORY[e.evidence_type],
            "evidence_ref": str(e.evidence_ref),
            "event_time": e.event_time,
            "step_id": e.step_id,
            "contribution": e.contribution,
        }
        if e.evidence_type == "event":
            item["link"] = f"/api/v1/events/{e.evidence_ref}"
            item["event_id"] = str(e.evidence_ref)
        elif e.evidence_type == "anomaly_result":
            item["link"] = f"/api/v1/anomalies/{e.evidence_ref}"
        elif (e.evidence_type, e.evidence_ref) in event_of:
            item["event_id"] = str(event_of[(e.evidence_type, e.evidence_ref)])
            item["link"] = f"/api/v1/events/{item['event_id']}"
        out.append(item)
    return out


def get_alert(session: Session, alert_id: uuid.UUID, evidence_limit: int = 500) -> dict[str, Any]:
    with session.begin():
        alert = session.get(Alert, alert_id)
        if alert is None:
            raise NotFoundError(f"alert {alert_id} not found")
        rule = session.get(CorrelationRule, alert.rule_id)
        out = _alert_out(alert, rule)
        out["risk_breakdown"] = alert.risk_breakdown
        out["evidence"] = _evidence_rows(session, alert_id, evidence_limit)
        out["feedback"] = _feedback_for(session, "alert", str(alert_id))
        return out


def update_alert(
    session: Session,
    actor: Actor,
    alert_id: uuid.UUID,
    *,
    status: str | None,
    assigned_to: uuid.UUID | None,
    dismiss_reason: str | None,
    verdict: str | None,
) -> dict[str, Any]:
    with session.begin():
        alert = session.get(Alert, alert_id, with_for_update=True)
        if alert is None:
            raise NotFoundError(f"alert {alert_id} not found")
        changes: dict[str, Any] = {}
        if status is not None and status != alert.status:
            if status not in ALERT_TRANSITIONS.get(alert.status, set()):
                raise ConflictError(f"cannot change alert status from {alert.status} to {status}")
            if status == "dismissed":
                if not dismiss_reason:
                    raise ValidationFailedError(
                        "dismissing an alert requires dismiss_reason",
                        errors=[FieldError("dismiss_reason", "required", "")],
                    )
                alert.dismiss_reason = dismiss_reason[:1000]
                session.add(
                    AnalystFeedback(
                        target_type="alert",
                        target_id=str(alert_id),
                        verdict=verdict or "false_positive",
                        comment=dismiss_reason[:10_000],
                        analyst_id=actor.user_id,
                    )
                )
            changes["status"] = {"old": alert.status, "new": status}
            alert.status = status
        if assigned_to is not None and assigned_to != alert.assigned_to:
            if session.get(AppUser, assigned_to) is None:
                raise ValidationFailedError("unknown assignee")
            changes["assigned_to"] = str(assigned_to)
            alert.assigned_to = assigned_to
        if changes:
            alert.updated_at = clock.now()
            audit.record(
                session,
                actor,
                "alert.updated",
                target_type="alert",
                target_id=alert_id,
                details=changes,
            )
        session.flush()
        return _alert_out(alert)


# --- cases ---------------------------------------------------------------------------------------


def _case_out(c: IncidentCase) -> dict[str, Any]:
    return {
        "case_id": c.case_id,
        "title": c.title,
        "status": c.status,
        "disposition": c.disposition,
        "severity": c.severity,
        "assigned_to": c.assigned_to,
        "summary": c.summary,
        "opened_by": c.opened_by,
        "opened_at": c.opened_at,
        "closed_at": c.closed_at,
        "updated_at": c.updated_at,
        "confirmed_incident": c.disposition == "confirmed_incident",
    }


def _timeline(
    session: Session,
    case_id: uuid.UUID,
    entry_type: str,
    body: str,
    actor: Actor,
    ref: dict[str, Any] | None = None,
    at: datetime | None = None,
) -> None:
    session.add(
        CaseTimelineEntry(
            case_id=case_id,
            entry_time=at or clock.now(),
            entry_type=entry_type,
            author_id=actor.user_id,
            body=body[:10_000],
            ref=ref or {},
        )
    )


def create_case(
    session: Session,
    actor: Actor,
    title: str,
    severity: str,
    summary: str | None = None,
    *,
    in_transaction: bool = False,
) -> IncidentCase:
    def _create() -> IncidentCase:
        case = IncidentCase(
            case_id=uuid.uuid4(),
            title=title[:300],
            severity=severity,
            summary=summary,
            opened_by=actor.user_id,
            status="open",
        )
        session.add(case)
        session.flush()
        _timeline(session, case.case_id, "status_change", "case opened", actor)
        audit.record(
            session, actor, "case.created", target_type="incident_case", target_id=case.case_id
        )
        return case

    if in_transaction:
        return _create()
    with session.begin():
        case = _create()
        session.flush()
        session.expunge(case)
        return case


def _link(session: Session, actor: Actor, case: IncidentCase, alert: Alert) -> None:
    if session.get(CaseAlert, (case.case_id, alert.alert_id)) is not None:
        raise ConflictError("alert is already linked to this case")
    session.add(CaseAlert(case_id=case.case_id, alert_id=alert.alert_id))
    alert.case_id = case.case_id
    alert.status = "escalated"
    alert.updated_at = clock.now()
    _timeline(
        session,
        case.case_id,
        "alert_linked",
        f"alert linked: {alert.title}",
        actor,
        {"alert_id": str(alert.alert_id), "risk_score": alert.risk_score},
    )
    for ev in _evidence_rows(session, alert.alert_id, 200):
        _timeline(
            session,
            case.case_id,
            "evidence",
            f"{ev['category']}: {ev['evidence_type']} {ev['evidence_ref']}",
            actor,
            {
                "alert_id": str(alert.alert_id),
                **{k: ev[k] for k in ("evidence_type", "evidence_ref")},
            },
            at=ev["event_time"] or clock.now(),
        )
    audit.record(
        session,
        actor,
        "case.alert_linked",
        target_type="incident_case",
        target_id=case.case_id,
        details={"alert_id": str(alert.alert_id)},
    )


def escalate(
    session: Session,
    actor: Actor,
    alert_id: uuid.UUID,
    case_id: uuid.UUID | None,
    new_case: dict[str, Any] | None,
) -> dict[str, Any]:
    with session.begin():
        alert = session.get(Alert, alert_id, with_for_update=True)
        if alert is None:
            raise NotFoundError(f"alert {alert_id} not found")
        if alert.status not in ("acknowledged", "in_review"):
            raise ConflictError("only acknowledged or in-review alerts can be escalated")
        if case_id is not None:
            case = session.get(IncidentCase, case_id, with_for_update=True)
            if case is None:
                raise NotFoundError(f"case {case_id} not found")
            if case.status == "closed":
                raise ConflictError("cannot link alerts to a closed case")
        elif new_case is not None:
            case = create_case(
                session,
                actor,
                new_case["title"],
                new_case["severity"],
                new_case.get("summary"),
                in_transaction=True,
            )
        else:
            raise ValidationFailedError("give case_id or new_case")
        _link(session, actor, case, alert)
        session.flush()
        return {"alert": _alert_out(alert), "case": _case_out(case)}


def link_alert(
    session: Session, actor: Actor, case_id: uuid.UUID, alert_id: uuid.UUID
) -> dict[str, Any]:
    with session.begin():
        case = session.get(IncidentCase, case_id, with_for_update=True)
        alert = session.get(Alert, alert_id, with_for_update=True)
        if case is None or alert is None:
            raise NotFoundError("case or alert not found")
        if case.status == "closed":
            raise ConflictError("cannot link alerts to a closed case")
        if alert.status in ("dismissed", "closed"):
            raise ConflictError(f"alert is {alert.status}")
        _link(session, actor, case, alert)
        session.flush()
        return _case_out(case)


def list_cases(
    session: Session,
    *,
    status: str | None,
    disposition: str | None,
    assigned_to: uuid.UUID | None,
    limit: int,
) -> list[dict[str, Any]]:
    stmt = select(IncidentCase).order_by(IncidentCase.opened_at.desc())
    if status:
        stmt = stmt.where(IncidentCase.status == status)
    if disposition:
        stmt = stmt.where(IncidentCase.disposition == disposition)
    if assigned_to:
        stmt = stmt.where(IncidentCase.assigned_to == assigned_to)
    with session.begin():
        return [_case_out(c) for c in session.scalars(stmt.limit(limit))]


def get_case(session: Session, case_id: uuid.UUID) -> dict[str, Any]:
    with session.begin():
        case = session.get(IncidentCase, case_id)
        if case is None:
            raise NotFoundError(f"case {case_id} not found")
        alerts = session.scalars(
            select(Alert)
            .join(CaseAlert, CaseAlert.alert_id == Alert.alert_id)
            .where(CaseAlert.case_id == case_id)
        )
        return _case_out(case) | {"alerts": [_alert_out(a) for a in alerts]}


def update_case(
    session: Session, actor: Actor, case_id: uuid.UUID, values: dict[str, Any]
) -> dict[str, Any]:
    with session.begin():
        case = session.get(IncidentCase, case_id, with_for_update=True)
        if case is None:
            raise NotFoundError(f"case {case_id} not found")
        if case.status == "closed":
            raise ConflictError("closed cases cannot be modified")
        status = values.get("status")
        if status and status != case.status:
            if status not in CASE_TRANSITIONS.get(case.status, set()):
                raise ConflictError(f"cannot change case status from {case.status} to {status}")
            if status == "closed":
                if not values.get("disposition"):
                    raise ValidationFailedError(
                        "closing a case requires a disposition",
                        errors=[FieldError("disposition", "required", "")],
                    )
                case.disposition = values["disposition"]
                case.closed_at = clock.now()
                for alert in session.scalars(
                    select(Alert)
                    .join(CaseAlert, CaseAlert.alert_id == Alert.alert_id)
                    .where(CaseAlert.case_id == case_id, Alert.status == "escalated")
                ):
                    alert.status = "closed"
            _timeline(
                session,
                case_id,
                "status_change",
                f"status {case.status} -> {status}"
                + (f" (disposition: {values['disposition']})" if status == "closed" else ""),
                actor,
            )
            case.status = status
        for key in ("title", "severity", "summary", "assigned_to"):
            if key in values and values[key] is not None:
                setattr(case, key, values[key])
        audit.record(
            session,
            actor,
            "case.updated",
            target_type="incident_case",
            target_id=case_id,
            details={k: str(v) for k, v in values.items()},
        )
        session.flush()
        return _case_out(case)


def add_note(session: Session, actor: Actor, case_id: uuid.UUID, body: str) -> dict[str, Any]:
    with session.begin():
        case = session.get(IncidentCase, case_id)
        if case is None:
            raise NotFoundError(f"case {case_id} not found")
        if case.status == "closed":
            raise ConflictError("closed cases cannot be modified")
        _timeline(session, case_id, "note", body, actor)
        audit.record(
            session, actor, "case.note_added", target_type="incident_case", target_id=case_id
        )
    return {"case_id": case_id, "added": True}


def timeline(session: Session, case_id: uuid.UUID) -> list[dict[str, Any]]:
    with session.begin():
        if session.get(IncidentCase, case_id) is None:
            raise NotFoundError(f"case {case_id} not found")
        return [
            {
                "entry_id": e.entry_id,
                "entry_time": e.entry_time,
                "entry_type": e.entry_type,
                "author_id": e.author_id,
                "body": e.body,
                "ref": e.ref,
            }
            for e in session.scalars(
                select(CaseTimelineEntry)
                .where(CaseTimelineEntry.case_id == case_id)
                .order_by(CaseTimelineEntry.entry_time, CaseTimelineEntry.entry_id)
            )
        ]


# --- feedback ------------------------------------------------------------------------------------


def _target_exists(session: Session, target_type: str, target_id: str) -> bool:
    try:
        if target_type == "alert":
            return session.get(Alert, uuid.UUID(target_id)) is not None
        numeric = int(target_id)
    except ValueError:
        return False
    column = {
        "event": FactSecurityEvent.event_id,
        "classification_result": ClassificationResult.result_id,
        "anomaly_result": AnomalyResult.result_id,
        "indicator_match": IndicatorMatch.match_id,
    }[target_type]
    return session.scalar(select(func.count()).where(column == numeric)) != 0


def _feedback_for(session: Session, target_type: str, target_id: str) -> list[dict[str, Any]]:
    return [
        _feedback_out(f, code)
        for f, code in session.execute(
            select(AnalystFeedback, DimAttackCategory.code)
            .outerjoin(
                DimAttackCategory,
                DimAttackCategory.attack_category_id == AnalystFeedback.corrected_category_id,
            )
            .where(
                AnalystFeedback.target_type == target_type, AnalystFeedback.target_id == target_id
            )
            .order_by(AnalystFeedback.created_at)
        )
    ]


def _feedback_out(f: AnalystFeedback, code: str | None) -> dict[str, Any]:
    return {
        "feedback_id": f.feedback_id,
        "target_type": f.target_type,
        "target_id": f.target_id,
        "verdict": f.verdict,
        "corrected_category": code,
        "comment": f.comment,
        "analyst_id": f.analyst_id,
        "created_at": f.created_at,
        "kind": "analyst_conclusion",
    }


def create_feedback(session: Session, actor: Actor, values: dict[str, Any]) -> dict[str, Any]:
    with session.begin():
        if not _target_exists(session, values["target_type"], values["target_id"]):
            raise NotFoundError(f"{values['target_type']} {values['target_id']} not found")
        category_id = None
        if values.get("corrected_category"):
            category_id = session.scalar(
                select(DimAttackCategory.attack_category_id).where(
                    DimAttackCategory.code == values["corrected_category"].upper()
                )
            )
            if category_id is None:
                raise ValidationFailedError("unknown corrected_category")
        fb = AnalystFeedback(
            target_type=values["target_type"],
            target_id=values["target_id"],
            verdict=values["verdict"],
            corrected_category_id=category_id,
            comment=values.get("comment"),
            analyst_id=actor.user_id,
        )
        session.add(fb)
        session.flush()
        audit.record(
            session,
            actor,
            "feedback.created",
            target_type=values["target_type"],
            target_id=values["target_id"],
            details={"verdict": values["verdict"]},
        )
        return _feedback_out(fb, values.get("corrected_category"))


def list_feedback(
    session: Session,
    *,
    target_type: str | None,
    target_id: str | None,
    verdict: str | None,
    analyst_id: uuid.UUID | None,
    limit: int,
) -> list[dict[str, Any]]:
    stmt = (
        select(AnalystFeedback, DimAttackCategory.code)
        .outerjoin(
            DimAttackCategory,
            DimAttackCategory.attack_category_id == AnalystFeedback.corrected_category_id,
        )
        .order_by(AnalystFeedback.created_at.desc())
    )
    for col, value in (
        (AnalystFeedback.target_type, target_type),
        (AnalystFeedback.target_id, target_id),
        (AnalystFeedback.verdict, verdict),
        (AnalystFeedback.analyst_id, analyst_id),
    ):
        if value is not None:
            stmt = stmt.where(col == value)
    with session.begin():
        return [_feedback_out(f, c) for f, c in session.execute(stmt.limit(limit))]


def feedback_summary(session: Session) -> dict[str, Any]:
    with session.begin():
        by_rule = session.execute(
            select(CorrelationRule.rule_key, AnalystFeedback.verdict, func.count())
            .select_from(AnalystFeedback)
            .join(
                Alert,
                and_(
                    AnalystFeedback.target_type == "alert",
                    cast(Alert.alert_id, Text) == AnalystFeedback.target_id,
                ),
            )
            .join(CorrelationRule, CorrelationRule.rule_id == Alert.rule_id)
            .group_by(CorrelationRule.rule_key, AnalystFeedback.verdict)
        ).all()
        by_model = session.execute(
            select(MlModel.name, MlModel.version, AnalystFeedback.verdict, func.count())
            .select_from(AnalystFeedback)
            .join(
                ClassificationResult,
                and_(
                    AnalystFeedback.target_type == "classification_result",
                    cast(ClassificationResult.result_id, Text) == AnalystFeedback.target_id,
                ),
            )
            .join(MlModel, MlModel.model_id == ClassificationResult.model_id)
            .group_by(MlModel.name, MlModel.version, AnalystFeedback.verdict)
        ).all()
        by_anomaly = session.execute(
            select(MlModel.name, MlModel.version, AnalystFeedback.verdict, func.count())
            .select_from(AnalystFeedback)
            .join(
                AnomalyResult,
                and_(
                    AnalystFeedback.target_type == "anomaly_result",
                    cast(AnomalyResult.result_id, Text) == AnalystFeedback.target_id,
                ),
            )
            .join(MlModel, MlModel.model_id == AnomalyResult.model_id)
            .group_by(MlModel.name, MlModel.version, AnalystFeedback.verdict)
        ).all()
    return {
        "by_rule": [{"rule_key": k, "verdict": v, "count": n} for k, v, n in by_rule],
        "by_classifier": [
            {"name": m, "version": ver, "verdict": v, "count": n} for m, ver, v, n in by_model
        ],
        "by_anomaly_model": [
            {"name": m, "version": ver, "verdict": v, "count": n} for m, ver, v, n in by_anomaly
        ],
    }


def alerts_for_event(session: Session, event_id: int) -> list[dict[str, Any]]:
    """Alerts whose evidence is this event, or a match / classification derived from it."""
    ev = AlertEvidence
    refs = [
        select(ev.alert_id).where(ev.evidence_type == "event", ev.evidence_ref == event_id),
        select(ev.alert_id)
        .join(IndicatorMatch, IndicatorMatch.match_id == ev.evidence_ref)
        .where(ev.evidence_type == "indicator_match", IndicatorMatch.event_id == event_id),
        select(ev.alert_id)
        .join(ClassificationResult, ClassificationResult.result_id == ev.evidence_ref)
        .where(
            ev.evidence_type == "classification_result",
            ClassificationResult.event_id == event_id,
        ),
    ]
    ids = {row for stmt in refs for row in session.scalars(stmt)}
    if not ids:
        return []
    rows = session.scalars(
        select(Alert).where(Alert.alert_id.in_(ids)).order_by(Alert.risk_score.desc())
    )
    return [
        {"alert_id": a.alert_id, "status": a.status, "risk_score": a.risk_score, "title": a.title}
        for a in rows
    ]


def feedback_for_event(session: Session, event_id: int) -> list[dict[str, Any]]:
    return _feedback_for(session, "event", str(event_id))
