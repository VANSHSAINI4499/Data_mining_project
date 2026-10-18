"""Correlation runs: evidence loading, matching, alert dedup, risk (ATTACK_CORRELATION.md)."""

from __future__ import annotations

import tomllib
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from pydantic import ValidationError
from sqlalchemy import and_, func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session
from sqlalchemy.sql.elements import ColumnElement

from app.core import clock
from app.core.config import REPO_ROOT
from app.core.errors import ConflictError, FieldError, NotFoundError, ValidationFailedError
from app.correlation import risk
from app.correlation.rules import Evidence, RuleDefinition, RuleStep, dedup_key, find_matches
from app.models import (
    Alert,
    AlertEvidence,
    AnomalyResult,
    ClassificationResult,
    CorrelationRule,
    DimAsset,
    DimAttackCategory,
    FactSecurityEvent,
    IndicatorMatch,
    MlModel,
    TiFeed,
    TiIndicator,
    WebPayloadResult,
)
from app.services import audit
from app.services import jobs as jobs_service
from app.services.actors import SYSTEM_ACTOR, Actor

F = FactSecurityEvent
JOB_TYPE = "correlation.run"
RULES_FILE = REPO_ROOT / "config" / "correlation_rules" / "default.toml"
MAX_EVIDENCE_PER_ALERT = 10_000
OPEN_STATUSES = ("new", "acknowledged", "in_review")
CLASSIFIER_NAME = "attack_classifier"
WEB_PAYLOAD_MODEL = "web_attack_classifier"
PROBABILITY_SCORE_KIND = "logistic_regression_probability_uncalibrated"
# Web payload classes are not dim_attack_category codes; for risk they count as WEB_ATTACK.
WEB_PAYLOAD_CATEGORY = "WEB_ATTACK"


def parse_rule(data: dict[str, Any]) -> RuleDefinition:
    try:
        return RuleDefinition.model_validate(data)
    except ValidationError as exc:
        raise ValidationFailedError(
            "invalid correlation rule",
            errors=[
                FieldError(".".join(str(p) for p in e["loc"]) or "rule", e["type"], e["msg"])
                for e in exc.errors()
            ],
        ) from exc


def _rule_from_row(row: CorrelationRule) -> RuleDefinition:
    return RuleDefinition.model_validate(
        {
            "key": row.rule_key,
            "version": row.version,
            "name": row.name,
            "description": row.description,
            "base_severity": row.base_severity,
            "enabled": row.enabled,
            **row.definition,
        }
    )


# --- rule management -----------------------------------------------------------------------------


def _latest(session: Session, rule_key: str, *, for_update: bool = False) -> CorrelationRule | None:
    stmt = (
        select(CorrelationRule)
        .where(CorrelationRule.rule_key == rule_key)
        .order_by(CorrelationRule.version.desc())
        .limit(1)
    )
    return session.scalar(stmt.with_for_update() if for_update else stmt)


def _rule_out(row: CorrelationRule) -> dict[str, Any]:
    return {
        "rule_id": row.rule_id,
        "rule_key": row.rule_key,
        "version": row.version,
        "name": row.name,
        "description": row.description,
        "enabled": row.enabled,
        "base_severity": row.base_severity,
        "definition": row.definition,
        "created_at": row.created_at,
    }


def seed_default_rules(session: Session, actor: Actor, path: Path = RULES_FILE) -> int:
    """Insert default rules whose key does not exist yet (inside the caller's transaction)."""
    with path.open("rb") as fh:
        rules = tomllib.load(fh)["rule"]
    created = 0
    for raw in rules:
        rule = parse_rule(raw)
        if _latest(session, rule.key) is not None:
            continue
        session.add(
            CorrelationRule(
                rule_id=uuid.uuid4(),
                rule_key=rule.key,
                version=rule.version,
                name=rule.name,
                description=rule.description,
                enabled=rule.enabled,
                definition=rule.definition(),
                base_severity=rule.base_severity,
                created_by=actor.user_id,
            )
        )
        created += 1
    return created


def list_rules(session: Session) -> list[dict[str, Any]]:
    with session.begin():
        latest = (
            select(CorrelationRule.rule_key, func.max(CorrelationRule.version).label("v"))
            .group_by(CorrelationRule.rule_key)
            .subquery()
        )
        rows = session.scalars(
            select(CorrelationRule)
            .join(
                latest,
                and_(
                    latest.c.rule_key == CorrelationRule.rule_key,
                    latest.c.v == CorrelationRule.version,
                ),
            )
            .order_by(CorrelationRule.rule_key)
        )
        return [_rule_out(r) for r in rows]


def rule_versions(session: Session, rule_key: str) -> list[dict[str, Any]]:
    with session.begin():
        rows = list(
            session.scalars(
                select(CorrelationRule)
                .where(CorrelationRule.rule_key == rule_key)
                .order_by(CorrelationRule.version)
            )
        )
        if not rows:
            raise NotFoundError(f"rule {rule_key!r} not found")
        return [_rule_out(r) for r in rows]


def create_rule(session: Session, actor: Actor, data: dict[str, Any]) -> dict[str, Any]:
    rule = parse_rule({**data, "version": 1})
    with session.begin():
        if _latest(session, rule.key) is not None:
            raise ConflictError(f"rule {rule.key!r} exists; use PUT to create a new version")
        row = CorrelationRule(
            rule_id=uuid.uuid4(),
            rule_key=rule.key,
            version=1,
            name=rule.name,
            description=rule.description,
            enabled=rule.enabled,
            definition=rule.definition(),
            base_severity=rule.base_severity,
            created_by=actor.user_id,
        )
        session.add(row)
        session.flush()
        audit.record(
            session,
            actor,
            "correlation.rule_created",
            target_type="correlation_rule",
            target_id=row.rule_id,
            details={"rule_key": rule.key},
        )
        return _rule_out(row)


def new_version(
    session: Session, actor: Actor, rule_key: str, data: dict[str, Any]
) -> dict[str, Any]:
    with session.begin():
        current = _latest(session, rule_key, for_update=True)
        if current is None:
            raise NotFoundError(f"rule {rule_key!r} not found")
        rule = parse_rule({**data, "key": rule_key, "version": current.version + 1})
        row = CorrelationRule(
            rule_id=uuid.uuid4(),
            rule_key=rule_key,
            version=rule.version,
            name=rule.name,
            description=rule.description,
            enabled=rule.enabled,
            definition=rule.definition(),
            base_severity=rule.base_severity,
            created_by=actor.user_id,
        )
        session.add(row)
        session.flush()
        audit.record(
            session,
            actor,
            "correlation.rule_versioned",
            target_type="correlation_rule",
            target_id=row.rule_id,
            details={"rule_key": rule_key, "version": rule.version},
        )
        return _rule_out(row)


def set_enabled(session: Session, actor: Actor, rule_key: str, enabled: bool) -> dict[str, Any]:
    with session.begin():
        current = _latest(session, rule_key, for_update=True)
        if current is None:
            raise NotFoundError(f"rule {rule_key!r} not found")
        current.enabled = enabled
        audit.record(
            session,
            actor,
            "correlation.rule_enabled" if enabled else "correlation.rule_disabled",
            target_type="correlation_rule",
            target_id=current.rule_id,
        )
        session.flush()
        return _rule_out(current)


# --- evidence loading ----------------------------------------------------------------------------


def _entity_expr(entity_type: str) -> Any:
    if entity_type == "account":
        return F.user_name_normalized
    if entity_type == "src_ip":
        return func.host(F.src_ip)
    if entity_type == "dst_ip":
        return func.host(F.dst_ip)
    return func.coalesce(func.lower(F.host_name), func.host(F.src_ip))


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else [value]


def _event_filters(where: dict[str, Any]) -> list[ColumnElement[bool]]:
    conds: list[ColumnElement[bool]] = []
    for key in ("event_type", "auth_result", "protocol", "app_protocol"):
        if key in where:
            conds.append(getattr(F, key).in_([str(v).lower() for v in _list(where[key])]))
    for key in ("dst_port", "signature_id"):
        if key in where:
            conds.append(getattr(F, key).in_(_list(where[key])))
    return conds


def load_evidence(
    session: Session, rule: RuleDefinition, step: RuleStep, start: datetime, end: datetime
) -> list[Evidence]:
    entity = _entity_expr(rule.entity_type)
    where = step.where
    out: list[Evidence] = []
    if step.evidence == "event":
        same = (
            (func.host(F.dst_ip) if step.same == "dst_ip" else getattr(F, step.same))
            if step.same
            else None
        )
        columns = [F.event_id, F.event_time, entity.label("entity")]
        if same is not None:
            columns.append(same.label("same"))
        rows = session.execute(
            select(*columns).where(
                F.event_time >= start,
                F.event_time < end,
                entity.is_not(None),
                *_event_filters(where),
            )
        )
        out = [
            Evidence(
                step.id,
                "event",
                r.event_id,
                str(r.entity),
                r.event_time,
                {step.same: r.same} if step.same else {},
            )
            for r in rows
        ]
    elif step.evidence == "classification_result":
        model = session.scalar(
            select(MlModel).where(MlModel.name == CLASSIFIER_NAME, MlModel.status == "active")
        )
        if model is None:
            return []
        R = ClassificationResult
        conds: list[ColumnElement[bool]] = [
            R.model_id == model.model_id,
            R.event_time >= start,
            R.event_time < end,
            entity.is_not(None),
        ]
        if "predicted_category" in where:
            conds.append(
                DimAttackCategory.code.in_(
                    [str(v).upper() for v in _list(where["predicted_category"])]
                )
            )
        if where.get("exclude_benign"):
            conds.append(DimAttackCategory.is_benign.is_(False))
        if "min_predicted_score" in where:
            conds.append(R.predicted_score >= float(where["min_predicted_score"]))
        rows = session.execute(
            select(
                R.result_id,
                R.event_time,
                entity.label("entity"),
                R.predicted_score,
                DimAttackCategory.code,
                DimAttackCategory.severity_weight,
            )
            .join(F, and_(F.event_id == R.event_id, F.event_time == R.event_time))
            .join(
                DimAttackCategory, DimAttackCategory.attack_category_id == R.predicted_category_id
            )
            .where(*conds)
        )
        out = [
            Evidence(
                step.id,
                "classification_result",
                r.result_id,
                str(r.entity),
                r.event_time,
                {
                    "predicted_category": r.code,
                    "predicted_score": float(r.predicted_score),
                    "severity_weight": float(r.severity_weight),
                    "evidence_ref": r.result_id,
                },
            )
            for r in rows
        ]
    elif step.evidence == "web_payload_result":
        out = _web_payload_evidence(session, step, entity, start, end)
    elif step.evidence == "anomaly_result":
        if rule.entity_type == "dst_ip":
            return []
        A = AnomalyResult
        conds = [
            A.is_flagged.is_(True),
            A.entity_type == rule.entity_type,
            A.window_start >= start,
            A.window_start < end,
            MlModel.status == "active",
        ]
        if "min_score_percentile" in where:
            conds.append(A.score_percentile >= float(where["min_score_percentile"]))
        rows = session.execute(
            select(A.result_id, A.window_start, A.entity_value, A.score_percentile, A.anomaly_score)
            .join(MlModel, MlModel.model_id == A.model_id)
            .where(*conds)
        )
        out = [
            Evidence(
                step.id,
                "anomaly_result",
                r.result_id,
                r.entity_value,
                r.window_start,
                {
                    "score_percentile": float(r.score_percentile or 0),
                    "anomaly_score": float(r.anomaly_score),
                    "evidence_ref": r.result_id,
                },
            )
            for r in rows
        ]
    elif step.evidence == "indicator_match":
        M = IndicatorMatch
        conds = [
            M.event_time >= start,
            M.event_time < end,
            entity.is_not(None),
            M.indicator_state_at_match.in_(
                [str(s) for s in _list(where.get("indicator_state", "active"))]
            ),
        ]
        if "min_confidence" in where:
            conds.append(M.indicator_confidence_at_match >= int(where["min_confidence"]))
        if "indicator_type" in where:
            conds.append(TiIndicator.indicator_type.in_(_list(where["indicator_type"])))
        rows = session.execute(
            select(
                M.match_id,
                M.event_time,
                entity.label("entity"),
                M.indicator_confidence_at_match,
                TiFeed.reliability,
                M.matched_value,
            )
            .join(F, and_(F.event_id == M.event_id, F.event_time == M.event_time))
            .join(TiIndicator, TiIndicator.indicator_id == M.indicator_id)
            .join(TiFeed, TiFeed.feed_id == TiIndicator.feed_id)
            .where(*conds)
        )
        out = [
            Evidence(
                step.id,
                "indicator_match",
                r.match_id,
                str(r.entity),
                r.event_time,
                {
                    "confidence": int(r.indicator_confidence_at_match),
                    "reliability": r.reliability,
                    "matched_value": r.matched_value,
                    "evidence_ref": r.match_id,
                },
            )
            for r in rows
        ]
    return out


def _web_payload_evidence(
    session: Session, step: RuleStep, entity: Any, start: datetime, end: datetime
) -> list[Evidence]:
    model = session.scalar(
        select(MlModel).where(MlModel.name == WEB_PAYLOAD_MODEL, MlModel.status == "active")
    )
    if model is None:
        return []
    W = WebPayloadResult
    where = step.where
    conds: list[ColumnElement[bool]] = [
        W.model_id == model.model_id,
        W.event_time >= start,
        W.event_time < end,
        entity.is_not(None),
    ]
    if "predicted_class" in where:
        conds.append(
            W.predicted_class.in_([str(v).upper() for v in _list(where["predicted_class"])])
        )
    if where.get("exclude_benign"):
        conds.append(W.is_attack_like.is_(True))
    if "min_score" in where:
        conds += [W.score_kind == PROBABILITY_SCORE_KIND, W.score >= float(where["min_score"])]
    rows = session.execute(
        select(
            W.result_id,
            W.event_time,
            entity.label("entity"),
            W.param_name,
            W.predicted_class,
            W.score,
            W.score_kind,
        )
        .join(F, and_(F.event_id == W.event_id, F.event_time == W.event_time))
        .where(*conds)
    )
    return [
        Evidence(
            step.id,
            "web_payload_result",
            r.result_id,
            str(r.entity),
            r.event_time,
            {
                "param_name": r.param_name[:64],
                "predicted_class": r.predicted_class,
                "score": float(r.score),
                "score_kind": r.score_kind,
                "evidence_ref": r.result_id,
            },
        )
        for r in rows
    ]


# --- alerts --------------------------------------------------------------------------------------


def _asset(session: Session, entity_type: str, entity: str) -> tuple[str, str | None]:
    if entity_type == "account":
        return "unknown", None
    stmt = select(DimAsset).where(DimAsset.is_current.is_(True))
    stmt = stmt.where(
        (func.host(DimAsset.ip_address) == entity)
        | (func.lower(DimAsset.hostname) == entity.lower())
    )
    asset = session.scalar(stmt.limit(1))
    return (asset.criticality, asset.asset_id) if asset else ("unknown", None)


def _risk_inputs(session: Session, alert_id: uuid.UUID) -> dict[str, list[dict[str, Any]]]:
    ev = AlertEvidence
    classifications = [
        {
            "predicted_category": code,
            "predicted_score": float(score),
            "severity_weight": float(weight),
            "evidence_ref": ref,
        }
        for ref, score, code, weight in session.execute(
            select(
                ClassificationResult.result_id,
                ClassificationResult.predicted_score,
                DimAttackCategory.code,
                DimAttackCategory.severity_weight,
            )
            .join(
                ev,
                and_(
                    ev.evidence_ref == ClassificationResult.result_id,
                    ev.evidence_type == "classification_result",
                ),
            )
            .join(
                DimAttackCategory,
                DimAttackCategory.attack_category_id == ClassificationResult.predicted_category_id,
            )
            .where(ev.alert_id == alert_id)
        )
    ]
    web_weight = session.scalar(
        select(DimAttackCategory.severity_weight).where(
            DimAttackCategory.code == WEB_PAYLOAD_CATEGORY
        )
    )
    if web_weight is not None:
        classifications += [
            {
                "predicted_category": WEB_PAYLOAD_CATEGORY,
                "predicted_score": float(score),
                "severity_weight": float(web_weight),
                "evidence_ref": ref,
                "evidence_type": "web_payload_result",
                "web_payload_class": cls,
            }
            for ref, score, cls in session.execute(
                select(
                    WebPayloadResult.result_id,
                    WebPayloadResult.score,
                    WebPayloadResult.predicted_class,
                )
                .join(
                    ev,
                    and_(
                        ev.evidence_ref == WebPayloadResult.result_id,
                        ev.evidence_type == "web_payload_result",
                    ),
                )
                .where(
                    ev.alert_id == alert_id,
                    WebPayloadResult.is_attack_like.is_(True),
                    # Only probability-type scores are on the 0-1 scale the formula expects.
                    WebPayloadResult.score_kind == PROBABILITY_SCORE_KIND,
                )
            )
        ]
    anomalies = [
        {"score_percentile": float(p or 0), "anomaly_score": float(s), "evidence_ref": ref}
        for ref, p, s in session.execute(
            select(
                AnomalyResult.result_id, AnomalyResult.score_percentile, AnomalyResult.anomaly_score
            )
            .join(
                ev,
                and_(
                    ev.evidence_ref == AnomalyResult.result_id, ev.evidence_type == "anomaly_result"
                ),
            )
            .where(ev.alert_id == alert_id)
        )
    ]
    matches = [
        {"confidence": int(c), "reliability": rel, "matched_value": v, "evidence_ref": ref}
        for ref, c, rel, v in session.execute(
            select(
                IndicatorMatch.match_id,
                IndicatorMatch.indicator_confidence_at_match,
                TiFeed.reliability,
                IndicatorMatch.matched_value,
            )
            .join(
                ev,
                and_(
                    ev.evidence_ref == IndicatorMatch.match_id,
                    ev.evidence_type == "indicator_match",
                ),
            )
            .join(TiIndicator, TiIndicator.indicator_id == IndicatorMatch.indicator_id)
            .join(TiFeed, TiFeed.feed_id == TiIndicator.feed_id)
            .where(ev.alert_id == alert_id)
        )
    ]
    return {
        "classifications": classifications,
        "anomalies": anomalies,
        "indicator_matches": matches,
    }


def _upsert_alert(
    session: Session, rule_row: CorrelationRule, rule: RuleDefinition, match: Any
) -> tuple[Alert, bool]:
    key = dedup_key(rule.key, rule.entity_type, match.entity)
    alert = session.scalar(
        select(Alert)
        .where(Alert.dedup_key == key, Alert.status.in_(OPEN_STATUSES))
        .with_for_update()
    )
    created = alert is None
    if alert is None:
        previous = session.scalar(
            select(Alert.alert_id)
            .where(Alert.dedup_key == key)
            .order_by(Alert.created_at.desc())
            .limit(1)
        )
        alert = Alert(
            alert_id=uuid.uuid4(),
            rule_id=rule_row.rule_id,
            dedup_key=key,
            status="new",
            title=f"{rule.name}: {rule.entity_type} {match.entity}"[:300],
            primary_entity_type=rule.entity_type,
            primary_entity_value=match.entity,
            risk_score=0,
            risk_breakdown={},
            first_event_time=match.start,
            last_event_time=match.end,
            evidence_count=0,
            related_alert_id=previous,
        )
        session.add(alert)
        session.flush()
    current = (
        session.scalar(
            select(func.count())
            .select_from(AlertEvidence)
            .where(AlertEvidence.alert_id == alert.alert_id)
        )
        or 0
    )
    room = max(0, MAX_EVIDENCE_PER_ALERT - current)
    rows = [
        {
            "alert_id": alert.alert_id,
            "evidence_type": e.evidence_type,
            "evidence_ref": e.ref,
            "event_time": e.time,
            "step_id": e.step_id,
            "contribution": e.data,
        }
        for e in match.evidence[:room]
    ]
    if rows:
        session.execute(
            pg_insert(AlertEvidence).on_conflict_do_nothing(
                index_elements=["alert_id", "evidence_type", "evidence_ref"]
            ),
            rows,
        )
    alert.first_event_time = min(alert.first_event_time, match.start)
    alert.last_event_time = max(alert.last_event_time, match.end)
    stored = (
        session.scalar(
            select(func.count())
            .select_from(AlertEvidence)
            .where(AlertEvidence.alert_id == alert.alert_id)
        )
        or 0
    )
    alert.evidence_count = int(stored) + max(0, len(match.evidence) - room)
    criticality, asset_id = _asset(session, rule.entity_type, match.entity)
    inputs = _risk_inputs(session, alert.alert_id)
    alert.risk_score, breakdown = risk.compute(
        classifications=inputs["classifications"],
        anomalies=inputs["anomalies"],
        indicator_matches=inputs["indicator_matches"],
        evidence_count=alert.evidence_count,
        base_severity=rule.base_severity,
        asset_criticality=criticality,
        asset_id=asset_id,
    )
    breakdown["evidence_cap"] = {
        "max_stored": MAX_EVIDENCE_PER_ALERT,
        "capped": len(match.evidence) > room,
    }
    breakdown["rule"] = {"rule_key": rule.key, "version": rule.version}
    alert.risk_breakdown = breakdown
    alert.updated_at = clock.now()
    return alert, created


def run_correlation(
    session: Session,
    actor: Actor,
    start: datetime,
    end: datetime,
    rule_keys: list[str] | None = None,
) -> dict[str, Any]:
    if start.tzinfo is None or end.tzinfo is None or end <= start:
        raise ValidationFailedError("correlation needs timezone-aware from < to")
    summary: dict[str, Any] = {"rules": {}, "alerts_created": 0, "alerts_updated": 0}
    with session.begin():
        latest = (
            select(CorrelationRule.rule_key, func.max(CorrelationRule.version).label("v"))
            .group_by(CorrelationRule.rule_key)
            .subquery()
        )
        rows = list(
            session.scalars(
                select(CorrelationRule)
                .join(
                    latest,
                    and_(
                        latest.c.rule_key == CorrelationRule.rule_key,
                        latest.c.v == CorrelationRule.version,
                    ),
                )
                .where(CorrelationRule.enabled.is_(True))
            )
        )
        if rule_keys:
            rows = [r for r in rows if r.rule_key in rule_keys]
        for row in rows:
            rule = _rule_from_row(row)
            look_back = start - rule.window_delta
            evidence: list[Evidence] = []
            available: dict[str, int] = {}
            for step in rule.steps:
                items = load_evidence(session, rule, step, look_back, end)
                available[step.id] = len(items)
                evidence += items
            matches = [m for m in find_matches(rule, evidence) if m.end >= start]
            created = updated = 0
            for match in matches:
                alert, is_new = _upsert_alert(session, row, rule, match)
                if is_new:
                    created += 1
                    audit.record(
                        session,
                        SYSTEM_ACTOR,
                        "alert.created",
                        target_type="alert",
                        target_id=alert.alert_id,
                        details={"rule_key": rule.key},
                    )
                else:
                    updated += 1
            summary["rules"][rule.key] = {
                "version": rule.version,
                "evidence_available": available,
                "matches": len(matches),
                "alerts_created": created,
                "alerts_updated": updated,
            }
            summary["alerts_created"] += created
            summary["alerts_updated"] += updated
        audit.record(
            session,
            actor,
            "correlation.run",
            details={
                "from": start.isoformat(),
                "to": end.isoformat(),
                "alerts_created": summary["alerts_created"],
                "alerts_updated": summary["alerts_updated"],
            },
        )
    return summary


def start_run(
    session: Session, actor: Actor, start: datetime, end: datetime, rule_keys: list[str] | None
) -> uuid.UUID:
    if start.tzinfo is None or end.tzinfo is None or end <= start:
        raise ValidationFailedError("correlation needs timezone-aware from < to")
    with session.begin():
        job = jobs_service.enqueue_in_transaction(
            session,
            actor,
            JOB_TYPE,
            {"from": start.isoformat(), "to": end.isoformat(), "rule_keys": rule_keys or []},
        )
        return job.job_id
