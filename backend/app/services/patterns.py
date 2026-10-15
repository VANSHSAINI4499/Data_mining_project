"""Temporal pattern mining runs (ATTACK_CORRELATION.md §10, Phase 8)."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy import and_, func, select
from sqlalchemy.orm import Session, sessionmaker

from app.core.errors import FieldError, NotFoundError, ValidationFailedError
from app.correlation.patterns import Token, build_sequences, candidates
from app.models import (
    AnomalyResult,
    ClassificationResult,
    DimAttackCategory,
    EventGroundTruth,
    FactSecurityEvent,
    MlModel,
    PatternMiningRun,
)
from app.services import audit
from app.services import jobs as jobs_service
from app.services.actors import Actor

F = FactSecurityEvent
JOB_TYPE = "correlation.mine_patterns"
MAX_TOKENS = 500_000


class MiningParams(BaseModel):
    model_config = ConfigDict(extra="forbid")

    entity_type: str = Field(pattern="^(account|src_ip|dst_ip|host)$")
    start: datetime
    end: datetime
    min_support: int = Field(default=2, ge=1, le=100_000)
    max_length: int = Field(default=3, ge=2, le=5)
    max_gap_minutes: int = Field(default=30, ge=1, le=1440)
    min_malicious_ratio: float = Field(default=0.5, ge=0, le=1)


def parse(data: dict[str, Any]) -> MiningParams:
    try:
        params = MiningParams.model_validate(data)
    except ValidationError as exc:
        raise ValidationFailedError(
            "invalid pattern mining parameters",
            errors=[
                FieldError(".".join(map(str, e["loc"])), e["type"], e["msg"]) for e in exc.errors()
            ],
        ) from exc
    if params.start.tzinfo is None or params.end.tzinfo is None or params.end <= params.start:
        raise ValidationFailedError("pattern mining needs timezone-aware start < end")
    if params.end - params.start > timedelta(days=400):
        raise ValidationFailedError("pattern mining is limited to 400 days")
    return params


def _entity(entity_type: str) -> Any:
    if entity_type == "account":
        return F.user_name_normalized
    if entity_type == "src_ip":
        return func.host(F.src_ip)
    if entity_type == "dst_ip":
        return func.host(F.dst_ip)
    return func.coalesce(func.lower(F.host_name), func.host(F.src_ip))


def _malicious() -> Any:
    return func.coalesce(DimAttackCategory.is_benign.is_(False), False)


def load_tokens(session: Session, p: MiningParams) -> list[Token]:
    entity = _entity(p.entity_type)
    label_join = (
        and_(EventGroundTruth.event_id == F.event_id, EventGroundTruth.event_time == F.event_time),
        DimAttackCategory.attack_category_id == EventGroundTruth.attack_category_id,
    )
    tokens: list[Token] = []
    events = session.execute(
        select(
            F.event_time,
            entity.label("entity"),
            F.event_type,
            F.auth_result,
            F.signature_id,
            _malicious().label("mal"),
        )
        .outerjoin(EventGroundTruth, label_join[0])
        .outerjoin(DimAttackCategory, label_join[1])
        .where(
            F.event_time >= p.start,
            F.event_time < p.end,
            entity.is_not(None),
            F.event_type.in_(("auth", "ids_alert")),
        )
        .limit(MAX_TOKENS)
    )
    for t, ent, kind, auth, sig, mal in events:
        token = (
            f"auth:{auth or 'unknown'}"
            if kind == "auth"
            else f"ids:{sig if sig is not None else 'unknown'}"
        )
        tokens.append(Token(str(ent), t, token, bool(mal)))

    classifier = session.scalar(
        select(MlModel.model_id).where(
            MlModel.name == "attack_classifier", MlModel.status == "active"
        )
    )
    if classifier is not None:
        R = ClassificationResult
        pred = DimAttackCategory.__table__.alias("pred")
        rows = session.execute(
            select(R.event_time, entity.label("entity"), pred.c.code, _malicious().label("mal"))
            .join(F, and_(F.event_id == R.event_id, F.event_time == R.event_time))
            .join(pred, pred.c.attack_category_id == R.predicted_category_id)
            .outerjoin(EventGroundTruth, label_join[0])
            .outerjoin(DimAttackCategory, label_join[1])
            .where(
                R.model_id == classifier,
                R.event_time >= p.start,
                R.event_time < p.end,
                pred.c.is_benign.is_(False),
                R.predicted_score >= 0.6,
                entity.is_not(None),
            )
            .limit(MAX_TOKENS)
        )
        tokens += [Token(str(e), t, f"class:{code}", bool(mal)) for t, e, code, mal in rows]

    if p.entity_type != "dst_ip":
        rows = session.execute(
            select(AnomalyResult.window_start, AnomalyResult.entity_value)
            .join(MlModel, MlModel.model_id == AnomalyResult.model_id)
            .where(
                MlModel.status == "active",
                AnomalyResult.is_flagged.is_(True),
                AnomalyResult.entity_type == p.entity_type,
                AnomalyResult.window_start >= p.start,
                AnomalyResult.window_start < p.end,
            )
        )
        tokens += [Token(e, t, "anomaly:flagged") for t, e in rows]
    return tokens


def run(session: Session, actor: Actor, params: MiningParams) -> PatternMiningRun:
    with session.begin():
        tokens = load_tokens(session, params)
        sequences = build_sequences(tokens, timedelta(minutes=params.max_gap_minutes))
        found, stats = candidates(
            sequences,
            entity_type=params.entity_type,
            min_support=params.min_support,
            max_length=params.max_length,
            min_malicious_ratio=params.min_malicious_ratio,
        )
        stats |= {"tokens": len(tokens), "token_limit_reached": len(tokens) >= MAX_TOKENS}
        record = PatternMiningRun(
            run_id=uuid.uuid4(),
            entity_type=params.entity_type,
            period_start=params.start,
            period_end=params.end,
            params=params.model_dump(mode="json"),
            stats=stats,
            candidates=found,
        )
        session.add(record)
        session.flush()
        audit.record(
            session,
            actor,
            "correlation.patterns_mined",
            target_type="pattern_mining_run",
            target_id=record.run_id,
            details={"candidates": len(found)},
        )
        session.expunge(record)
        return record


def start(session: Session, actor: Actor, params: MiningParams) -> uuid.UUID:
    with session.begin():
        job = jobs_service.enqueue_in_transaction(
            session, actor, JOB_TYPE, params.model_dump(mode="json")
        )
        return job.job_id


def run_job(factory: sessionmaker[Session], actor: Actor, data: dict[str, Any]) -> dict[str, Any]:
    with factory() as session:
        record = run(session, actor, parse(data))
    return {"run_id": str(record.run_id), "candidates": len(record.candidates)}


def out(r: PatternMiningRun) -> dict[str, Any]:
    return {
        "run_id": r.run_id,
        "entity_type": r.entity_type,
        "period_start": r.period_start,
        "period_end": r.period_end,
        "params": r.params,
        "stats": r.stats,
        "candidates": r.candidates,
        "created_at": r.created_at,
        "note": "candidate rules for human review; create one through POST /correlation/rules "
        "to use it — nothing is enabled automatically",
    }


def list_runs(session: Session, limit: int = 50) -> list[dict[str, Any]]:
    with session.begin():
        rows = session.scalars(
            select(PatternMiningRun).order_by(PatternMiningRun.created_at.desc()).limit(limit)
        )
        return [out(r) | {"candidates": len(r.candidates)} for r in rows]


def get_run(session: Session, run_id: uuid.UUID) -> dict[str, Any]:
    with session.begin():
        r = session.get(PatternMiningRun, run_id)
        if r is None:
            raise NotFoundError(f"pattern mining run {run_id} not found")
        return out(r)
