"""Queries for feeds, indicators, matching, and ATT&CK."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import case, func, literal, or_, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session
from sqlalchemy.sql.elements import ColumnElement

from app.models import (
    AttackCategoryTechnique,
    AttackTechnique,
    DimAttackCategory,
    FactSecurityEvent,
    IndicatorMatch,
    TiFeed,
    TiIndicator,
)

F = FactSecurityEvent
I = TiIndicator  # noqa: E741 - short alias used in long expressions
MATCHER_VERSION = "exact-1"

# (indicator_type, event field name, expression producing the comparable event value)
MATCH_FIELDS: list[tuple[str, str, Any]] = [
    ("ipv4", "src_ip", func.host(F.src_ip)),
    ("ipv4", "dst_ip", func.host(F.dst_ip)),
    ("ipv6", "src_ip", func.host(F.src_ip)),
    ("ipv6", "dst_ip", func.host(F.dst_ip)),
    ("domain", "dns_query", F.dns_query),
    ("domain", "http_host", F.http_host),
    ("url", "url", F.url),
    ("url", "http_host+url", func.concat("http://", F.http_host, F.url)),
    ("url", "https_host+url", func.concat("https://", F.http_host, F.url)),
    ("sha256", "file_sha256", F.file_sha256),
]


def state_expression() -> Any:
    """Indicator state relative to the *event* time (THREAT_INTELLIGENCE.md §4)."""
    expiry = func.coalesce(
        I.valid_until, I.last_seen + func.make_interval(0, 0, 0, TiFeed.default_ttl_days)
    )
    return case(
        (I.revoked.is_(True), literal("revoked")),
        (or_(F.event_time < I.valid_from, F.event_time > expiry), literal("expired")),
        else_=literal("active"),
    )


def run_matching(
    session: Session,
    *,
    start: datetime | None,
    end: datetime | None,
    batch_ids: list[uuid.UUID] | None,
    include_expired: bool,
    job_id: uuid.UUID | None,
) -> dict[str, int]:
    created: dict[str, int] = {}
    state = state_expression()
    scope: list[ColumnElement[bool]] = []
    if start is not None:
        scope.append(F.event_time >= start)
    if end is not None:
        scope.append(F.event_time < end)
    if batch_ids:
        scope.append(F.batch_id.in_(batch_ids))
    for indicator_type, field_name, expression in MATCH_FIELDS:
        conds = [
            *scope,
            I.indicator_type == indicator_type,
            expression.is_not(None),
            expression == I.value_normalized,
            TiFeed.enabled.is_(True),
        ]
        if not include_expired:
            conds.append(state == "active")
        selection = (
            select(
                F.event_id,
                F.event_time,
                I.indicator_id,
                literal(field_name),
                expression,
                literal("exact"),
                I.confidence,
                state,
                literal(MATCHER_VERSION),
                literal(job_id, type_=IndicatorMatch.job_id.type),
            )
            .select_from(F)
            .join(I, expression == I.value_normalized)
            .join(TiFeed, TiFeed.feed_id == I.feed_id)
            .where(*conds)
        )
        stmt = (
            pg_insert(IndicatorMatch)
            .from_select(
                [
                    "event_id",
                    "event_time",
                    "indicator_id",
                    "matched_field",
                    "matched_value",
                    "match_type",
                    "indicator_confidence_at_match",
                    "indicator_state_at_match",
                    "matcher_version",
                    "job_id",
                ],
                selection,
            )
            .on_conflict_do_nothing(
                index_elements=["event_id", "event_time", "indicator_id", "matched_field"]
            )
            .returning(IndicatorMatch.match_id)
        )
        # Count RETURNING rows: rowcount is not reliable for INSERT ... SELECT here.
        created[f"{indicator_type}:{field_name}"] = len(session.execute(stmt).all())
    return created


def indicator_state_now(now: datetime) -> Any:
    expiry = func.coalesce(
        I.valid_until, I.last_seen + func.make_interval(0, 0, 0, TiFeed.default_ttl_days)
    )
    return case(
        (I.revoked.is_(True), literal("revoked")),
        (or_(literal(now) < I.valid_from, literal(now) > expiry), literal("expired")),
        else_=literal("active"),
    )


def list_indicators(
    session: Session,
    *,
    now: datetime,
    indicator_type: str | None,
    feed_id: uuid.UUID | None,
    state: str | None,
    min_confidence: int | None,
    value: str | None,
    after: int | None,
    limit: int,
) -> list[tuple[TiIndicator, str, str, str]]:
    st = indicator_state_now(now).label("state")
    stmt = select(I, st, TiFeed.feed_key, TiFeed.reliability).join(
        TiFeed, TiFeed.feed_id == I.feed_id
    )
    if indicator_type:
        stmt = stmt.where(I.indicator_type == indicator_type)
    if feed_id:
        stmt = stmt.where(I.feed_id == feed_id)
    if state:
        stmt = stmt.where(indicator_state_now(now) == state)
    if min_confidence is not None:
        stmt = stmt.where(I.confidence >= min_confidence)
    if value:
        stmt = stmt.where(I.value_normalized == value)
    if after is not None:
        stmt = stmt.where(I.indicator_id < after)
    rows = session.execute(stmt.order_by(I.indicator_id.desc()).limit(limit))
    return [(r[0], r[1], r[2], r[3]) for r in rows]


def list_matches(
    session: Session,
    *,
    indicator_id: int | None,
    state: str | None,
    start: datetime | None,
    end: datetime | None,
    event: tuple[int, datetime] | None,
    after: int | None,
    limit: int,
) -> list[dict[str, Any]]:
    M = IndicatorMatch
    stmt = (
        select(
            M,
            I.indicator_type,
            I.value_normalized,
            I.description,
            I.technique_ids,
            I.tlp,
            TiFeed.feed_key,
            TiFeed.reliability,
        )
        .join(I, I.indicator_id == M.indicator_id)
        .join(TiFeed, TiFeed.feed_id == I.feed_id)
    )
    if indicator_id is not None:
        stmt = stmt.where(M.indicator_id == indicator_id)
    if state:
        stmt = stmt.where(M.indicator_state_at_match == state)
    if start:
        stmt = stmt.where(M.event_time >= start)
    if end:
        stmt = stmt.where(M.event_time < end)
    if event is not None:
        stmt = stmt.where(M.event_id == event[0], M.event_time == event[1])
    if after is not None:
        stmt = stmt.where(M.match_id < after)
    out = []
    for row in session.execute(stmt.order_by(M.match_id.desc()).limit(limit)):
        m = row[0]
        out.append(
            {
                "match_id": m.match_id,
                "event_id": str(m.event_id),
                "event_time": m.event_time,
                "indicator_id": m.indicator_id,
                "indicator_type": row[1],
                "value_normalized": row[2],
                "description": row[3],
                "technique_ids": row[4],
                "tlp": row[5],
                "feed_key": row[6],
                "feed_reliability": row[7],
                "matched_field": m.matched_field,
                "matched_value": m.matched_value,
                "indicator_confidence_at_match": m.indicator_confidence_at_match,
                "indicator_state_at_match": m.indicator_state_at_match,
                "matcher_version": m.matcher_version,
                "matched_at": m.matched_at,
            }
        )
    return out


def upsert_techniques(session: Session, rows: list[dict[str, Any]]) -> int:
    if not rows:
        return 0
    stmt = pg_insert(AttackTechnique)
    stmt = stmt.on_conflict_do_update(
        index_elements=["technique_id"],
        set_={c: getattr(stmt.excluded, c) for c in rows[0] if c != "technique_id"}
        | {"imported_at": func.now()},
    )
    session.execute(stmt, rows)
    return len(rows)


def technique_ids(session: Session) -> dict[str, tuple[bool, bool]]:
    return {
        t: (d, r)
        for t, d, r in session.execute(
            select(
                AttackTechnique.technique_id, AttackTechnique.deprecated, AttackTechnique.revoked
            )
        )
    }


def category_mappings(session: Session) -> list[dict[str, Any]]:
    rows = session.execute(
        select(
            DimAttackCategory.code,
            DimAttackCategory.name,
            AttackCategoryTechnique.technique_id,
            AttackTechnique.name,
            AttackCategoryTechnique.mapping_confidence,
            AttackCategoryTechnique.rationale,
            AttackCategoryTechnique.mapping_version,
        )
        .select_from(DimAttackCategory)
        .outerjoin(
            AttackCategoryTechnique,
            AttackCategoryTechnique.attack_category_id == DimAttackCategory.attack_category_id,
        )
        .outerjoin(
            AttackTechnique, AttackTechnique.technique_id == AttackCategoryTechnique.technique_id
        )
        .order_by(DimAttackCategory.attack_category_id, AttackCategoryTechnique.technique_id)
    )
    out: dict[str, dict[str, Any]] = {}
    for code, name, tid, tname, conf, rationale, version in rows:
        entry = out.setdefault(code, {"code": code, "name": name, "techniques": []})
        if tid:
            entry["techniques"].append(
                {
                    "technique_id": tid,
                    "name": tname,
                    "mapping_confidence": conf,
                    "rationale": rationale,
                    "mapping_version": version,
                }
            )
    return list(out.values())


def techniques_for_category(session: Session, category_code: str) -> list[dict[str, Any]]:
    rows = session.execute(
        select(
            AttackCategoryTechnique.technique_id,
            AttackTechnique.name,
            AttackCategoryTechnique.mapping_confidence,
        )
        .join(AttackTechnique, AttackTechnique.technique_id == AttackCategoryTechnique.technique_id)
        .join(
            DimAttackCategory,
            DimAttackCategory.attack_category_id == AttackCategoryTechnique.attack_category_id,
        )
        .where(DimAttackCategory.code == category_code)
    )
    return [{"technique_id": t, "name": n, "mapping_confidence": c} for t, n, c in rows]


def search_techniques(
    session: Session, tactic: str | None, q: str | None, limit: int
) -> list[AttackTechnique]:
    stmt = select(AttackTechnique).order_by(AttackTechnique.technique_id)
    if tactic:
        stmt = stmt.where(AttackTechnique.tactics.any(tactic))  # type: ignore[arg-type]
    if q:
        pattern = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        stmt = stmt.where(
            or_(
                AttackTechnique.technique_id.ilike(pattern, escape="\\"),
                AttackTechnique.name.ilike(pattern, escape="\\"),
            )
        )
    return list(session.scalars(stmt.limit(limit)))


def feed_counts(session: Session) -> dict[uuid.UUID, int]:
    return {
        fid: int(n)
        for fid, n in session.execute(select(I.feed_id, func.count()).group_by(I.feed_id))
    }
