"""Threat-intelligence use cases (THREAT_INTELLIGENCE.md). Feeds are optional."""

from __future__ import annotations

import re
import tomllib
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from app.core import clock
from app.core.config import REPO_ROOT, Settings
from app.core.errors import (
    ConflictError,
    FieldError,
    NotFoundError,
    PayloadTooLargeError,
    UnsupportedMediaTypeError,
    ValidationFailedError,
)
from app.models import (
    AttackCategoryTechnique,
    DimAttackCategory,
    TiFeed,
    TiFeedRun,
    TiIndicator,
    TiIndicatorVersion,
)
from app.repositories import ti as repo
from app.services import audit
from app.services import jobs as jobs_service
from app.services.actors import Actor
from app.ti.indicators import (
    IndicatorError,
    ParsedIndicator,
    defang,
    normalize,
    parse_attack_bundle,
    parse_csv,
    parse_stix_bundle,
)

IMPORT_JOB = "ti.import"
MATCH_JOB = "ti.match"
MAX_IMPORT_BYTES = 50 * 1024 * 1024
MAPPING_FILE = REPO_ROOT / "config" / "attack_mappings" / "category_techniques.toml"
RELIABILITY_WEIGHTS = {"A": 1.0, "B": 0.8, "C": 0.6, "D": 0.4, "E": 0.2, "F": 0.3}
_FEED_KEY = re.compile(r"^[a-z0-9][a-z0-9._-]{1,63}$")
_ENV_NAME = re.compile(r"^[A-Z][A-Z0-9_]{2,63}$")


# --- feeds ---------------------------------------------------------------------------------------


def _feed_out(feed: TiFeed, count: int = 0) -> dict[str, Any]:
    health = (
        "not_configured"
        if feed.feed_type == "taxii" and not feed.url
        else (
            "error"
            if feed.last_error
            and (
                not feed.last_success_at
                or (feed.last_error_at and feed.last_error_at > feed.last_success_at)
            )
            else "ok"
        )
    )
    return {
        "feed_id": feed.feed_id,
        "feed_key": feed.feed_key,
        "name": feed.name,
        "feed_type": feed.feed_type,
        "url": feed.url,
        "collection_id": feed.collection_id,
        "reliability": feed.reliability,
        "default_confidence": feed.default_confidence,
        "default_ttl_days": feed.default_ttl_days,
        "enabled": feed.enabled,
        "poll_interval_minutes": feed.poll_interval_minutes,
        "credentials_ref": feed.credentials_ref,
        "last_success_at": feed.last_success_at,
        "last_error": feed.last_error,
        "last_error_at": feed.last_error_at,
        "indicator_count": count,
        "health": health,
    }


def _validate_feed(values: dict[str, Any]) -> None:
    problems = []
    if "feed_key" in values and not _FEED_KEY.match(values["feed_key"]):
        problems.append(FieldError("feed_key", "invalid", "lowercase letters, digits, . _ -"))
    if values.get("feed_type") not in (None, "manual", "csv_file", "stix_file", "taxii"):
        problems.append(
            FieldError("feed_type", "invalid_choice", "manual/csv_file/stix_file/taxii")
        )
    if values.get("url") and not str(values["url"]).startswith("https://"):
        problems.append(FieldError("url", "https_required", "feed URLs must use https"))
    if values.get("credentials_ref") and not _ENV_NAME.match(values["credentials_ref"]):
        problems.append(
            FieldError(
                "credentials_ref",
                "invalid",
                "name of an environment variable, never the secret itself",
            )
        )
    if problems:
        raise ValidationFailedError("invalid feed", errors=problems)


def list_feeds(session: Session) -> list[dict[str, Any]]:
    with session.begin():
        counts = repo.feed_counts(session)
        return [
            _feed_out(f, counts.get(f.feed_id, 0))
            for f in session.scalars(select(TiFeed).order_by(TiFeed.feed_key))
        ]


def create_feed(session: Session, actor: Actor, values: dict[str, Any]) -> dict[str, Any]:
    _validate_feed(values)
    try:
        with session.begin():
            feed = TiFeed(feed_id=uuid.uuid4(), **values)
            session.add(feed)
            session.flush()
            audit.record(
                session,
                actor,
                "ti.feed_created",
                target_type="ti_feed",
                target_id=feed.feed_id,
                details={"feed_key": feed.feed_key},
            )
            return _feed_out(feed)
    except IntegrityError as exc:
        raise ConflictError(f"feed {values.get('feed_key')!r} already exists") from exc


def update_feed(
    session: Session, actor: Actor, feed_id: uuid.UUID, values: dict[str, Any]
) -> dict[str, Any]:
    _validate_feed(values)
    with session.begin():
        feed = session.get(TiFeed, feed_id, with_for_update=True)
        if feed is None:
            raise NotFoundError(f"feed {feed_id} not found")
        changes = {}
        for key, value in values.items():
            if getattr(feed, key) != value:
                changes[key] = {"old": getattr(feed, key), "new": value}
                setattr(feed, key, value)
        if changes:
            audit.record(
                session,
                actor,
                "ti.feed_updated",
                target_type="ti_feed",
                target_id=feed_id,
                details={"changes": changes},
            )
        session.flush()
        return _feed_out(feed)


def feed_id_for_key(session: Session, feed_key: str) -> uuid.UUID:
    with session.begin():
        feed_id = session.scalar(select(TiFeed.feed_id).where(TiFeed.feed_key == feed_key))
    if feed_id is None:
        raise NotFoundError(f"feed {feed_key!r} not found (run `cti seed-reference` for local-csv)")
    return feed_id


def sync_feed(session: Session, actor: Actor, feed_id: uuid.UUID) -> None:
    with session.begin():
        feed = session.get(TiFeed, feed_id)
        if feed is None:
            raise NotFoundError(f"feed {feed_id} not found")
        audit.record(
            session,
            actor,
            "ti.feed_sync_requested",
            target_type="ti_feed",
            target_id=feed_id,
            outcome="error",
        )
    raise ConflictError(
        "remote feed polling (TAXII 2.1) is not implemented yet; it is planned for Phase 8. "
        "Import CSV or STIX 2.1 files with POST /threat-intel/imports instead."
    )


# --- imports -------------------------------------------------------------------------------------


def start_import(
    session: Session,
    settings: Settings,
    actor: Actor,
    *,
    feed_id: uuid.UUID,
    fmt: str,
    filename: str,
    data: bytes,
    enqueue: bool = True,
) -> TiFeedRun:
    if fmt not in ("csv", "stix"):
        raise ValidationFailedError(
            "format must be csv or stix",
            errors=[FieldError("format", "invalid_choice", "csv|stix")],
        )
    ext = Path(filename).suffix.lower()
    if (fmt == "csv" and ext != ".csv") or (fmt == "stix" and ext not in (".json", ".stix")):
        raise UnsupportedMediaTypeError(f"{fmt} imports need a .csv / .json file, got {ext!r}")
    if len(data) > MAX_IMPORT_BYTES:
        raise PayloadTooLargeError("indicator files are limited to 50 MB")
    if b"\x00" in data[:8192]:
        raise UnsupportedMediaTypeError("file looks binary")
    run_id = uuid.uuid4()
    settings.upload_dir.mkdir(parents=True, exist_ok=True)
    path = settings.upload_dir / f"ti-{run_id}{ext}"
    path.write_bytes(data)
    try:
        with session.begin():
            feed = session.get(TiFeed, feed_id)
            if feed is None:
                raise NotFoundError(f"feed {feed_id} not found")
            run = TiFeedRun(
                feed_run_id=run_id,
                feed_id=feed_id,
                status="queued",
                source_description=f"{fmt}:{Path(filename).name[:200]}",
                report={"stored_path": str(path), "format": fmt},
            )
            session.add(run)
            session.flush()
            if enqueue:
                job = jobs_service.enqueue_in_transaction(
                    session, actor, IMPORT_JOB, {"feed_run_id": str(run_id)}
                )
                run.job_id = job.job_id
            audit.record(
                session,
                actor,
                "ti.import_started",
                target_type="ti_feed_run",
                target_id=run_id,
                details={"feed_key": feed.feed_key, "format": fmt},
            )
            session.flush()
            session.expunge(run)
            return run
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _snapshot(ind: TiIndicator) -> dict[str, Any]:
    return {
        "confidence": ind.confidence,
        "valid_from": ind.valid_from,
        "valid_until": ind.valid_until,
        "revoked": ind.revoked,
        "last_seen": ind.last_seen,
        "description": ind.description,
        "technique_ids": list(ind.technique_ids or []),
    }


def _add_version(session: Session, ind: TiIndicator, run_id: uuid.UUID | None) -> None:
    current = (
        session.scalar(
            select(TiIndicatorVersion.version_no)
            .where(TiIndicatorVersion.indicator_id == ind.indicator_id)
            .order_by(TiIndicatorVersion.version_no.desc())
            .limit(1)
        )
        or 0
    )
    snap = {k: (v.isoformat() if isinstance(v, datetime) else v) for k, v in _snapshot(ind).items()}
    session.add(
        TiIndicatorVersion(
            indicator_id=ind.indicator_id, version_no=current + 1, snapshot=snap, feed_run_id=run_id
        )
    )


def upsert_indicator(
    session: Session, feed: TiFeed, item: ParsedIndicator, run_id: uuid.UUID | None
) -> str:
    """Returns 'created', 'updated', or 'unchanged'. Must run inside a transaction."""
    now = clock.now()
    existing = session.scalar(
        select(TiIndicator)
        .where(
            TiIndicator.feed_id == feed.feed_id,
            TiIndicator.indicator_type == item.indicator_type,
            TiIndicator.value_normalized == item.value_normalized,
        )
        .with_for_update()
    )
    if existing is None:
        first = item.first_seen or now
        ind = TiIndicator(
            feed_id=feed.feed_id,
            indicator_type=item.indicator_type,
            value_raw=item.value_raw,
            value_normalized=item.value_normalized,
            confidence=item.confidence if item.confidence is not None else feed.default_confidence,
            tlp=item.tlp,
            description=item.description,
            stix_id=item.stix_id,
            first_seen=first,
            last_seen=item.last_seen or first,
            valid_from=item.valid_from or first,
            valid_until=item.valid_until,
            revoked=item.revoked,
            technique_ids=item.technique_ids,
            last_feed_run_id=run_id,
        )
        session.add(ind)
        session.flush()
        _add_version(session, ind, run_id)
        return "created"
    before = _snapshot(existing)
    if item.confidence is not None:
        existing.confidence = item.confidence
    if item.valid_until is not None:
        existing.valid_until = item.valid_until
    if item.revoked:
        existing.revoked = True
    if item.description:
        existing.description = item.description
    if item.technique_ids:
        existing.technique_ids = sorted(set(existing.technique_ids or []) | set(item.technique_ids))
    seen = item.last_seen or now
    if seen > existing.last_seen:
        existing.last_seen = seen
    existing.last_feed_run_id = run_id
    if _snapshot(existing) != before:
        session.flush()
        _add_version(session, existing, run_id)
        return "updated"
    return "unchanged"


def run_import(factory: sessionmaker[Session], settings: Settings, run_id: uuid.UUID) -> TiFeedRun:
    with factory() as session, session.begin():
        run = session.get(TiFeedRun, run_id, with_for_update=True)
        if run is None:
            raise NotFoundError(f"feed run {run_id} not found")
        run.status = "running"
        report = dict(run.report)
        feed_id = run.feed_id
    path = Path(report["stored_path"])
    counts = {"created": 0, "updated": 0, "unchanged": 0}
    try:
        data = path.read_bytes()
        parsed = parse_csv(data) if report["format"] == "csv" else parse_stix_bundle(data)
        with factory() as session, session.begin():
            feed = session.get(TiFeed, feed_id)
            assert feed is not None
            for item in parsed.indicators:
                counts[upsert_indicator(session, feed, item, run_id)] += 1
            feed.last_success_at = clock.now()
            run = session.get(TiFeedRun, run_id, with_for_update=True)
            assert run is not None
            run.status, run.finished_at = "succeeded", clock.now()
            run.indicators_received = parsed.received
            run.indicators_created, run.indicators_updated = counts["created"], counts["updated"]
            run.indicators_rejected = len(parsed.rejected)
            run.report = report | {
                "rejected": parsed.rejected[:500],
                "unsupported_patterns": parsed.unsupported_patterns[:500],
                "unchanged": counts["unchanged"],
            }
    except (IndicatorError, ValueError, UnicodeDecodeError) as exc:
        with factory() as session, session.begin():
            run = session.get(TiFeedRun, run_id, with_for_update=True)
            feed = session.get(TiFeed, feed_id)
            assert run is not None and feed is not None
            run.status, run.finished_at, run.error = "failed", clock.now(), str(exc)[:500]
            feed.last_error, feed.last_error_at = str(exc)[:500], clock.now()
        raise
    finally:
        path.unlink(missing_ok=True)
    if settings.ti_retrohunt_days > 0 and (counts["created"] or counts["updated"]):
        end = clock.now()
        with factory() as session:
            start_match_run(
                session,
                _system_actor(),
                start=end - timedelta(days=settings.ti_retrohunt_days),
                end=end,
                batch_ids=None,
                include_expired=False,
            )
    with factory() as session, session.begin():
        done = session.get(TiFeedRun, run_id)
        assert done is not None
        session.expunge(done)
        return done


def _system_actor() -> Actor:
    from app.services.actors import SYSTEM_ACTOR

    return SYSTEM_ACTOR


def get_feed_run(session: Session, run_id: uuid.UUID) -> TiFeedRun:
    with session.begin():
        run = session.get(TiFeedRun, run_id)
        if run is None:
            raise NotFoundError(f"feed run {run_id} not found")
        session.expunge(run)
        return run


# --- manual indicators ---------------------------------------------------------------------------


def create_manual(session: Session, actor: Actor, values: dict[str, Any]) -> dict[str, Any]:
    try:
        item = ParsedIndicator(
            indicator_type=values["indicator_type"],
            value_raw=values["value"][:2048],
            value_normalized=normalize(values["indicator_type"], values["value"]),
            confidence=values["confidence"],
            valid_until=values.get("valid_until"),
            description=values.get("description"),
            tlp=values.get("tlp"),
            technique_ids=values.get("technique_ids") or [],
        )
    except IndicatorError as exc:
        raise ValidationFailedError(
            str(exc), errors=[FieldError("value", "invalid", str(exc))]
        ) from exc
    with session.begin():
        feed = session.scalar(
            select(TiFeed).where(TiFeed.feed_key == values.get("feed_key", "manual"))
        )
        if feed is None:
            feed = TiFeed(
                feed_id=uuid.uuid4(),
                feed_key="manual",
                name="Manual indicators",
                feed_type="manual",
                reliability="F",
            )
            session.add(feed)
            session.flush()
        outcome = upsert_indicator(session, feed, item, None)
        ind = session.scalar(
            select(TiIndicator).where(
                TiIndicator.feed_id == feed.feed_id,
                TiIndicator.indicator_type == item.indicator_type,
                TiIndicator.value_normalized == item.value_normalized,
            )
        )
        assert ind is not None
        audit.record(
            session,
            actor,
            "ti.indicator_saved",
            target_type="ti_indicator",
            target_id=ind.indicator_id,
            details={"outcome": outcome},
        )
        return _indicator_out(ind, None, feed.feed_key, feed.reliability)


def update_indicator(
    session: Session, actor: Actor, indicator_id: int, values: dict[str, Any]
) -> dict[str, Any]:
    with session.begin():
        ind = session.get(TiIndicator, indicator_id, with_for_update=True)
        if ind is None:
            raise NotFoundError(f"indicator {indicator_id} not found")
        before = _snapshot(ind)
        for key in ("confidence", "valid_until", "revoked", "description"):
            if key in values:
                setattr(ind, key, values[key])
        if _snapshot(ind) != before:
            session.flush()
            _add_version(session, ind, None)
            audit.record(
                session,
                actor,
                "ti.indicator_updated",
                target_type="ti_indicator",
                target_id=indicator_id,
                details={"fields": sorted(values)},
            )
        feed = session.get(TiFeed, ind.feed_id)
        assert feed is not None
        return _indicator_out(ind, None, feed.feed_key, feed.reliability)


def _indicator_out(
    ind: TiIndicator, state: str | None, feed_key: str, reliability: str
) -> dict[str, Any]:
    return {
        "indicator_id": ind.indicator_id,
        "feed_id": ind.feed_id,
        "feed_key": feed_key,
        "feed_reliability": reliability,
        "indicator_type": ind.indicator_type,
        "value_raw": ind.value_raw,
        "value_normalized": ind.value_normalized,
        "display_value": defang(ind.indicator_type, ind.value_normalized),
        "confidence": ind.confidence,
        "severity": ind.severity,
        "tlp": ind.tlp,
        "description": ind.description,
        "stix_id": ind.stix_id,
        "first_seen": ind.first_seen,
        "last_seen": ind.last_seen,
        "valid_from": ind.valid_from,
        "valid_until": ind.valid_until,
        "revoked": ind.revoked,
        "technique_ids": ind.technique_ids,
        "state": state,
        "matchable": ind.indicator_type in ("ipv4", "ipv6", "domain", "url", "sha256"),
    }


def list_indicators(
    session: Session,
    *,
    indicator_type: str | None,
    feed_id: uuid.UUID | None,
    state: str | None,
    min_confidence: int | None,
    value: str | None,
    cursor: int | None,
    limit: int,
) -> dict[str, Any]:
    normalized = None
    if value and indicator_type:
        try:
            normalized = normalize(indicator_type, value)
        except IndicatorError as exc:
            raise ValidationFailedError(str(exc)) from exc
    elif value:
        normalized = value.strip().lower()
    with session.begin():
        rows = repo.list_indicators(
            session,
            now=clock.now(),
            indicator_type=indicator_type,
            feed_id=feed_id,
            state=state,
            min_confidence=min_confidence,
            value=normalized,
            after=cursor,
            limit=limit + 1,
        )
        items = [_indicator_out(i, s, k, r) for i, s, k, r in rows[:limit]]
    nxt = str(rows[limit - 1][0].indicator_id) if len(rows) > limit else None
    return {"items": items, "next_cursor": nxt, "limit": limit}


def get_indicator(session: Session, indicator_id: int) -> dict[str, Any]:
    with session.begin():
        rows = repo.list_indicators(
            session,
            now=clock.now(),
            indicator_type=None,
            feed_id=None,
            state=None,
            min_confidence=None,
            value=None,
            after=indicator_id + 1,
            limit=1,
        )
        if not rows or rows[0][0].indicator_id != indicator_id:
            raise NotFoundError(f"indicator {indicator_id} not found")
        ind, state, key, rel = rows[0]
        versions = session.scalars(
            select(TiIndicatorVersion)
            .where(TiIndicatorVersion.indicator_id == indicator_id)
            .order_by(TiIndicatorVersion.version_no)
        )
        out = _indicator_out(ind, state, key, rel)
        out["versions"] = [
            {"version_no": v.version_no, "snapshot": v.snapshot, "changed_at": v.changed_at}
            for v in versions
        ]
        out["match_count"] = len(
            repo.list_matches(
                session,
                indicator_id=indicator_id,
                state=None,
                start=None,
                end=None,
                event=None,
                after=None,
                limit=10_000,
            )
        )
        return out


# --- matching ------------------------------------------------------------------------------------


def start_match_run(
    session: Session,
    actor: Actor,
    *,
    start: datetime | None,
    end: datetime | None,
    batch_ids: list[uuid.UUID] | None,
    include_expired: bool,
    enqueue: bool = True,
) -> uuid.UUID:
    if not batch_ids and not (start and end):
        raise ValidationFailedError("match runs need batch_ids or from/to")
    params = {
        "from": start.isoformat() if start else None,
        "to": end.isoformat() if end else None,
        "batch_ids": [str(b) for b in batch_ids or []],
        "include_expired": include_expired,
    }
    with session.begin():
        job = jobs_service.enqueue_in_transaction(session, actor, MATCH_JOB, params)
        return job.job_id


def run_match(
    factory: sessionmaker[Session], params: dict[str, Any], job_id: uuid.UUID | None
) -> dict[str, Any]:
    start = datetime.fromisoformat(params["from"]) if params.get("from") else None
    end = datetime.fromisoformat(params["to"]) if params.get("to") else None
    batches = [uuid.UUID(b) for b in params.get("batch_ids", [])]
    with factory() as session, session.begin():
        created = repo.run_matching(
            session,
            start=start,
            end=end,
            batch_ids=batches or None,
            include_expired=bool(params.get("include_expired")),
            job_id=job_id,
        )
    return {"matches_created": sum(created.values()), "by_field": created}


def list_matches(
    session: Session,
    *,
    indicator_id: int | None,
    state: str | None,
    start: datetime | None,
    end: datetime | None,
    cursor: int | None,
    limit: int,
) -> dict[str, Any]:
    with session.begin():
        rows = repo.list_matches(
            session,
            indicator_id=indicator_id,
            state=state,
            start=start,
            end=end,
            event=None,
            after=cursor,
            limit=limit + 1,
        )
    items = rows[:limit]
    for item in items:
        item["display_value"] = defang(item["indicator_type"], item["value_normalized"])
    nxt = str(items[-1]["match_id"]) if len(rows) > limit else None
    return {
        "items": items,
        "next_cursor": nxt,
        "limit": limit,
        "note": "a match means an observed value appears on a list; it is not proof of compromise",
    }


def event_context(
    session: Session,
    event_id: int,
    event_time: datetime,
    predicted: list[str],
    ground_truth: str | None,
) -> dict[str, Any]:
    matches = repo.list_matches(
        session,
        indicator_id=None,
        state=None,
        start=None,
        end=None,
        event=(event_id, event_time),
        after=None,
        limit=100,
    )
    for m in matches:
        m["display_value"] = defang(m["indicator_type"], m["value_normalized"])
    techniques: list[dict[str, Any]] = []
    for m in matches:
        techniques += [
            {"technique_id": t, "via": "indicator", "indicator_id": m["indicator_id"]}
            for t in m["technique_ids"] or []
        ]
    for code in predicted:
        techniques += [
            t | {"via": "predicted_category", "category": code}
            for t in repo.techniques_for_category(session, code)
        ]
    if ground_truth:
        techniques += [
            t | {"via": "dataset_label", "category": ground_truth}
            for t in repo.techniques_for_category(session, ground_truth)
        ]
    return {"matches": matches, "attack_techniques": techniques}


# --- ATT&CK --------------------------------------------------------------------------------------


def import_attack(session: Session, actor: Actor, data: bytes) -> dict[str, Any]:
    try:
        records, version = parse_attack_bundle(data)
    except IndicatorError as exc:
        raise ValidationFailedError(str(exc)) from exc
    with session.begin():
        rows = [{**r.__dict__, "attack_version": version} for r in records]
        count = repo.upsert_techniques(session, rows)
        mapping = _apply_category_mapping(session)
        audit.record(
            session,
            actor,
            "attack.imported",
            details={"techniques": count, "attack_version": version} | mapping,
        )
    return {"techniques": count, "attack_version": version} | mapping


def _apply_category_mapping(session: Session, path: Path = MAPPING_FILE) -> dict[str, Any]:
    """Load category -> technique mappings; IDs missing or revoked in the imported data are
    reported and skipped (THREAT_INTELLIGENCE.md §9)."""
    if not path.is_file():
        return {"mapping": "no mapping file"}
    with path.open("rb") as fh:
        data = tomllib.load(fh)
    version = f"category_techniques@{data['version']}"
    known = repo.technique_ids(session)
    categories = {c.code: c.attack_category_id for c in session.scalars(select(DimAttackCategory))}
    applied, skipped = 0, []
    for entry in data.get("mapping", []):
        cid = categories.get(entry["category"])
        tid = entry["technique_id"]
        status = known.get(tid)
        if cid is None or status is None or status[0] or status[1]:
            skipped.append(
                {
                    "category": entry["category"],
                    "technique_id": tid,
                    "reason": "unknown category"
                    if cid is None
                    else "technique not in imported ATT&CK data"
                    if status is None
                    else "technique deprecated or revoked",
                }
            )
            continue
        existing = session.get(AttackCategoryTechnique, (cid, tid))
        if existing is None:
            session.add(
                AttackCategoryTechnique(
                    attack_category_id=cid,
                    technique_id=tid,
                    mapping_confidence=entry["confidence"],
                    rationale=entry["rationale"],
                    mapping_version=version,
                )
            )
        else:
            existing.mapping_confidence, existing.rationale = (
                entry["confidence"],
                entry["rationale"],
            )
            existing.mapping_version = version
        applied += 1
    return {"mappings_applied": applied, "mappings_skipped": skipped}


def attack_categories(session: Session) -> list[dict[str, Any]]:
    with session.begin():
        return repo.category_mappings(session)


def attack_techniques(
    session: Session, tactic: str | None, q: str | None, limit: int
) -> list[dict[str, Any]]:
    with session.begin():
        return [
            {
                "technique_id": t.technique_id,
                "name": t.name,
                "tactics": t.tactics,
                "is_subtechnique": t.is_subtechnique,
                "attack_version": t.attack_version,
                "deprecated": t.deprecated,
                "revoked": t.revoked,
                "url": t.url,
            }
            for t in repo.search_techniques(session, tactic, q, limit)
        ]


def reliability_weight(grade: str) -> float:
    return RELIABILITY_WEIGHTS.get(grade, RELIABILITY_WEIGHTS["F"])
