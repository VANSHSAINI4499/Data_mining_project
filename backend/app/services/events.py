"""Event exploration and historical aggregations (API_SPECIFICATION.md §5.7, §5.8)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.errors import FieldError, NotFoundError, ValidationFailedError
from app.core.pagination import DEFAULT_LIMIT, decode_cursor, encode_cursor
from app.ingestion.normalize import FieldError as NormalizeFieldError
from app.ingestion.normalize import parse_ip
from app.repositories import events as repo
from app.repositories.events import EventFilters

__all__ = ["EventFilters"]

TOP_GROUP_KEYS = 10
TOP_DIMENSIONS = frozenset(repo.TOP_DIMENSIONS)
DISTRIBUTION_DIMENSIONS = frozenset({"event_type", "protocol", "ground_truth_category", "source"})
TIMESERIES_GROUPS = frozenset({"event_type", "source", "ground_truth_category"})
INTERVALS = frozenset(repo.INTERVALS)
METRICS = frozenset({"event_count", "bytes_total"})


def validate_filters(f: EventFilters, max_days: int) -> EventFilters:
    problems: list[FieldError] = []
    if f.start.tzinfo is None or f.end.tzinfo is None:
        problems.append(FieldError("from", "timezone_required", "timestamps need a timezone"))
    elif f.end <= f.start:
        problems.append(FieldError("to", "invalid_range", "'to' must be after 'from'"))
    elif f.end - f.start > timedelta(days=max_days):
        problems.append(FieldError("to", "range_too_large", f"maximum span is {max_days} days"))
    for name in ("src_ip", "dst_ip", "ip"):
        value = getattr(f, name)
        if value:
            try:
                setattr(f, name, parse_ip(value))
            except NormalizeFieldError:
                problems.append(FieldError(name, "invalid_ip", "not an IP address"))
    if problems:
        raise ValidationFailedError("invalid event filters", errors=problems)
    return f


@dataclass(frozen=True)
class EventPage:
    items: list[dict[str, Any]]
    next_cursor: str | None
    limit: int


def search(
    session: Session,
    settings: Settings,
    f: EventFilters,
    cursor: str | None,
    limit: int = DEFAULT_LIMIT,
) -> EventPage:
    validate_filters(f, settings.max_query_days)
    key = decode_cursor(cursor, frozenset({"t", "id"}))
    after = None
    if key is not None:
        try:
            after = (datetime.fromisoformat(key["t"]), int(key["id"]))
        except (TypeError, ValueError) as exc:
            raise ValidationFailedError(
                "invalid cursor", errors=[FieldError("cursor", "invalid_cursor", "malformed")]
            ) from exc
    with session.begin():
        rows = repo.search_events(session, f, after, limit + 1)
    items = rows[:limit]
    next_cursor = None
    if len(rows) > limit:
        last = items[-1]
        next_cursor = encode_cursor({"t": last["event_time"].isoformat(), "id": last["event_id"]})
    return EventPage(items, next_cursor, limit)


OBSERVED_FIELDS = (
    "event_type",
    "event_time",
    "event_end_time",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "protocol",
    "ip_proto",
    "app_protocol",
    "direction",
    "conn_state",
    "duration_s",
    "bytes_out",
    "bytes_in",
    "packets_out",
    "packets_in",
    "user_name",
    "auth_result",
    "auth_method",
    "service",
    "host_name",
    "process_name",
    "process_command_line",
    "parent_process_name",
    "file_path",
    "file_sha256",
    "dns_query",
    "http_host",
    "url",
    "signature_id",
    "signature",
    "alert_category",
    "source_severity",
    "source_event_id",
    "attributes",
)


def detail(session: Session, event_id: int, event_time: datetime | None) -> dict[str, Any]:
    with session.begin():
        found = repo.get_event(session, event_id, event_time)
        if found is None:
            raise NotFoundError(f"event {event_id} not found")
        event, batch, source, raw = found
        truth = repo.get_ground_truth(session, event.event_id, event.event_time)
        result: dict[str, Any] = {
            "event_id": str(event.event_id),
            # Observed facts only. Model outputs, threat intel, alerts, and analyst feedback
            # are added to this response by the phases that create them.
            "observed": {name: getattr(event, name) for name in OBSERVED_FIELDS},
            "provenance": {
                "source": {
                    "source_id": source.source_id,
                    "source_key": source.source_key,
                    "name": source.name,
                },
                "batch_id": batch.batch_id,
                "original_filename": batch.original_filename,
                "file_sha256": batch.file_sha256,
                "record_number": raw.record_number,
                "record_sha256": raw.record_sha256,
                "adapter_version": event.adapter_version,
                "normalizer_version": event.normalizer_version,
                "time_quality": event.time_quality,
                "timezone_assumption": batch.timezone_assumption,
                "ingested_at": event.ingested_at,
                "asset_keys": {"src": event.src_asset_key, "dst": event.dst_asset_key},
            },
            "ground_truth": None,
        }
        if truth is not None:
            gt, code = truth
            result["ground_truth"] = {
                "label_raw": gt.label_raw,
                "attack_category": code,
                "is_attack": gt.is_attack,
                "mapping_status": gt.mapping_status,
                "label_mapping_version": gt.label_mapping_version,
                "label_origin": gt.label_origin,
            }
    return result


def raw_record(session: Session, event_id: int, event_time: datetime | None) -> dict[str, Any]:
    with session.begin():
        found = repo.get_event(session, event_id, event_time)
        if found is None:
            raise NotFoundError(f"event {event_id} not found")
        _event, _batch, _source, raw = found
        return {
            "event_id": str(event_id),
            "record_number": raw.record_number,
            "record_sha256": raw.record_sha256,
            "raw_payload": raw.raw_payload,
            "raw_text": raw.raw_text,
            "raw_truncated": raw.raw_truncated,
            "raw_nul_escaped": raw.raw_nul_escaped,
        }


# --- aggregations ------------------------------------------------------------------------------


def _choice(value: str | None, allowed: frozenset[str], name: str, required: bool = True) -> None:
    if value is None and not required:
        return
    if value not in allowed:
        raise ValidationFailedError(
            f"invalid {name}",
            errors=[FieldError(name, "invalid_choice", f"one of {sorted(allowed)}")],
        )


def timeseries(
    session: Session,
    settings: Settings,
    f: EventFilters,
    *,
    interval: str,
    metric: str,
    group_by: str | None,
) -> dict[str, Any]:
    _choice(interval, INTERVALS, "interval")
    _choice(metric, METRICS, "metric")
    _choice(group_by, TIMESERIES_GROUPS, "group_by", required=False)
    validate_filters(f, settings.max_agg_days)
    with session.begin():
        rows = repo.timeseries(session, f, interval, metric, group_by)
    buckets: dict[datetime, dict[str, float]] = {}
    if group_by:
        totals: dict[str, float] = {}
        for _, key, value in rows:
            totals[str(key)] = totals.get(str(key), 0.0) + value
        keep = {
            k for k, _ in sorted(totals.items(), key=lambda kv: (-kv[1], kv[0]))[:TOP_GROUP_KEYS]
        }
        for bucket, key, value in rows:
            name = str(key) if key in keep else "other"
            series = buckets.setdefault(bucket, {})
            series[name] = series.get(name, 0.0) + value
    else:
        for bucket, _, value in rows:
            buckets[bucket] = {metric: value}
    return {
        "interval": interval,
        "metric": metric,
        "group_by": group_by,
        "from": f.start,
        "to": f.end,
        "buckets": [{"ts": ts, "series": series} for ts, series in sorted(buckets.items())],
    }


def top_entities(
    session: Session, settings: Settings, f: EventFilters, *, dimension: str, limit: int
) -> dict[str, Any]:
    _choice(dimension, TOP_DIMENSIONS, "dimension")
    validate_filters(f, settings.max_agg_days)
    with session.begin():
        rows = repo.top_entities(session, f, dimension, limit)
    return {
        "dimension": dimension,
        "from": f.start,
        "to": f.end,
        "items": [{"value": v, "count": n} for v, n in rows],
    }


def distribution(
    session: Session, settings: Settings, f: EventFilters, *, dimension: str
) -> dict[str, Any]:
    _choice(dimension, DISTRIBUTION_DIMENSIONS, "dimension")
    validate_filters(f, settings.max_agg_days)
    with session.begin():
        rows = repo.distribution(session, f, dimension)
    return {
        "dimension": dimension,
        "from": f.start,
        "to": f.end,
        "items": [{"value": v, "count": n} for v, n in rows],
    }
