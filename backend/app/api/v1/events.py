"""Events, historical aggregations, data quality (API_SPECIFICATION.md §5.7, §5.8, §5.17)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query

from app.api.deps import Analyst, SettingsDep, Viewer, allow_query_params
from app.core.db import DbSession
from app.core.pagination import DEFAULT_LIMIT, MAX_LIMIT
from app.schemas.ingestion import DqResultOut
from app.services import data_quality
from app.services import events as events_service
from app.services.events import EventFilters

router = APIRouter(tags=["events"])

FILTER_PARAMS = (
    "from",
    "to",
    "source_id",
    "batch_id",
    "event_type",
    "src_ip",
    "dst_ip",
    "ip",
    "dst_port",
    "protocol",
    "user_name",
    "host_name",
    "signature_id",
    "ground_truth_category",
    "time_quality",
    "predicted_category",
    "min_predicted_score",
)


def event_filters(
    start: Annotated[datetime, Query(alias="from")],
    end: Annotated[datetime, Query(alias="to")],
    source_id: Annotated[list[int] | None, Query()] = None,
    batch_id: uuid.UUID | None = None,
    event_type: Annotated[list[str] | None, Query()] = None,
    src_ip: Annotated[str | None, Query(max_length=64)] = None,
    dst_ip: Annotated[str | None, Query(max_length=64)] = None,
    ip: Annotated[str | None, Query(max_length=64)] = None,
    dst_port: Annotated[int | None, Query(ge=0, le=65535)] = None,
    protocol: Annotated[str | None, Query(max_length=32)] = None,
    user_name: Annotated[str | None, Query(max_length=256)] = None,
    host_name: Annotated[str | None, Query(max_length=255)] = None,
    signature_id: Annotated[int | None, Query(ge=0)] = None,
    ground_truth_category: Annotated[list[str] | None, Query()] = None,
    time_quality: Annotated[str | None, Query(pattern="^(exact|second|assumed)$")] = None,
    predicted_category: Annotated[list[str] | None, Query()] = None,
    min_predicted_score: Annotated[float | None, Query(ge=0, le=1)] = None,
) -> EventFilters:
    return EventFilters(
        start=start,
        end=end,
        source_ids=source_id or [],
        batch_id=batch_id,
        event_types=event_type or [],
        src_ip=src_ip,
        dst_ip=dst_ip,
        ip=ip,
        dst_port=dst_port,
        protocol=protocol.lower() if protocol else None,
        user_name=user_name,
        host_name=host_name,
        signature_id=signature_id,
        ground_truth_categories=[c.upper() for c in ground_truth_category or []],
        time_quality=time_quality,
        predicted_categories=[c.upper() for c in predicted_category or []],
        min_predicted_score=min_predicted_score,
    )


Filters = Annotated[EventFilters, Depends(event_filters)]


def _summary(row: dict[str, Any]) -> dict[str, Any]:
    out = dict(row)
    out["event_id"] = str(row["event_id"])  # avoid JavaScript precision loss
    for key in ("src_ip", "dst_ip"):
        out[key] = str(row[key]).split("/")[0] if row[key] is not None else None
    return out


@router.get(
    "/events", dependencies=[Depends(allow_query_params(*FILTER_PARAMS, "cursor", "limit"))]
)
def list_events(
    principal: Viewer,
    session: DbSession,
    settings: SettingsDep,
    filters: Filters,
    cursor: str | None = None,
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = DEFAULT_LIMIT,
) -> dict[str, Any]:
    page = events_service.search(session, settings, filters, cursor, limit)
    return {
        "items": [_summary(r) for r in page.items],
        "next_cursor": page.next_cursor,
        "limit": page.limit,
    }


def _ip_text(value: Any) -> Any:
    return str(value).split("/")[0] if value is not None else None


@router.get("/events/{event_id}", dependencies=[Depends(allow_query_params("event_time"))])
def get_event(
    event_id: int, principal: Viewer, session: DbSession, event_time: datetime | None = None
) -> dict[str, Any]:
    result = events_service.detail(session, event_id, event_time)
    observed = result["observed"]
    observed["src_ip"], observed["dst_ip"] = (
        _ip_text(observed["src_ip"]),
        _ip_text(observed["dst_ip"]),
    )
    return result


@router.get("/events/{event_id}/raw", dependencies=[Depends(allow_query_params("event_time"))])
def get_event_raw(
    event_id: int, principal: Analyst, session: DbSession, event_time: datetime | None = None
) -> dict[str, Any]:
    """The raw record as JSON data; clients must never render it as HTML."""
    return events_service.raw_record(session, event_id, event_time)


@router.get(
    "/analytics/timeseries",
    dependencies=[Depends(allow_query_params(*FILTER_PARAMS, "interval", "metric", "group_by"))],
)
def timeseries(
    principal: Viewer,
    session: DbSession,
    settings: SettingsDep,
    filters: Filters,
    interval: str = "day",
    metric: str = "event_count",
    group_by: str | None = None,
) -> dict[str, Any]:
    return events_service.timeseries(
        session, settings, filters, interval=interval, metric=metric, group_by=group_by
    )


@router.get(
    "/analytics/top-entities",
    dependencies=[Depends(allow_query_params(*FILTER_PARAMS, "dimension", "limit"))],
)
def top_entities(
    principal: Viewer,
    session: DbSession,
    settings: SettingsDep,
    filters: Filters,
    dimension: str,
    limit: Annotated[int, Query(ge=1, le=50)] = 10,
) -> dict[str, Any]:
    return events_service.top_entities(session, settings, filters, dimension=dimension, limit=limit)


@router.get(
    "/analytics/distribution",
    dependencies=[Depends(allow_query_params(*FILTER_PARAMS, "dimension"))],
)
def distribution(
    principal: Viewer, session: DbSession, settings: SettingsDep, filters: Filters, dimension: str
) -> dict[str, Any]:
    return events_service.distribution(session, settings, filters, dimension=dimension)


@router.get("/data-quality/summary", dependencies=[Depends(allow_query_params("from", "to"))])
def dq_summary(
    principal: Viewer,
    session: DbSession,
    start: Annotated[datetime, Query(alias="from")],
    end: Annotated[datetime, Query(alias="to")],
) -> dict[str, Any]:
    return data_quality.summary(session, start=start, end=end)


@router.get("/data-quality/batches/{batch_id}", response_model=list[DqResultOut])
def dq_batch(batch_id: uuid.UUID, principal: Viewer, session: DbSession) -> list[DqResultOut]:
    return [DqResultOut.model_validate(r) for r in data_quality.batch_results(session, batch_id)]
