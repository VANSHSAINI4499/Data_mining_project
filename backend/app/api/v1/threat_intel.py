"""Threat-intelligence and ATT&CK endpoints (API_SPECIFICATION.md §5.12)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, File, Form, Query, UploadFile, status
from pydantic import Field

from app.api.deps import Admin, Analyst, SettingsDep, Viewer, allow_query_params
from app.api.v1.router_prefix import API_PREFIX
from app.core.db import DbSession
from app.core.pagination import DEFAULT_LIMIT, MAX_LIMIT
from app.schemas.common import RequestModel
from app.services import threat_intel

router = APIRouter(tags=["threat-intel"])

IndicatorType = Literal["ipv4", "ipv6", "domain", "url", "sha256", "sha1", "md5", "email"]
Reliability = Literal["A", "B", "C", "D", "E", "F"]


class FeedCreate(RequestModel):
    feed_key: str = Field(min_length=2, max_length=64)
    name: str = Field(min_length=1, max_length=200)
    feed_type: Literal["manual", "csv_file", "stix_file", "taxii"]
    url: str | None = Field(default=None, max_length=2048)
    collection_id: str | None = Field(default=None, max_length=200)
    reliability: Reliability = "F"
    default_confidence: int = Field(default=50, ge=0, le=100)
    default_ttl_days: int = Field(default=90, ge=1, le=3650)
    enabled: bool = True
    poll_interval_minutes: int | None = Field(default=None, ge=15, le=7 * 24 * 60)
    credentials_ref: str | None = Field(default=None, max_length=64)


class FeedUpdate(RequestModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    url: str | None = Field(default=None, max_length=2048)
    collection_id: str | None = Field(default=None, max_length=200)
    reliability: Reliability | None = None
    default_confidence: int | None = Field(default=None, ge=0, le=100)
    default_ttl_days: int | None = Field(default=None, ge=1, le=3650)
    enabled: bool | None = None
    poll_interval_minutes: int | None = Field(default=None, ge=15, le=7 * 24 * 60)
    credentials_ref: str | None = Field(default=None, max_length=64)


class IndicatorCreate(RequestModel):
    indicator_type: IndicatorType
    value: str = Field(min_length=1, max_length=2048)
    confidence: int = Field(ge=0, le=100)
    valid_until: datetime | None = None
    description: str | None = Field(default=None, max_length=2000)
    tlp: Literal["TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED"] | None = None
    technique_ids: list[Annotated[str, Field(pattern=r"^T\d{4}(\.\d{3})?$")]] = Field(
        default_factory=list, max_length=50
    )


class IndicatorUpdate(RequestModel):
    confidence: int | None = Field(default=None, ge=0, le=100)
    valid_until: datetime | None = None
    revoked: bool | None = None
    description: str | None = Field(default=None, max_length=2000)


class MatchRunBody(RequestModel):
    from_: datetime | None = Field(default=None, alias="from")
    to: datetime | None = None
    batch_ids: list[uuid.UUID] | None = Field(default=None, max_length=100)
    include_expired: bool = False


@router.get("/threat-intel/feeds")
def list_feeds(principal: Viewer, session: DbSession) -> list[dict[str, Any]]:
    return threat_intel.list_feeds(session)


@router.post("/threat-intel/feeds", status_code=status.HTTP_201_CREATED)
def create_feed(body: FeedCreate, principal: Admin, session: DbSession) -> dict[str, Any]:
    return threat_intel.create_feed(session, principal.actor, body.model_dump())


@router.patch("/threat-intel/feeds/{feed_id}")
def update_feed(
    feed_id: uuid.UUID, body: FeedUpdate, principal: Admin, session: DbSession
) -> dict[str, Any]:
    return threat_intel.update_feed(
        session, principal.actor, feed_id, body.model_dump(exclude_unset=True)
    )


@router.post("/threat-intel/feeds/{feed_id}/sync", status_code=status.HTTP_202_ACCEPTED)
def sync_feed(feed_id: uuid.UUID, principal: Admin, session: DbSession) -> dict[str, Any]:
    threat_intel.sync_feed(session, principal.actor, feed_id)
    return {}  # pragma: no cover - sync_feed always raises until TAXII polling exists


@router.post("/threat-intel/imports", status_code=status.HTTP_202_ACCEPTED)
def import_indicators(
    principal: Admin,
    session: DbSession,
    settings: SettingsDep,
    file: Annotated[UploadFile, File()],
    feed_id: Annotated[uuid.UUID, Form()],
    format: Annotated[Literal["csv", "stix"], Form()],
) -> dict[str, Any]:
    data = file.file.read(threat_intel.MAX_IMPORT_BYTES + 1)
    run = threat_intel.start_import(
        session,
        settings,
        principal.actor,
        feed_id=feed_id,
        fmt=format,
        filename=file.filename or "upload",
        data=data,
    )
    return {
        "id": str(run.feed_run_id),
        "job_id": str(run.job_id),
        "status": run.status,
        "links": {
            "import": f"{API_PREFIX}/threat-intel/imports/{run.feed_run_id}",
            "job": f"{API_PREFIX}/jobs/{run.job_id}",
        },
    }


@router.get("/threat-intel/imports/{run_id}")
def get_import(run_id: uuid.UUID, principal: Viewer, session: DbSession) -> dict[str, Any]:
    run = threat_intel.get_feed_run(session, run_id)
    report = {k: v for k, v in run.report.items() if k != "stored_path"}
    return {
        "feed_run_id": run.feed_run_id,
        "feed_id": run.feed_id,
        "status": run.status,
        "source_description": run.source_description,
        "started_at": run.started_at,
        "finished_at": run.finished_at,
        "indicators_received": run.indicators_received,
        "indicators_created": run.indicators_created,
        "indicators_updated": run.indicators_updated,
        "indicators_rejected": run.indicators_rejected,
        "error": run.error,
        "report": report,
        "job_id": run.job_id,
    }


@router.get(
    "/threat-intel/indicators",
    dependencies=[
        Depends(
            allow_query_params(
                "indicator_type", "feed_id", "state", "min_confidence", "value", "cursor", "limit"
            )
        )
    ],
)
def list_indicators(
    principal: Viewer,
    session: DbSession,
    indicator_type: IndicatorType | None = None,
    feed_id: uuid.UUID | None = None,
    state: Literal["active", "expired", "revoked"] | None = None,
    min_confidence: Annotated[int | None, Query(ge=0, le=100)] = None,
    value: Annotated[str | None, Query(max_length=2048)] = None,
    cursor: Annotated[int | None, Query(ge=0)] = None,
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = DEFAULT_LIMIT,
) -> dict[str, Any]:
    return threat_intel.list_indicators(
        session,
        indicator_type=indicator_type,
        feed_id=feed_id,
        state=state,
        min_confidence=min_confidence,
        value=value,
        cursor=cursor,
        limit=limit,
    )


@router.post("/threat-intel/indicators", status_code=status.HTTP_201_CREATED)
def create_indicator(body: IndicatorCreate, principal: Admin, session: DbSession) -> dict[str, Any]:
    return threat_intel.create_manual(session, principal.actor, body.model_dump())


@router.get("/threat-intel/indicators/{indicator_id}")
def get_indicator(indicator_id: int, principal: Viewer, session: DbSession) -> dict[str, Any]:
    return threat_intel.get_indicator(session, indicator_id)


@router.patch("/threat-intel/indicators/{indicator_id}")
def update_indicator(
    indicator_id: int, body: IndicatorUpdate, principal: Admin, session: DbSession
) -> dict[str, Any]:
    return threat_intel.update_indicator(
        session, principal.actor, indicator_id, body.model_dump(exclude_unset=True)
    )


@router.post("/threat-intel/match-runs", status_code=status.HTTP_202_ACCEPTED)
def start_match_run(body: MatchRunBody, principal: Analyst, session: DbSession) -> dict[str, Any]:
    job_id = threat_intel.start_match_run(
        session,
        principal.actor,
        start=body.from_,
        end=body.to,
        batch_ids=body.batch_ids,
        include_expired=body.include_expired,
    )
    return {
        "job_id": str(job_id),
        "status": "queued",
        "links": {"job": f"{API_PREFIX}/jobs/{job_id}"},
    }


@router.get(
    "/threat-intel/matches",
    dependencies=[
        Depends(allow_query_params("indicator_id", "state", "from", "to", "cursor", "limit"))
    ],
)
def list_matches(
    principal: Viewer,
    session: DbSession,
    indicator_id: int | None = None,
    state: Literal["active", "expired", "revoked"] | None = None,
    start: Annotated[datetime | None, Query(alias="from")] = None,
    end: Annotated[datetime | None, Query(alias="to")] = None,
    cursor: Annotated[int | None, Query(ge=0)] = None,
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = DEFAULT_LIMIT,
) -> dict[str, Any]:
    return threat_intel.list_matches(
        session,
        indicator_id=indicator_id,
        state=state,
        start=start,
        end=end,
        cursor=cursor,
        limit=limit,
    )


@router.get(
    "/attack/techniques",
    dependencies=[Depends(allow_query_params("tactic", "q", "limit"))],
)
def list_techniques(
    principal: Viewer,
    session: DbSession,
    tactic: Annotated[str | None, Query(max_length=64)] = None,
    q: Annotated[str | None, Query(max_length=100)] = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 200,
) -> list[dict[str, Any]]:
    return threat_intel.attack_techniques(session, tactic, q, limit)


@router.get("/attack/categories")
def list_categories(principal: Viewer, session: DbSession) -> list[dict[str, Any]]:
    return threat_intel.attack_categories(session)
