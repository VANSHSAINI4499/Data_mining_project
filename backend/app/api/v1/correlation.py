"""Correlation rule and run endpoints (API_SPECIFICATION.md §5.13)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, status
from pydantic import Field

from app.api.deps import Admin, Analyst, Viewer
from app.api.v1.router_prefix import API_PREFIX
from app.core.db import DbSession
from app.schemas.common import RequestModel
from app.services import correlation, patterns

router = APIRouter(prefix="/correlation", tags=["correlation"])


class EnabledBody(RequestModel):
    enabled: bool


class RunBody(RequestModel):
    from_: datetime = Field(alias="from")
    to: datetime
    rule_keys: list[str] | None = Field(default=None, max_length=100)


@router.get("/rules")
def list_rules(principal: Viewer, session: DbSession) -> list[dict[str, Any]]:
    return correlation.list_rules(session)


@router.get("/rules/{rule_key}/versions")
def rule_versions(rule_key: str, principal: Viewer, session: DbSession) -> list[dict[str, Any]]:
    return correlation.rule_versions(session, rule_key)


# Rule bodies are validated by the rule DSL model (app.correlation.rules.RuleDefinition),
# which rejects unknown fields, filters, and operators.
@router.post("/rules", status_code=status.HTTP_201_CREATED)
def create_rule(body: dict[str, Any], principal: Admin, session: DbSession) -> dict[str, Any]:
    return correlation.create_rule(session, principal.actor, body)


@router.put("/rules/{rule_key}")
def new_version(
    rule_key: str, body: dict[str, Any], principal: Admin, session: DbSession
) -> dict[str, Any]:
    return correlation.new_version(session, principal.actor, rule_key, body)


@router.patch("/rules/{rule_key}")
def set_enabled(
    rule_key: str, body: EnabledBody, principal: Admin, session: DbSession
) -> dict[str, Any]:
    return correlation.set_enabled(session, principal.actor, rule_key, body.enabled)


@router.post("/runs", status_code=status.HTTP_202_ACCEPTED)
def start_run(body: RunBody, principal: Analyst, session: DbSession) -> dict[str, Any]:
    job_id = correlation.start_run(session, principal.actor, body.from_, body.to, body.rule_keys)
    return {
        "job_id": str(job_id),
        "status": "queued",
        "links": {"job": f"{API_PREFIX}/jobs/{job_id}"},
    }


class MiningBody(RequestModel):
    entity_type: str = Field(pattern="^(account|src_ip|dst_ip|host)$")
    from_: datetime = Field(alias="from")
    to: datetime
    min_support: int = Field(default=2, ge=1, le=100_000)
    max_length: int = Field(default=3, ge=2, le=5)
    max_gap_minutes: int = Field(default=30, ge=1, le=1440)
    min_malicious_ratio: float = Field(default=0.5, ge=0, le=1)


@router.post("/pattern-runs", status_code=status.HTTP_202_ACCEPTED)
def start_pattern_run(body: MiningBody, principal: Analyst, session: DbSession) -> dict[str, Any]:
    params = patterns.parse(
        body.model_dump(exclude={"from_", "to"}) | {"start": body.from_, "end": body.to}
    )
    job_id = patterns.start(session, principal.actor, params)
    return {
        "job_id": str(job_id),
        "status": "queued",
        "links": {"job": f"{API_PREFIX}/jobs/{job_id}"},
    }


@router.get("/pattern-runs")
def list_pattern_runs(principal: Viewer, session: DbSession) -> list[dict[str, Any]]:
    return patterns.list_runs(session)


@router.get("/pattern-runs/{run_id}")
def get_pattern_run(run_id: uuid.UUID, principal: Viewer, session: DbSession) -> dict[str, Any]:
    return patterns.get_run(session, run_id)
