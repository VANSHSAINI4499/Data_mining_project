"""Schemas for sources, adapters, assets, ingestion batches, and data quality."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.common import RequestModel

SourceType = Literal["dataset", "network_sensor", "ids", "auth", "endpoint", "ti_feed", "other"]
Reliability = Literal["A", "B", "C", "D", "E", "F"]


class SourceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    source_id: int
    source_key: str
    name: str
    source_type: str
    default_adapter: str | None
    default_timezone: str | None
    reliability: str
    description: str | None
    is_active: bool
    created_at: datetime


class SourceDetail(SourceOut):
    counts: dict[str, int]


class SourceCreate(RequestModel):
    source_key: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{1,63}$")
    name: str = Field(min_length=1, max_length=200)
    source_type: SourceType
    default_adapter: str | None = Field(default=None, max_length=64)
    default_timezone: str | None = Field(default=None, max_length=64)
    reliability: Reliability = "F"
    description: str | None = Field(default=None, max_length=2000)


class SourceUpdate(RequestModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    default_adapter: str | None = Field(default=None, max_length=64)
    default_timezone: str | None = Field(default=None, max_length=64)
    reliability: Reliability | None = None
    description: str | None = Field(default=None, max_length=2000)
    is_active: bool | None = None


class AdapterOut(BaseModel):
    name: str
    version: str
    description: str
    extensions: list[str]
    event_types: list[str]
    variants: list[str]
    label_mapping: str | None


class AssetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    asset_key: int
    asset_id: str
    hostname: str | None
    ip_address: Any
    criticality: str
    owner: str | None
    environment: str | None
    valid_from: datetime


class AssetImportOut(BaseModel):
    created: int
    updated: int
    unchanged: int
    rejected: list[dict[str, Any]]
    note: str


class BatchOut(BaseModel):
    """Batch view. ``stored_path`` is deliberately not exposed."""

    model_config = ConfigDict(from_attributes=True)

    batch_id: uuid.UUID
    source_id: int
    adapter: str
    adapter_version: str
    original_filename: str
    file_sha256: str
    file_size_bytes: int
    status: str
    records_total: int
    records_loaded: int
    records_rejected: int
    records_duplicate: int
    last_committed_record: int
    timezone_assumption: str | None
    label_mapping_version: str | None
    batch_metadata: dict[str, Any] = Field(serialization_alias="metadata")
    error_summary: dict[str, Any] | None
    duplicate_of: uuid.UUID | None
    job_id: uuid.UUID | None
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None


class UploadAccepted(BaseModel):
    batch_id: uuid.UUID
    status: str
    job_id: uuid.UUID | None = None
    duplicate_of: uuid.UUID | None = None
    links: dict[str, str]


class RejectionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    record_number: int
    error_code: str
    field_name: str | None
    error_detail: str


class RejectionPage(BaseModel):
    items: list[RejectionOut]
    next_cursor: str | None
    limit: int
    total: int


class DqResultOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    check_name: str
    status: str
    metric_value: float | None
    threshold: float | None
    details: dict[str, Any]
    checked_at: datetime
