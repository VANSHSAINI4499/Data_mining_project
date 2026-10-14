"""Per-batch data-quality checks (DATA_INGESTION.md §10).

Results are derived data: re-running replaces the batch's previous results. Every check is
computed from stored rows/counters, never estimated.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from app.core import clock
from app.core.errors import NotFoundError
from app.ingestion.adapters import get_adapter_class
from app.models import DataQualityResult
from app.repositories import data_quality as dq_repo
from app.repositories import ingestion as ingestion_repo

REJECTION_WARN, REJECTION_FAIL = 0.05, 0.20
DUPLICATE_WARN = 0.50


@dataclass(frozen=True)
class Check:
    name: str
    status: str  # pass | warn | fail
    metric: float | None = None
    threshold: float | None = None
    details: dict[str, Any] | None = None


def _ratio(part: int, whole: int) -> float:
    return part / whole if whole else 0.0


def evaluate(session: Session, batch_id: uuid.UUID, now: datetime) -> list[Check]:
    batch = ingestion_repo.get_batch(session, batch_id)
    if batch is None:
        raise NotFoundError(f"batch {batch_id} not found")
    total, loaded = batch.records_total, batch.records_loaded
    rejected, duplicate = batch.records_rejected, batch.records_duplicate
    meta = batch.batch_metadata
    checks: list[Check] = []

    reconciles = total == loaded + rejected + duplicate
    checks.append(
        Check(
            "counter_reconciliation",
            "pass" if reconciles else "fail",
            details={
                "total": total,
                "loaded": loaded,
                "rejected": rejected,
                "duplicate": duplicate,
            },
        )
    )
    checks.append(Check("records_present", "pass" if total else "warn", float(total), None))

    rej = _ratio(rejected, total)
    checks.append(
        Check(
            "rejection_ratio",
            "fail" if rej > REJECTION_FAIL else "warn" if rej > REJECTION_WARN else "pass",
            rej,
            REJECTION_WARN,
            {"by_code": dq_repo.rejection_counts(session, batch_id)},
        )
    )

    dup = _ratio(duplicate, total)
    checks.append(
        Check("duplicate_ratio", "warn" if dup > DUPLICATE_WARN else "pass", dup, DUPLICATE_WARN)
    )

    adapter_cls = get_adapter_class(batch.adapter)
    expected = adapter_cls.expected_fields if adapter_cls else {}
    if loaded and expected:
        nulls = dq_repo.null_counts(session, batch_id, sorted(expected))
        for field_name, threshold in sorted(expected.items()):
            rate = _ratio(nulls[field_name], loaded)
            checks.append(
                Check(
                    f"null_rate:{field_name}",
                    "warn" if rate > threshold else "pass",
                    rate,
                    threshold,
                )
            )

    field_warnings: dict[str, dict[str, int]] = meta.get("field_warnings", {})
    invalid = sum(sum(codes.values()) for codes in field_warnings.values())
    checks.append(
        Check(
            "invalid_optional_values",
            "warn" if invalid else "pass",
            float(invalid),
            None,
            {"by_field": field_warnings},
        )
    )

    non_finite = int(meta.get("non_finite_values", 0))
    checks.append(Check("non_finite_values", "warn" if non_finite else "pass", float(non_finite)))

    future = dq_repo.future_event_count(session, batch_id, now)
    checks.append(
        Check(
            "timestamp_range",
            "warn" if future else "pass",
            float(future),
            None,
            {"events_after_check_time": future},
        )
    )

    assumed = dq_repo.assumed_time_count(session, batch_id)
    checks.append(
        Check(
            "time_quality_assumed",
            "warn" if assumed else "pass",
            float(assumed),
            None,
            {"note": "assumed timestamps are excluded from anomaly mining and temporal correlation"}
            if assumed
            else None,
        )
    )

    in_default = dq_repo.default_partition_count(session)
    checks.append(
        Check("default_partition_empty", "fail" if in_default else "pass", float(in_default))
    )

    label_status = dq_repo.label_status_counts(session, batch_id)
    not_mapped = label_status.get("unmapped", 0) + label_status.get("ambiguous", 0)
    if label_status:
        checks.append(
            Check(
                "unmapped_labels",
                "warn" if not_mapped else "pass",
                float(not_mapped),
                None,
                {"by_status": label_status, "values": meta.get("unmapped_labels", {})},
            )
        )
    return checks


def run_checks(session: Session, batch_id: uuid.UUID) -> list[DataQualityResult]:
    now = clock.now()
    with session.begin():
        checks = evaluate(session, batch_id, now)
        rows = dq_repo.replace_results(
            session,
            batch_id,
            [
                {
                    "check_name": c.name,
                    "status": c.status,
                    "metric_value": c.metric,
                    "threshold": c.threshold,
                    "details": c.details or {},
                    "checked_at": now,
                }
                for c in checks
            ],
        )
    return rows


def batch_results(session: Session, batch_id: uuid.UUID) -> list[DataQualityResult]:
    with session.begin():
        if ingestion_repo.get_batch(session, batch_id) is None:
            raise NotFoundError(f"batch {batch_id} not found")
        return dq_repo.results_for_batch(session, batch_id)


def summary(session: Session, *, start: datetime, end: datetime) -> dict[str, Any]:
    with session.begin():
        return {
            "from": start,
            "to": end,
            "by_source": dq_repo.status_counts_by_source(session, start, end),
            "latest_failures": [
                {
                    "batch_id": r.batch_id,
                    "check_name": r.check_name,
                    "status": r.status,
                    "metric_value": r.metric_value,
                    "checked_at": r.checked_at,
                }
                for r in dq_repo.latest_problems(session, start, end, limit=20)
            ],
        }
