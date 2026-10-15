"""Overview payload for the dashboard (API_SPECIFICATION.md §5.16).

Every number is computed from the database at request time; each section says when it was
computed (``as_of``) and whether there is anything to show (``is_empty``).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core import clock
from app.core.errors import ValidationFailedError
from app.correlation.risk import severity_label
from app.models import (
    Alert,
    AnomalyResult,
    DataQualityResult,
    DimSource,
    FactSecurityEvent,
    IndicatorMatch,
    IngestionBatch,
    MlModel,
    MlTrainingRun,
    TiFeed,
    TiIndicator,
)
from app.repositories.ti import indicator_state_now

OPEN_ALERT_STATUSES = ("new", "acknowledged", "in_review", "escalated")
SEVERITIES = ("critical", "high", "medium", "low")


def _section(data: dict[str, Any], empty: bool, now: datetime) -> dict[str, Any]:
    return {"as_of": now, "is_empty": empty, **data}


def _classifier_summary(session: Session, model: MlModel, run: MlTrainingRun) -> dict[str, Any]:
    metrics = run.metrics or {}
    test = metrics.get("models", {}).get(model.algorithm, {}).get("test", {})
    batch_ids = [uuid.UUID(b) for b in (run.dataset_snapshot or {}).get("batch_ids", [])]
    datasets = sorted(
        session.scalars(
            select(DimSource.name)
            .join(IngestionBatch, IngestionBatch.source_id == DimSource.source_id)
            .where(IngestionBatch.batch_id.in_(batch_ids))
            .distinct()
        )
    )
    return {
        "test_metrics": {
            key: test.get(key)
            for key in ("macro_f1", "weighted_f1", "balanced_accuracy", "accuracy", "rows")
        }
        | {"malicious_recall": test.get("binary", {}).get("malicious_recall")},
        "evaluated_on": {
            "split": "held-out test split of the training snapshot",
            "datasets": datasets,
            "snapshot_rows": (run.dataset_snapshot or {}).get("rows"),
        },
    }


def _anomaly_summary(model: MlModel, run: MlTrainingRun) -> dict[str, Any]:
    reference = (run.metrics or {}).get("reference", {})
    return {
        "reference_period": {k: reference.get(k) for k in ("start", "end", "windows", "entities")},
        "threshold": (run.metrics or {}).get("threshold"),
        "note": "anomaly scores are not probabilities; no labelled test metrics exist",
    }


def overview(session: Session, start: datetime, end: datetime) -> dict[str, Any]:
    if start.tzinfo is None or end.tzinfo is None or end <= start:
        raise ValidationFailedError("overview needs timezone-aware from < to")
    now = clock.now()
    F = FactSecurityEvent
    with session.begin():
        by_type = dict(
            session.execute(
                select(F.event_type, func.count())
                .where(F.event_time >= start, F.event_time < end)
                .group_by(F.event_type)
            ).all()
        )
        batches = dict(
            session.execute(
                select(IngestionBatch.status, func.count()).group_by(IngestionBatch.status)
            ).all()
        )
        model_rows = session.execute(
            select(MlModel, MlTrainingRun)
            .join(MlTrainingRun, MlTrainingRun.run_id == MlModel.training_run_id)
            .where(MlModel.status == "active")
            .order_by(MlModel.task, MlModel.name)
        ).all()
        models = []
        for model, run in model_rows:
            entry: dict[str, Any] = {
                "model_id": model.model_id,
                "name": model.name,
                "version": model.version,
                "task": model.task,
                "algorithm": model.algorithm,
                "promoted_at": model.promoted_at,
            }
            if model.task == "classification":
                entry |= _classifier_summary(session, model, run)
            elif model.task == "web_payload_classification":
                test = (
                    (run.metrics or {})
                    .get("models", {})
                    .get((run.metrics or {}).get("primary_model", ""), {})
                    .get("test", {})
                )
                entry |= {
                    "test_metrics": {
                        k: test.get(k) for k in ("macro_f1", "weighted_f1", "accuracy", "rows")
                    },
                    "evaluated_on": {
                        "split": "held-out grouped test split of HTTPParamsDataset payloads",
                        "datasets": ["HTTPParamsDataset (HTTP parameter values)"],
                        "snapshot_rows": (run.dataset_snapshot or {}).get("rows"),
                    },
                }
            else:
                entry |= _anomaly_summary(model, run)
            models.append(entry)
        alert_rows = session.execute(
            select(Alert.risk_score, Alert.status).where(
                Alert.status.in_(OPEN_ALERT_STATUSES),
                Alert.last_event_time >= start,
                Alert.first_event_time < end,
            )
        ).all()
        flagged = session.scalar(
            select(func.count())
            .select_from(AnomalyResult)
            .join(MlModel, MlModel.model_id == AnomalyResult.model_id)
            .where(
                AnomalyResult.is_flagged.is_(True),
                MlModel.status == "active",
                AnomalyResult.window_start >= start,
                AnomalyResult.window_start < end,
            )
        )
        active_indicators = session.scalar(
            select(func.count())
            .select_from(TiIndicator)
            .join(TiFeed, TiFeed.feed_id == TiIndicator.feed_id)
            .where(indicator_state_now(now) == "active")
        )
        matches = session.scalar(
            select(func.count())
            .select_from(IndicatorMatch)
            .where(IndicatorMatch.event_time >= start, IndicatorMatch.event_time < end)
        )
        dq = session.execute(
            select(
                DataQualityResult.check_name,
                DataQualityResult.batch_id,
                DataQualityResult.status,
                DataQualityResult.checked_at,
            )
            .where(DataQualityResult.status.in_(("fail", "warn")))
            .order_by(DataQualityResult.checked_at.desc())
            .limit(20)
        ).all()
        dq_counts = dict(
            session.execute(
                select(DataQualityResult.status, func.count()).group_by(DataQualityResult.status)
            ).all()
        )

    by_severity = dict.fromkeys(SEVERITIES, 0)
    by_status: dict[str, int] = {}
    for score, status in alert_rows:
        by_severity[severity_label(score)] += 1
        by_status[status] = by_status.get(status, 0) + 1
    return {
        "range": {"from": start, "to": end},
        "events": _section({"total": sum(by_type.values()), "by_type": by_type}, not by_type, now),
        "ingestion": _section({"batches_by_status": batches}, not batches, now),
        "models": _section({"active": models}, not models, now),
        "alerts": _section(
            {
                "open_total": len(alert_rows),
                "open_by_severity": by_severity,
                "open_by_status": by_status,
                "note": "alerts are hypotheses for review, not confirmed incidents",
            },
            not alert_rows,
            now,
        ),
        "anomalies": _section({"flagged": flagged or 0}, not flagged, now),
        "threat_intel": _section(
            {"active_indicators": active_indicators or 0, "matches": matches or 0},
            not active_indicators and not matches,
            now,
        ),
        "data_quality": _section(
            {
                "status_counts": dq_counts,
                "recent_problems": [
                    {"check_name": c, "batch_id": b, "status": s, "checked_at": t}
                    for c, b, s, t in dq
                ],
            },
            not dq_counts,
            now,
        ),
    }
