"""Concept-drift reports (ANOMALY_DETECTION.md §11, Phase 8).

Reports are informational: they record PSI values and warnings for a model and recommend
retraining when drift is found. Nothing here retrains, re-thresholds, or promotes models.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from typing import Any

import pandas as pd
from sqlalchemy import Text as SqlText
from sqlalchemy import and_, cast, func, select
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings
from app.core.errors import NotFoundError, ValidationFailedError
from app.ml import drift as psi
from app.ml.anomaly.windows import FEATURES, build_windows
from app.models import (
    AnalystFeedback,
    AnomalyResult,
    ClassificationResult,
    DimAttackCategory,
    DriftReport,
    MlModel,
    MlTrainingRun,
)
from app.repositories import anomaly as anomaly_repo
from app.services import audit
from app.services import jobs as jobs_service
from app.services.actors import Actor

JOB_TYPE = "ml.drift"
MIN_ROWS = 100
MIN_WINDOWS = 20
FLAG_RATE_FACTOR = 3.0
MIN_EXPECTED_FLAGS = 5
RECOMMENDATION = "review the model and consider retraining; no automatic action is taken"


def _check_range(start: datetime, end: datetime) -> None:
    if start.tzinfo is None or end.tzinfo is None or end <= start:
        raise ValidationFailedError("drift periods need timezone-aware from < to")


def _classifier_rows(
    session: Session, model_id: uuid.UUID, start: datetime, end: datetime
) -> tuple[list[str], list[float]]:
    rows = session.execute(
        select(DimAttackCategory.code, ClassificationResult.predicted_score)
        .join(
            DimAttackCategory,
            DimAttackCategory.attack_category_id == ClassificationResult.predicted_category_id,
        )
        .where(
            ClassificationResult.model_id == model_id,
            ClassificationResult.event_time >= start,
            ClassificationResult.event_time < end,
        )
    ).all()
    return [r[0] for r in rows], [float(r[1]) for r in rows]


def _feedback(
    session: Session, model_id: uuid.UUID, start: datetime, end: datetime
) -> dict[str, int]:
    rows = session.execute(
        select(AnalystFeedback.verdict, func.count())
        .join(
            ClassificationResult,
            and_(
                AnalystFeedback.target_type == "classification_result",
                cast(ClassificationResult.result_id, SqlText) == AnalystFeedback.target_id,
            ),
        )
        .where(
            ClassificationResult.model_id == model_id,
            ClassificationResult.event_time >= start,
            ClassificationResult.event_time < end,
        )
        .group_by(AnalystFeedback.verdict)
    ).all()
    return {v: int(n) for v, n in rows}


def _classification_report(
    session: Session, model: MlModel, ref: tuple[datetime, datetime], cur: tuple[datetime, datetime]
) -> tuple[str, dict[str, Any], list[str]]:
    ref_cats, ref_scores = _classifier_rows(session, model.model_id, *ref)
    cur_cats, cur_scores = _classifier_rows(session, model.model_id, *cur)
    metrics: dict[str, Any] = {
        "kind": "classification",
        "reference_rows": len(ref_cats),
        "current_rows": len(cur_cats),
        "minimum_rows": MIN_ROWS,
    }
    if len(ref_cats) < MIN_ROWS or len(cur_cats) < MIN_ROWS:
        return "insufficient_data", metrics, []
    ref_shares = psi.category_shares(ref_cats)
    cur_shares = psi.category_shares(cur_cats)
    edges = [i / 10 for i in range(1, 10)]  # predicted_score lies in [0, 1]
    metrics |= {
        "predicted_category_psi": psi.psi_categorical(ref_shares, cur_shares),
        "predicted_score_psi": psi.psi_numeric(ref_scores, cur_scores, edges),
        "reference_category_shares": ref_shares,
        "current_category_shares": cur_shares,
        "feedback_reference": _feedback(session, model.model_id, *ref),
        "feedback_current": _feedback(session, model.model_id, *cur),
    }
    warnings = []
    for key in ("predicted_category_psi", "predicted_score_psi"):
        if metrics[key] >= psi.PSI_WARNING:
            warnings.append(f"{key} = {metrics[key]:.3f} >= {psi.PSI_WARNING}")
    for name, counts in (
        ("reference", metrics["feedback_reference"]),
        ("current", metrics["feedback_current"]),
    ):
        total = sum(counts.values())
        metrics[f"feedback_{name}_false_positive_share"] = (
            round(counts.get("false_positive", 0) / total, 4) if total else None
        )
    fp_ref = metrics["feedback_reference_false_positive_share"]
    fp_cur = metrics["feedback_current_false_positive_share"]
    if fp_ref is not None and fp_cur is not None and fp_cur - fp_ref >= 0.2:
        warnings.append(f"analyst false-positive share rose from {fp_ref:.2f} to {fp_cur:.2f}")
    return ("warning" if warnings else "ok"), metrics, warnings


def _windows(
    session: Session, settings: Settings, config: dict[str, Any], start: datetime, end: datetime
) -> pd.DataFrame:
    look_back = timedelta(days=int(config.get("baseline_days", 14)))
    rows = anomaly_repo.window_events(session, start - look_back, end, config.get("source_id"))
    columns = [
        "event_time",
        "event_type",
        "src_ip",
        "dst_ip",
        "dst_port",
        "host_name",
        "user_name_normalized",
        "auth_result",
        "bytes_out",
        "bytes_in",
        "duration_s",
        "labelled_malicious",
    ]
    frame = pd.DataFrame(rows, columns=columns)
    windows = build_windows(
        frame, config["entity_type"], config.get("window_size", "1h"), settings.site_timezone
    )
    if windows.empty:
        return windows
    return windows[(windows["window_start"] >= start) & (windows["window_start"] < end)]


def _anomaly_report(
    session: Session,
    settings: Settings,
    model: MlModel,
    run: MlTrainingRun,
    cur: tuple[datetime, datetime],
) -> tuple[str, dict[str, Any], list[str], tuple[datetime, datetime]]:
    config = dict(run.config)
    ref = (
        datetime.fromisoformat(config["reference_start"]),
        datetime.fromisoformat(config["reference_end"]),
    )
    features = FEATURES[config["entity_type"]]
    ref_w = _windows(session, settings, config, *ref)
    cur_w = _windows(session, settings, config, *cur)
    metrics: dict[str, Any] = {
        "kind": "anomaly",
        "reference_windows": len(ref_w),
        "current_windows": len(cur_w),
        "minimum_windows": MIN_WINDOWS,
        "reference_period_from": "model training configuration",
    }
    warnings: list[str] = []
    flagged, total = session.execute(
        select(func.count().filter(AnomalyResult.is_flagged.is_(True)), func.count()).where(
            AnomalyResult.model_id == model.model_id,
            AnomalyResult.window_start >= cur[0],
            AnomalyResult.window_start < cur[1],
        )
    ).one()
    expected = 1 - float(config.get("threshold_percentile", 99.0)) / 100
    metrics["flagged_rate"] = {
        "scored_windows": int(total),
        "flagged": int(flagged),
        "rate": round(flagged / total, 6) if total else None,
        "expected_rate": round(expected, 6),
    }
    if total >= MIN_WINDOWS:
        rate = flagged / total
        # A low rate is only meaningful when several flags were expected at all.
        too_low = total * expected >= MIN_EXPECTED_FLAGS and rate < expected / FLAG_RATE_FACTOR
        if rate > expected * FLAG_RATE_FACTOR or too_low:
            warnings.append(
                f"flagged rate {rate:.4f} differs from the expected {expected:.4f} by more "
                f"than {FLAG_RATE_FACTOR:g}x"
            )
    if len(ref_w) < MIN_WINDOWS or len(cur_w) < MIN_WINDOWS:
        return "insufficient_data", metrics, warnings, ref
    feature_psi = {
        f: psi.psi_numeric(ref_w[f].astype(float).tolist(), cur_w[f].astype(float).tolist())
        for f in features
    }
    metrics["feature_psi"] = feature_psi
    warnings += [
        f"feature {f}: PSI {v:.3f} >= {psi.PSI_WARNING}"
        for f, v in feature_psi.items()
        if v >= psi.PSI_WARNING
    ]
    return ("warning" if warnings else "ok"), metrics, warnings, ref


def compute(
    factory: sessionmaker[Session],
    settings: Settings,
    actor: Actor,
    model_id: uuid.UUID,
    start: datetime,
    end: datetime,
    reference: tuple[datetime, datetime] | None = None,
) -> DriftReport:
    _check_range(start, end)
    with factory() as session, session.begin():
        model = session.get(MlModel, model_id)
        if model is None:
            raise NotFoundError(f"model {model_id} not found")
        run = session.get(MlTrainingRun, model.training_run_id)
        assert run is not None
        if model.task == "classification":
            ref = reference or (start - (end - start), start)
            _check_range(*ref)
            status, metrics, warnings = _classification_report(session, model, ref, (start, end))
        else:
            status, metrics, warnings, ref = _anomaly_report(
                session, settings, model, run, (start, end)
            )
        metrics["reference_period"] = {"from": ref[0].isoformat(), "to": ref[1].isoformat()}
        if warnings:
            metrics["recommendation"] = RECOMMENDATION
        report = DriftReport(
            report_id=uuid.uuid4(),
            model_id=model_id,
            period_start=start,
            period_end=end,
            status=status,
            metrics=metrics,
            warnings=warnings,
        )
        session.add(report)
        session.flush()
        audit.record(
            session,
            actor,
            "model.drift_report",
            target_type="ml_model",
            target_id=model_id,
            details={"status": status, "warnings": len(warnings)},
        )
        session.expunge(report)
        return report


def start(
    session: Session, actor: Actor, model_id: uuid.UUID, start: datetime, end: datetime
) -> uuid.UUID:
    _check_range(start, end)
    with session.begin():
        if session.get(MlModel, model_id) is None:
            raise NotFoundError(f"model {model_id} not found")
        job = jobs_service.enqueue_in_transaction(
            session,
            actor,
            JOB_TYPE,
            {"model_id": str(model_id), "from": start.isoformat(), "to": end.isoformat()},
        )
        return job.job_id


def report_out(r: DriftReport) -> dict[str, Any]:
    return {
        "report_id": r.report_id,
        "model_id": r.model_id,
        "period_start": r.period_start,
        "period_end": r.period_end,
        "status": r.status,
        "metrics": r.metrics,
        "warnings": r.warnings,
        "created_at": r.created_at,
        "note": "informational; drift never retrains or re-thresholds a model automatically",
    }


def list_reports(session: Session, model_id: uuid.UUID, limit: int = 50) -> list[dict[str, Any]]:
    with session.begin():
        rows = session.scalars(
            select(DriftReport)
            .where(DriftReport.model_id == model_id)
            .order_by(DriftReport.created_at.desc())
            .limit(limit)
        )
        return [report_out(r) for r in rows]


def latest_status(session: Session, model_ids: list[uuid.UUID]) -> dict[uuid.UUID, dict[str, Any]]:
    """Latest report per model (caller manages the transaction)."""
    if not model_ids:
        return {}
    latest = (
        select(DriftReport.model_id, func.max(DriftReport.created_at).label("at"))
        .where(DriftReport.model_id.in_(model_ids))
        .group_by(DriftReport.model_id)
        .subquery()
    )
    rows = session.scalars(
        select(DriftReport).join(
            latest,
            and_(latest.c.model_id == DriftReport.model_id, latest.c.at == DriftReport.created_at),
        )
    )
    return {
        r.model_id: {"status": r.status, "warnings": len(r.warnings), "created_at": r.created_at}
        for r in rows
    }
