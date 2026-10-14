"""Anomaly mining use cases (ANOMALY_DETECTION.md)."""

from __future__ import annotations

import tomllib
import uuid
from collections.abc import Callable
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator
from sqlalchemy.orm import Session, sessionmaker

from app.core import clock
from app.core.config import REPO_ROOT, Settings
from app.core.errors import ConflictError, FieldError, NotFoundError, ValidationFailedError
from app.core.pagination import DEFAULT_LIMIT, decode_cursor, encode_cursor
from app.ml import artifacts
from app.ml.anomaly import methods
from app.ml.anomaly.windows import (
    FEATURE_SET,
    FEATURES,
    WINDOW_SIZES,
    build_windows,
    robust_stats,
    robust_z,
)
from app.ml.classification.training import TrainingError
from app.models import AnomalyResult, MlModel, MlScoringRun, MlTrainingRun
from app.repositories import anomaly as repo
from app.repositories import ml as ml_repo
from app.services import audit
from app.services import jobs as jobs_service
from app.services.actors import Actor

TRAIN_JOB = "ml.train_anomaly"
SCORE_JOB = "ml.score_anomaly"
UNUSUAL_NOTE = (
    "Unusual behaviour is not necessarily malicious; anomaly scores are not probabilities."
)


class AnomalyConfig(BaseModel):
    """Validated anomaly model configuration (ANOMALY_DETECTION.md §12)."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(pattern=r"^[a-z][a-z0-9_]{2,63}$")
    method: str = Field(pattern="^(isolation_forest|robust_zscore)$")
    entity_type: str = Field(pattern="^(host|account|src_ip)$")
    window_size: str = Field(default="1h", pattern="^(15m|1h|1d)$")
    feature_set: str = Field(default=FEATURE_SET, pattern=f"^{FEATURE_SET}$")
    random_seed: int = Field(default=42, ge=0)
    reference_start: datetime
    reference_end: datetime
    threshold_percentile: float = Field(default=99.0, ge=90, le=99.9)
    baseline_days: int = Field(default=14, ge=1, le=90)
    min_baseline_windows: int = Field(default=24, ge=3)
    min_reference_days: int = Field(default=7, ge=1)
    source_id: int | None = None
    iforest: dict[str, int] = Field(default_factory=lambda: {"n_estimators": 200})

    @model_validator(mode="after")
    def _check(self) -> AnomalyConfig:
        if self.reference_start.tzinfo is None or self.reference_end.tzinfo is None:
            raise ValueError("reference_start/reference_end need a timezone")
        if self.reference_end <= self.reference_start:
            raise ValueError("reference_end must be after reference_start")
        if self.reference_end - self.reference_start > timedelta(days=400):
            raise ValueError("reference period is limited to 400 days")
        n = self.iforest.get("n_estimators", 200)
        if not 10 <= n <= 2000:
            raise ValueError("iforest.n_estimators must be 10-2000")
        return self

    def method_config(self) -> methods.MethodConfig:
        return methods.MethodConfig(
            method=self.method,
            entity_type=self.entity_type,
            window_size=self.window_size,
            features=FEATURES[self.entity_type],
            random_seed=self.random_seed,
            threshold_percentile=self.threshold_percentile,
            baseline_days=self.baseline_days,
            min_baseline_windows=self.min_baseline_windows,
            n_estimators=self.iforest.get("n_estimators", 200),
        )


def parse_config(data: dict[str, Any]) -> AnomalyConfig:
    try:
        return AnomalyConfig.model_validate(data)
    except ValidationError as exc:
        raise ValidationFailedError(
            "invalid anomaly configuration",
            errors=[
                FieldError(".".join(str(p) for p in e["loc"]) or "config", e["type"], e["msg"])
                for e in exc.errors()
            ],
        ) from exc


def load_config_file(path: Path) -> AnomalyConfig:
    if not path.is_absolute():
        path = (REPO_ROOT / path).resolve()
    with path.open("rb") as fh:
        return parse_config(tomllib.load(fh))


def _frame(rows: list[dict[str, Any]]) -> pd.DataFrame:
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
    return pd.DataFrame(rows, columns=columns)


def _malicious_windows(
    events: pd.DataFrame, windows: pd.DataFrame, cfg: AnomalyConfig
) -> np.ndarray:
    if events.empty or windows.empty:
        return np.zeros(len(windows), dtype=bool)
    from app.ml.anomaly.windows import entity_column

    frame = events.copy()
    frame["event_time"] = pd.to_datetime(frame["event_time"], utc=True)
    frame["entity_value"] = entity_column(frame, cfg.entity_type)
    frame["window_start"] = frame["event_time"].dt.floor(
        pd.Timedelta(WINDOW_SIZES[cfg.window_size])
    )
    bad = frame[frame["labelled_malicious"]].groupby(["entity_value", "window_start"]).size()
    keys = set(bad.index)
    return np.array(
        [
            (e, w) in keys
            for e, w in zip(windows["entity_value"], windows["window_start"], strict=True)
        ]
    )


# --- training ---------------------------------------------------------------------------------


def start_training(
    session: Session, actor: Actor, config: AnomalyConfig, *, enqueue: bool = True
) -> MlTrainingRun:
    with session.begin():
        run = MlTrainingRun(
            run_id=uuid.uuid4(),
            task="anomaly",
            name=config.name,
            status="queued",
            config=config.model_dump(mode="json"),
            random_seed=config.random_seed,
            feature_set_version=f"{FEATURE_SET}@1",
            split_strategy=None,
            triggered_by=actor.user_id,
        )
        session.add(run)
        session.flush()
        if enqueue:
            job = jobs_service.enqueue_in_transaction(
                session, actor, TRAIN_JOB, {"run_id": str(run.run_id)}, max_attempts=1
            )
            run.job_id = job.job_id
        audit.record(
            session,
            actor,
            "ml.training_started",
            target_type="ml_training_run",
            target_id=run.run_id,
            details={"name": config.name, "task": "anomaly"},
        )
        session.flush()
        session.expunge(run)
        return run


def run_training(
    factory: sessionmaker[Session],
    settings: Settings,
    run_id: uuid.UUID,
    progress: Callable[[str], None] | None = None,
) -> MlTrainingRun:
    with factory() as session, session.begin():
        run = ml_repo.get_run(session, run_id, for_update=True)
        if run is None:
            raise NotFoundError(f"training run {run_id} not found")
        if run.status != "queued":
            raise ConflictError(f"training run is {run.status}")
        run.status, run.started_at = "running", clock.now()
        config = AnomalyConfig.model_validate(run.config)
    try:
        _train(factory, settings, run_id, config, progress)
    except Exception as exc:
        with factory() as session, session.begin():
            failed = ml_repo.get_run(session, run_id, for_update=True)
            assert failed is not None
            failed.status, failed.finished_at = "failed", clock.now()
            failed.error = {
                "code": "TRAINING_FAILED"
                if isinstance(exc, TrainingError)
                else exc.__class__.__name__,
                "message": str(exc)[:500],
            }
        raise
    with factory() as session, session.begin():
        result = ml_repo.get_run(session, run_id)
        assert result is not None
        session.expunge(result)
        return result


def _train(
    factory: sessionmaker[Session],
    settings: Settings,
    run_id: uuid.UUID,
    config: AnomalyConfig,
    progress: Callable[[str], None] | None,
) -> None:
    mcfg = config.method_config()
    look_back = timedelta(days=config.baseline_days)
    with factory() as session, session.begin():
        rows = repo.window_events(
            session, config.reference_start - look_back, config.reference_end, config.source_id
        )
    events = _frame(rows)
    if progress:
        progress("building windows")
    windows = build_windows(events, config.entity_type, config.window_size, settings.site_timezone)
    in_ref = (
        (windows["window_start"] >= config.reference_start)
        & (windows["window_start"] < config.reference_end)
        if not windows.empty
        else pd.Series(dtype=bool)
    )
    reference = windows[in_ref] if not windows.empty else windows
    if len(reference) < 10:
        raise TrainingError(f"only {len(reference)} reference windows; need at least 10")
    days = (config.reference_end - config.reference_start).total_seconds() / 86400
    ref_info = {
        "start": config.reference_start.isoformat(),
        "end": config.reference_end.isoformat(),
        "days": round(days, 3),
        "windows": len(reference),
        "entities": int(reference["entity_value"].nunique()),
        "too_short": days < config.min_reference_days,
        "note": "attacks inside the reference period are treated as normal",
    }
    if progress:
        progress("scoring reference windows")
    pipeline = None
    if config.method == "isolation_forest":
        pipeline = methods.fit_isolation_forest(reference, mcfg)
        ref_scores = methods.isolation_scores(pipeline, reference, mcfg.features)
        insufficient = 0
    else:
        history = methods.history_scores(windows, mcfg)
        ref_scores = history.scores[in_ref].to_numpy()
        insufficient = int(history.insufficient[in_ref].sum())
        if np.isnan(ref_scores).all():
            raise TrainingError(
                "no reference window has enough history for robust z-scores; "
                "lower min_baseline_windows or extend the period"
            )
    ref_quantiles = methods.quantiles(np.asarray(ref_scores, dtype="float64"))
    threshold = methods.threshold_from(ref_quantiles, config.threshold_percentile, config.method)
    median, mad, mean_abs = robust_stats(reference[mcfg.features].astype("float64"))
    population = {"median": median.to_dict(), "mad": mad.to_dict(), "mean_abs": mean_abs.to_dict()}
    malicious = _malicious_windows(events, reference.reset_index(drop=True), config)
    report = {
        "reference": ref_info,
        "threshold": {
            "method": "reference percentile",
            "percentile": config.threshold_percentile,
            "value": threshold,
        },
        "score_distribution": {
            f"p{p}": float(np.nanpercentile(ref_scores, p)) for p in (50, 90, 99)
        }
        | {"max": float(np.nanmax(ref_scores))},
        "insufficient_history_windows": insufficient,
        "features": mcfg.features,
        "proxy_evaluation": (
            methods.proxy_evaluation(np.asarray(ref_scores, dtype="float64"), malicious, threshold)
            | {"scope": "in-sample, reference period"}
        )
        if malicious.any()
        else {"note": "no labelled-malicious events in the reference period"},
        "interpretation": UNUSUAL_NOTE,
        "warnings": _training_warnings(config, len(reference), ref_scores),
    }
    env = artifacts.environment()
    obj = {
        "method": config.method,
        "entity_type": config.entity_type,
        "window_size": config.window_size,
        "features": mcfg.features,
        "pipeline": pipeline,
        "reference_quantiles": ref_quantiles,
        "threshold": threshold,
        "population": population,
        "config": config.model_dump(mode="json"),
    }
    with factory() as session, session.begin():
        version = ml_repo.next_version(session, config.name)
        model_id = uuid.uuid4()
        manifest = {
            "model_id": str(model_id),
            "name": config.name,
            "version": version,
            "task": "anomaly",
            "algorithm": config.method,
            "feature_set": f"{FEATURE_SET}@1",
            "features": mcfg.features,
            "entity_type": config.entity_type,
            "window_size": config.window_size,
            "training_run_id": str(run_id),
            "random_seed": config.random_seed,
            "environment": env,
            "created_at": clock.now(),
        }
        path, sha = artifacts.save(
            settings.artifact_dir, config.name, version, obj, manifest, report
        )
        session.add(
            MlModel(
                model_id=model_id,
                name=config.name,
                version=version,
                task="anomaly",
                algorithm=config.method,
                status="candidate",
                training_run_id=run_id,
                artifact_path=str(path),
                artifact_sha256=sha,
                feature_set_version=f"{FEATURE_SET}@1",
                threshold={"value": threshold, "percentile": config.threshold_percentile},
            )
        )
        run = ml_repo.get_run(session, run_id, for_update=True)
        assert run is not None
        run.status, run.finished_at = "succeeded", clock.now()
        run.metrics, run.environment = report, env
        run.leakage_checks = {"failures": [], "warnings": []}
        run.dataset_snapshot = {"reference": ref_info, "events_loaded": len(events)}


def _training_warnings(config: AnomalyConfig, windows: int, scores: Any) -> list[str]:
    warnings = []
    if (
        config.method == "isolation_forest"
        and windows < methods.IFOREST_RECOMMENDED_REFERENCE_WINDOWS
    ):
        warnings.append(
            f"only {windows} reference windows (< {methods.IFOREST_RECOMMENDED_REFERENCE_WINDOWS}"
            "): Isolation Forest results are unreliable, and values far outside the reference "
            "range score like the range boundary; consider robust_zscore for low-volume entities"
        )
    clean = np.asarray(scores, dtype="float64")
    clean = clean[~np.isnan(clean)]
    if clean.size and np.unique(np.round(clean, 9)).size <= 2:
        warnings.append(
            "reference scores are nearly constant; the percentile threshold carries "
            "little information"
        )
    return warnings


# --- scoring ----------------------------------------------------------------------------------


def start_scoring(
    session: Session,
    actor: Actor,
    *,
    start: datetime,
    end: datetime,
    model_id: uuid.UUID | None,
    name: str | None,
    enqueue: bool = True,
) -> MlScoringRun:
    if start.tzinfo is None or end.tzinfo is None or end <= start:
        raise ValidationFailedError("scoring needs timezone-aware from < to")
    with session.begin():
        if model_id:
            model = ml_repo.get_model(session, model_id)
        elif name:
            model = ml_repo.active_model(session, name)
        else:
            raise ValidationFailedError(
                "give model_id or name", errors=[FieldError("model_id", "required", "or name")]
            )
        if model is None:
            raise NotFoundError("no such model / no active model with that name")
        if model.task != "anomaly":
            raise ConflictError("model is not an anomaly model")
        run = MlScoringRun(
            scoring_run_id=uuid.uuid4(),
            model_id=model.model_id,
            scope={"from": start.isoformat(), "to": end.isoformat()},
            status="queued",
            evaluation_only=model.status != "active",
            triggered_by=actor.user_id,
        )
        session.add(run)
        session.flush()
        if enqueue:
            job = jobs_service.enqueue_in_transaction(
                session, actor, SCORE_JOB, {"scoring_run_id": str(run.scoring_run_id)}
            )
            run.job_id = job.job_id
        audit.record(
            session,
            actor,
            "ml.scoring_started",
            target_type="ml_scoring_run",
            target_id=run.scoring_run_id,
            details={"model_id": str(model.model_id)},
        )
        session.flush()
        session.expunge(run)
        return run


def run_scoring(
    factory: sessionmaker[Session], settings: Settings, scoring_run_id: uuid.UUID
) -> MlScoringRun:
    with factory() as session, session.begin():
        run = session.get(MlScoringRun, scoring_run_id, with_for_update=True)
        if run is None:
            raise NotFoundError(f"scoring run {scoring_run_id} not found")
        model = ml_repo.get_model(session, run.model_id)
        assert model is not None
        run.status, run.started_at = "running", clock.now()
        scope, path, sha, model_id = (
            dict(run.scope),
            model.artifact_path,
            model.artifact_sha256,
            model.model_id,
        )
    try:
        obj, _manifest = artifacts.load(settings.artifact_dir, path, sha)
        cfg = AnomalyConfig.model_validate(obj["config"])
        mcfg = cfg.method_config()
        start, end = datetime.fromisoformat(scope["from"]), datetime.fromisoformat(scope["to"])
        with factory() as session, session.begin():
            rows = repo.window_events(
                session, start - timedelta(days=cfg.baseline_days), end, cfg.source_id
            )
        windows = build_windows(
            _frame(rows), cfg.entity_type, cfg.window_size, settings.site_timezone
        )
        scored, skipped = 0, {"insufficient_history": 0}
        if not windows.empty:
            history = methods.history_scores(windows, mcfg)
            target = (windows["window_start"] >= start) & (windows["window_start"] < end)
            if cfg.method == "isolation_forest":
                scores = pd.Series(np.nan, index=windows.index)
                scores[target] = methods.isolation_scores(
                    obj["pipeline"], windows[target], mcfg.features
                )
            else:
                scores = history.scores
            pop = obj["population"]
            pmed, pmad, pmean = (
                pd.Series(pop["median"]),
                pd.Series(pop["mad"]),
                pd.Series(pop["mean_abs"]),
            )
            size = WINDOW_SIZES[cfg.window_size]
            out = []
            for pos, idx in enumerate(windows.index):
                if not target[idx]:
                    continue
                score = scores[idx]
                if np.isnan(score):
                    skipped["insufficient_history"] += 1
                    continue
                row = windows.loc[idx]
                deviations = history.deviations[pos]
                if not deviations and history.insufficient[idx]:
                    values = row[mcfg.features].astype("float64")
                    deviations = methods.explain(
                        values,
                        robust_z(values, pmed, pmad, pmean),
                        pmed,
                        pmad,
                        against="population (reference)",
                    )
                out.append(
                    {
                        "model_id": model_id,
                        "scoring_run_id": scoring_run_id,
                        "method": cfg.method,
                        "entity_type": cfg.entity_type,
                        "entity_value": str(row["entity_value"]),
                        "window_start": row["window_start"].to_pydatetime(),
                        "window_end": (row["window_start"] + size).to_pydatetime(),
                        "window_size": size,
                        "anomaly_score": float(score),
                        "score_percentile": methods.percentile_of(
                            float(score), obj["reference_quantiles"]
                        ),
                        "threshold": float(obj["threshold"]),
                        "is_flagged": bool(score >= obj["threshold"]),
                        "feature_snapshot": {f: methods._num(row[f]) for f in mcfg.features},
                        "baseline_snapshot": history.baselines[pos],
                        "top_deviations": deviations,
                    }
                )
            with factory() as session, session.begin():
                scored = repo.insert_results(session, out)
    except Exception as exc:
        code = exc.code if isinstance(exc, artifacts.ArtifactError) else exc.__class__.__name__
        with factory() as session, session.begin():
            failed = session.get(MlScoringRun, scoring_run_id, with_for_update=True)
            assert failed is not None
            failed.status, failed.finished_at = "failed", clock.now()
            failed.error = {"code": code, "message": str(exc)[:500]}
        raise
    with factory() as session, session.begin():
        done = session.get(MlScoringRun, scoring_run_id, with_for_update=True)
        assert done is not None
        done.status, done.finished_at = "succeeded", clock.now()
        done.rows_scored, done.rows_skipped = scored, skipped
        session.flush()
        session.expunge(done)
        return done


# --- queries ----------------------------------------------------------------------------------


def _out(r: AnomalyResult) -> dict[str, Any]:
    return {
        "result_id": r.result_id,
        "model_id": r.model_id,
        "method": r.method,
        "entity_type": r.entity_type,
        "entity_value": r.entity_value,
        "window_start": r.window_start,
        "window_end": r.window_end,
        "anomaly_score": r.anomaly_score,
        "score_percentile": r.score_percentile,
        "threshold": r.threshold,
        "is_flagged": r.is_flagged,
        "top_deviation": r.top_deviations[0] if r.top_deviations else None,
        "score_is_probability": False,
    }


def list_results(
    session: Session,
    *,
    model_id: uuid.UUID | None,
    entity_type: str | None,
    entity_value: str | None,
    flagged: bool | None,
    min_percentile: float | None,
    start: datetime | None,
    end: datetime | None,
    cursor: str | None,
    limit: int = DEFAULT_LIMIT,
) -> dict[str, Any]:
    key = decode_cursor(cursor, frozenset({"s", "id"}))
    after = (float(key["s"]), int(key["id"])) if key else None
    with session.begin():
        rows = repo.list_results(
            session,
            model_id=model_id,
            entity_type=entity_type,
            entity_value=entity_value,
            flagged=flagged,
            min_percentile=min_percentile,
            start=start,
            end=end,
            after=after,
            limit=limit + 1,
        )
        items = [_out(r) for r in rows[:limit]]
    nxt = None
    if len(rows) > limit:
        nxt = encode_cursor({"s": rows[limit - 1].anomaly_score, "id": rows[limit - 1].result_id})
    return {"items": items, "next_cursor": nxt, "limit": limit, "interpretation": UNUSUAL_NOTE}


def detail(session: Session, result_id: int, history_days: int = 7) -> dict[str, Any]:
    with session.begin():
        r = session.get(AnomalyResult, result_id)
        if r is None:
            raise NotFoundError(f"anomaly result {result_id} not found")
        history = repo.entity_history(
            session,
            r.model_id,
            r.entity_type,
            r.entity_value,
            r.window_start - timedelta(days=history_days),
            r.window_start,
        )
        model = repo.model_names(session, r.model_id)
        weekly = [
            h
            for h in repo.entity_history(
                session,
                r.model_id,
                r.entity_type,
                r.entity_value,
                r.window_start - timedelta(days=28),
                r.window_start - timedelta(seconds=1),
            )
            if h.window_start.weekday() == r.window_start.weekday()
            and h.window_start.hour == r.window_start.hour
        ]
        seasonal: Any = "insufficient_history_for_seasonal_comparison"
        if len(weekly) >= 4:
            seasonal = {
                "same_hour_of_week_windows": len(weekly),
                "median_score": float(np.median([h.anomaly_score for h in weekly])),
            }
        result = _out(r) | {
            "feature_snapshot": r.feature_snapshot,
            "baseline": r.baseline_snapshot,
            "top_deviations": r.top_deviations,
            "history": [
                {
                    "window_start": h.window_start,
                    "anomaly_score": h.anomaly_score,
                    "is_flagged": h.is_flagged,
                }
                for h in history
            ],
            "seasonal_comparison": seasonal,
            "model": {"name": model.name, "version": model.version, "status": model.status}
            if model
            else None,
            "linked_events": {
                "endpoint": "/api/v1/events",
                "params": {
                    "from": r.window_start.isoformat(),
                    "to": r.window_end.isoformat(),
                    **(
                        {"user_name": r.entity_value}
                        if r.entity_type == "account"
                        else {"ip": r.entity_value}
                        if r.entity_type == "src_ip"
                        else {"host_name": r.entity_value}
                    ),
                },
            },
            "interpretation": UNUSUAL_NOTE,
        }
    return result
