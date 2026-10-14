"""Supervised classification use cases (ML_CLASSIFICATION.md)."""

from __future__ import annotations

import hashlib
import json
import tomllib
import uuid
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator
from sqlalchemy.orm import Session, sessionmaker

from app.core import clock
from app.core.config import REPO_ROOT, Settings
from app.core.errors import ConflictError, FieldError, NotFoundError, ValidationFailedError
from app.core.pagination import DEFAULT_LIMIT, decode_cursor, encode_cursor
from app.ml import artifacts
from app.ml.classification.training import TrainConfig, TrainingError, evaluate, train_and_evaluate
from app.ml.features import FeatureError, build_features, feature_hash, load_feature_set
from app.models import MlModel, MlScoringRun, MlTrainingRun
from app.repositories import ml as repo
from app.repositories import reference as reference_repo
from app.services import audit
from app.services import jobs as jobs_service
from app.services.actors import Actor

TRAIN_JOB = "ml.train_classifier"
SCORE_JOB = "ml.score_classifier"
SCORE_CHUNK = 50_000
MAX_MISSING_FRACTION = 0.5
CONFIG_DIR = REPO_ROOT / "config" / "ml"


class SnapshotConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    batch_ids: list[uuid.UUID] = Field(min_length=1)
    event_types: list[str] = Field(default_factory=lambda: ["network_flow"])


class RandomForestGrid(BaseModel):
    model_config = ConfigDict(extra="forbid")

    n_estimators: list[int] = Field(default_factory=lambda: [100, 300], min_length=1)
    max_depth: list[int] = Field(default_factory=lambda: [0, 20], min_length=1)
    min_samples_leaf: list[int] = Field(default_factory=lambda: [1, 5], min_length=1)

    @field_validator("n_estimators", "min_samples_leaf")
    @classmethod
    def _positive(cls, v: list[int]) -> list[int]:
        if any(x < 1 or x > 2000 for x in v):
            raise ValueError("values must be between 1 and 2000")
        return v


class ModelsConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    random_forest: RandomForestGrid = Field(default_factory=RandomForestGrid)


class BudgetConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    max_minutes: float = Field(default=30, gt=0, le=24 * 60)


class ClassifierConfig(BaseModel):
    """Validated training configuration (ML_CLASSIFICATION.md §14)."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(default="attack_classifier", pattern=r"^[a-z][a-z0-9_]{2,63}$")
    random_seed: int = Field(default=42, ge=0, le=2**31 - 1)
    feature_set: str = "flow_v1"
    label_level: str = Field(default="canonical", pattern="^(canonical|raw)$")
    split_strategy: str = Field(
        default="group_stratified", pattern="^(group_stratified|temporal|predefined)$"
    )
    group_key: str = Field(default="feature_hash", pattern="^(feature_hash|conversation)$")
    test_fraction: float = Field(default=0.2, gt=0.05, lt=0.5)
    validation_fraction: float = Field(default=0.2, gt=0.05, lt=0.5)
    include_raw_dst_port: bool = False
    min_class_support_train: int = Field(default=50, ge=1)
    rare_class_policy: str = Field(default="merge", pattern="^(merge|exclude)$")
    max_majority_ratio: float = Field(default=10.0, ge=0)
    include_feedback_labels: bool = False
    bootstrap_resamples: int = Field(default=1000, ge=50, le=10_000)
    snapshot: SnapshotConfig
    models: ModelsConfig = Field(default_factory=ModelsConfig)
    budget: BudgetConfig = Field(default_factory=BudgetConfig)

    @field_validator("include_feedback_labels")
    @classmethod
    def _feedback_not_yet(cls, v: bool) -> bool:
        if v:
            raise ValueError("analyst feedback labels are not available before Phase 5")
        return v

    def train_config(self) -> TrainConfig:
        return TrainConfig(
            random_seed=self.random_seed,
            split_strategy=self.split_strategy,
            group_key=self.group_key,
            test_fraction=self.test_fraction,
            validation_fraction=self.validation_fraction,
            min_class_support_train=self.min_class_support_train,
            rare_class_policy=self.rare_class_policy,
            max_majority_ratio=self.max_majority_ratio,
            bootstrap_resamples=self.bootstrap_resamples,
            rf_grid=self.models.random_forest.model_dump(),
            max_minutes=self.budget.max_minutes,
        )


def parse_config(data: dict[str, Any]) -> ClassifierConfig:
    try:
        config = ClassifierConfig.model_validate(data)
        load_feature_set(config.feature_set, config.include_raw_dst_port)
    except ValidationError as exc:
        raise ValidationFailedError(
            "invalid training configuration",
            errors=[
                FieldError(".".join(str(p) for p in e["loc"]), e["type"], e["msg"])
                for e in exc.errors()
            ],
        ) from exc
    except FeatureError as exc:
        raise ValidationFailedError(
            str(exc), errors=[FieldError("feature_set", "invalid", str(exc))]
        ) from exc
    return config


def load_config_file(path: Path, batch_ids: list[str]) -> ClassifierConfig:
    if not path.is_absolute():
        path = (REPO_ROOT / path).resolve()
    with path.open("rb") as fh:
        data = tomllib.load(fh)
    data.setdefault("snapshot", {})["batch_ids"] = batch_ids or data.get("snapshot", {}).get(
        "batch_ids", []
    )
    return parse_config(data)


# --- training -----------------------------------------------------------------------------------


def start_training(
    session: Session, actor: Actor, config: ClassifierConfig, *, enqueue: bool = True
) -> MlTrainingRun:
    with session.begin():
        run = MlTrainingRun(
            run_id=uuid.uuid4(),
            task="classification",
            name=config.name,
            status="queued",
            config=config.model_dump(mode="json"),
            random_seed=config.random_seed,
            feature_set_version=load_feature_set(config.feature_set).tag,
            split_strategy=config.split_strategy,
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
            details={"name": config.name},
        )
        session.flush()
        session.expunge(run)
        return run


def snapshot_hash(frame: pd.DataFrame) -> str:
    digest = hashlib.sha256()
    for event_id, event_time, label in sorted(
        zip(
            frame["event_id"],
            frame["event_time"].map(lambda t: t.isoformat()),
            frame["label"],
            strict=True,
        )
    ):
        digest.update(f"{event_id}|{event_time}|{label}\n".encode())
    return digest.hexdigest()


def _set_run(factory: sessionmaker[Session], run_id: uuid.UUID, **values: Any) -> None:
    with factory() as session, session.begin():
        run = repo.get_run(session, run_id, for_update=True)
        assert run is not None
        for key, value in values.items():
            setattr(run, key, value)


def run_training(
    factory: sessionmaker[Session],
    settings: Settings,
    run_id: uuid.UUID,
    progress: Callable[[str], None] | None = None,
) -> MlTrainingRun:
    """Job handler body. Marks the run succeeded/failed; raises TrainingError on failure."""
    with factory() as session, session.begin():
        run = repo.get_run(session, run_id, for_update=True)
        if run is None:
            raise NotFoundError(f"training run {run_id} not found")
        if run.status != "queued":
            raise ConflictError(f"training run is {run.status}")
        run.status, run.started_at = "running", clock.now()
        config = ClassifierConfig.model_validate(run.config)
    try:
        _train(factory, settings, run_id, config, progress)
    except (TrainingError, FeatureError) as exc:
        _set_run(
            factory,
            run_id,
            status="failed",
            finished_at=clock.now(),
            error={"code": "TRAINING_FAILED", "message": str(exc)},
        )
        raise TrainingError(str(exc)) from exc
    except Exception as exc:
        _set_run(
            factory,
            run_id,
            status="failed",
            finished_at=clock.now(),
            error={
                "code": "UNEXPECTED_ERROR",
                "type": exc.__class__.__name__,
                "message": str(exc)[:500],
            },
        )
        raise
    with factory() as session, session.begin():
        result = repo.get_run(session, run_id)
        assert result is not None
        session.expunge(result)
    return result


def _train(
    factory: sessionmaker[Session],
    settings: Settings,
    run_id: uuid.UUID,
    config: ClassifierConfig,
    progress: Callable[[str], None] | None,
) -> MlModel:
    fs = load_feature_set(config.feature_set, config.include_raw_dst_port)
    with factory() as session, session.begin():
        rows, excluded = repo.training_snapshot(
            session, config.snapshot.batch_ids, config.snapshot.event_types, config.label_level
        )
    if not rows:
        raise TrainingError("the snapshot contains no labelled events")
    frame = pd.DataFrame(rows)
    snapshot = {
        "batch_ids": [str(b) for b in config.snapshot.batch_ids],
        "event_types": config.snapshot.event_types,
        "label_level": config.label_level,
        "rows": len(frame),
        "rows_per_class": {str(k): int(v) for k, v in frame["label"].value_counts().items()},
        "excluded": excluded,
        "snapshot_hash": snapshot_hash(frame),
    }
    _set_run(factory, run_id, dataset_snapshot=snapshot)
    mapping_versions = sorted({str(v) for v in frame["label_mapping_version"].dropna()})
    features = build_features(frame, fs, require_attributes=True)
    hashes = feature_hash(features)
    meta = frame[
        [
            "event_id",
            "event_time",
            "time_quality",
            "src_ip",
            "dst_ip",
            "dst_port",
            "protocol",
            "dataset_partition",
        ]
    ].copy()
    result = train_and_evaluate(
        features,
        frame["label"].astype(str).to_numpy(),
        meta,
        hashes,
        fs.numeric_columns,
        fs.categorical_columns,
        config.train_config(),
        progress,
    )
    report = result.report
    env = artifacts.environment()

    with factory() as session, session.begin():
        active = repo.active_model(session, config.name)
        active_info = (
            None
            if active is None
            else (
                active.model_id,
                active.artifact_path,
                active.artifact_sha256,
                active.feature_set_version,
                list(active.class_labels or []),
            )
        )
    report["comparison"] = _compare_with_active(
        settings, active_info, fs.tag, result.labels, result.test_features, result.test_labels
    )

    with factory() as session, session.begin():
        version = repo.next_version(session, config.name)
        model_id = uuid.uuid4()
        manifest = {
            "model_id": str(model_id),
            "name": config.name,
            "version": version,
            "task": "classification",
            "algorithm": "random_forest",
            "feature_set": fs.tag,
            "features": [*fs.numeric_columns, *fs.categorical_columns],
            "numeric_features": fs.numeric_columns,
            "categorical_features": fs.categorical_columns,
            "class_labels": result.labels,
            "label_level": config.label_level,
            "label_mapping_versions": mapping_versions,
            "training_run_id": str(run_id),
            "random_seed": config.random_seed,
            "environment": env,
            "snapshot_hash": snapshot["snapshot_hash"],
            "created_at": clock.now(),
        }
        path, sha = artifacts.save(
            settings.artifact_dir, config.name, version, result.pipeline, manifest, report
        )
        model = MlModel(
            model_id=model_id,
            name=config.name,
            version=version,
            task="classification",
            algorithm="random_forest",
            status="candidate",
            training_run_id=run_id,
            artifact_path=str(path),
            artifact_sha256=sha,
            feature_set_version=fs.tag,
            label_mapping_version=",".join(mapping_versions) or None,
            class_labels=result.labels,
        )
        session.add(model)
        run = repo.get_run(session, run_id, for_update=True)
        assert run is not None
        run.status, run.finished_at = "succeeded", clock.now()
        run.metrics = report
        run.baseline_metrics = {k: v for k, v in report["models"].items() if k != "random_forest"}
        run.confusion_matrix = report["models"]["random_forest"]["test"]["confusion_matrix"]
        run.leakage_checks = report["leakage"]
        run.environment = env
        run.label_mapping_version = ",".join(mapping_versions) or None
        session.flush()
        session.expunge(model)
        return model


def _compare_with_active(
    settings: Settings,
    active: tuple[Any, ...] | None,
    feature_tag: str,
    labels: list[str],
    x_test: pd.DataFrame,
    y_test: np.ndarray,
) -> dict[str, Any]:
    if active is None:
        return {"skipped": "no active model"}
    model_id, path, sha, active_tag, active_labels = active
    if active_tag != feature_tag:
        return {
            "skipped": f"active model uses {active_tag}, candidate uses {feature_tag}",
            "active_model_id": str(model_id),
        }
    try:
        pipeline, _manifest = artifacts.load(settings.artifact_dir, path, sha)
    except artifacts.ArtifactError as exc:
        return {
            "skipped": f"active model could not be loaded: {exc.code}",
            "active_model_id": str(model_id),
        }
    union = sorted(set(labels) | set(active_labels))
    return {
        "active_model_id": str(model_id),
        "evaluated_on": "candidate test split",
        "active_test": evaluate(y_test, pipeline.predict(x_test), union),
    }


def acknowledge_warnings(
    session: Session, actor: Actor, run_id: uuid.UUID, note: str
) -> MlTrainingRun:
    with session.begin():
        run = repo.get_run(session, run_id, for_update=True)
        if run is None:
            raise NotFoundError(f"training run {run_id} not found")
        if run.status != "succeeded":
            raise ConflictError("only succeeded runs can be acknowledged")
        run.warnings_acknowledged = {
            "by": str(actor.user_id) if actor.user_id else actor.label,
            "at": clock.now().isoformat(),
            "note": note,
        }
        audit.record(
            session,
            actor,
            "ml.warnings_acknowledged",
            target_type="ml_training_run",
            target_id=run_id,
            details={"note": note[:500]},
        )
        session.flush()
        session.expunge(run)
        return run


def get_run(session: Session, run_id: uuid.UUID) -> MlTrainingRun:
    with session.begin():
        run = repo.get_run(session, run_id)
        if run is None:
            raise NotFoundError(f"training run {run_id} not found")
        session.expunge(run)
        return run


def list_runs(
    session: Session, task: str = "classification", limit: int = 50
) -> list[MlTrainingRun]:
    with session.begin():
        runs = repo.list_runs(session, task, limit)
        for r in runs:
            session.expunge(r)
        return runs


# --- scoring -------------------------------------------------------------------------------------


def start_scoring(
    session: Session,
    actor: Actor,
    scope: dict[str, Any],
    model_id: uuid.UUID | None,
    name: str = "attack_classifier",
    *,
    enqueue: bool = True,
) -> MlScoringRun:
    if not scope.get("batch_ids") and not (scope.get("from") and scope.get("to")):
        raise ValidationFailedError(
            "scope needs batch_ids or from/to",
            errors=[FieldError("scope", "required", "batch_ids or from+to")],
        )
    with session.begin():
        model = repo.get_model(session, model_id) if model_id else repo.active_model(session, name)
        if model is None:
            raise NotFoundError("no such model" if model_id else f"no active model named {name!r}")
        if model.task != "classification":
            raise ConflictError("model is not a classification model")
        run = MlScoringRun(
            scoring_run_id=uuid.uuid4(),
            model_id=model.model_id,
            scope=scope,
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
    factory: sessionmaker[Session],
    settings: Settings,
    scoring_run_id: uuid.UUID,
    progress: Callable[[int, int | None, str], None] | None = None,
) -> MlScoringRun:
    with factory() as session, session.begin():
        run = session.get(MlScoringRun, scoring_run_id, with_for_update=True)
        if run is None:
            raise NotFoundError(f"scoring run {scoring_run_id} not found")
        model = repo.get_model(session, run.model_id)
        assert model is not None
        run.status, run.started_at = "running", clock.now()
        scope, path, sha = dict(run.scope), model.artifact_path, model.artifact_sha256
        model_id = model.model_id
        category_ids = reference_repo.category_ids_by_code(session)
    try:
        pipeline, manifest = artifacts.load(settings.artifact_dir, path, sha)
        fs = load_feature_set(
            manifest["feature_set"].split("@")[0], "dst_port" in manifest["numeric_features"]
        )
        if fs.tag != manifest["feature_set"]:
            raise artifacts.ArtifactError(
                "FEATURE_SET_CHANGED", f"model needs {manifest['feature_set']}, have {fs.tag}"
            )
        classes = [str(c) for c in pipeline.classes_]
        scored, skipped = 0, {"incompatible_event_type": 0, "too_many_missing_features": 0}
        with factory() as session:
            for chunk in repo.scoring_events(session, scope, SCORE_CHUNK):
                session.rollback()  # end the read snapshot between chunks
                frame = pd.DataFrame(chunk)
                compatible = frame["event_type"].isin(fs.event_types)
                skipped["incompatible_event_type"] += int((~compatible).sum())
                frame = frame[compatible]
                if frame.empty:
                    continue
                features = build_features(frame, fs, require_attributes=False)
                sparse = features.isna().mean(axis=1) > MAX_MISSING_FRACTION
                skipped["too_many_missing_features"] += int(sparse.sum())
                frame, features = frame[~sparse], features[~sparse]
                if frame.empty:
                    continue
                proba = pipeline.predict_proba(
                    features[manifest["numeric_features"] + manifest["categorical_features"]]
                )
                best = proba.argmax(axis=1)
                rows = []
                for i, (event_id, event_time) in enumerate(
                    zip(frame["event_id"], frame["event_time"], strict=True)
                ):
                    label = classes[best[i]]
                    if label not in category_ids:
                        continue  # raw-label models are not stored as canonical predictions
                    rows.append(
                        {
                            "event_id": int(event_id),
                            "event_time": event_time,
                            "model_id": model_id,
                            "scoring_run_id": scoring_run_id,
                            "predicted_category_id": category_ids[label],
                            "predicted_score": float(proba[i, best[i]]),
                            "class_scores": {
                                c: round(float(p), 6)
                                for c, p in zip(classes, proba[i], strict=True)
                            },
                        }
                    )
                with session.begin():
                    scored += repo.insert_classifications(session, rows)
                if progress:
                    progress(scored, None, "events")
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


def get_scoring_run(session: Session, run_id: uuid.UUID) -> MlScoringRun:
    with session.begin():
        run = repo.get_scoring_run(session, run_id)
        if run is None:
            raise NotFoundError(f"scoring run {run_id} not found")
        session.expunge(run)
        return run


# --- queries -------------------------------------------------------------------------------------


def _resolve_model(session: Session, model_id: uuid.UUID | None, name: str) -> MlModel:
    model = repo.get_model(session, model_id) if model_id else repo.active_model(session, name)
    if model is None:
        raise NotFoundError("no such model" if model_id else f"no active model named {name!r}")
    return model


def list_results(
    session: Session,
    *,
    model_id: uuid.UUID | None,
    category: str | None,
    min_score: float | None,
    start: datetime | None,
    end: datetime | None,
    disagrees: bool,
    cursor: str | None,
    limit: int = DEFAULT_LIMIT,
) -> dict[str, Any]:
    key = decode_cursor(cursor, frozenset({"t", "id"}))
    after = (datetime.fromisoformat(key["t"]), int(key["id"])) if key else None
    with session.begin():
        model = _resolve_model(session, model_id, "attack_classifier")
        rows = repo.list_classifications(
            session,
            model.model_id,
            category=category,
            min_score=min_score,
            start=start,
            end=end,
            disagrees=disagrees,
            after=after,
            limit=limit + 1,
        )
        info = {
            "model_id": model.model_id,
            "name": model.name,
            "version": model.version,
            "status": model.status,
        }
    items = rows[:limit]
    nxt = None
    if len(rows) > limit:
        nxt = encode_cursor(
            {"t": items[-1]["event_time"].isoformat(), "id": items[-1]["result_id"]}
        )
    for r in items:
        r["event_id"] = str(r["event_id"])
        r["score_is_calibrated"] = False
    return {"model": info, "items": items, "next_cursor": nxt, "limit": limit}


def summary(
    session: Session, model_id: uuid.UUID | None, start: datetime | None, end: datetime | None
) -> dict[str, Any]:
    with session.begin():
        model = _resolve_model(session, model_id, "attack_classifier")
        counts, pairs = repo.classification_summary(session, model.model_id, start, end)
        info = {
            "model_id": model.model_id,
            "name": model.name,
            "version": model.version,
            "status": model.status,
        }
    labels = sorted({t for t, _, _ in pairs} | {p for _, p, _ in pairs})
    matrix = [[0] * len(labels) for _ in labels]
    for t, p, n in pairs:
        matrix[labels.index(t)][labels.index(p)] = n
    return {
        "model": info,
        "from": start,
        "to": end,
        "predictions_by_category": [{"category": c, "count": n} for c, n in counts],
        "scored_scope_confusion_matrix": {
            "note": "ground truth vs. prediction on the scored scope (not the held-out test split)",
            "labels": labels,
            "counts": matrix,
        }
        if pairs
        else None,
    }


def event_classifications(
    session: Session, event_id: int, event_time: datetime
) -> list[dict[str, Any]]:
    return [
        {
            "model": {"model_id": r[0].model_id, "name": r[1], "version": r[2], "status": r[3]},
            "predicted_category": r[4],
            "predicted_score": r[0].predicted_score,
            "score_is_calibrated": False,
            "class_scores": r[0].class_scores,
            "scored_at": r[0].scored_at,
        }
        for r in repo.classification_for_event(session, event_id, event_time)
    ]


def config_template() -> dict[str, Any]:
    with (CONFIG_DIR / "classifier_default.toml").open("rb") as fh:
        data: dict[str, Any] = json.loads(json.dumps(tomllib.load(fh)))
        return data
