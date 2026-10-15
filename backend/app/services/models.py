"""Model registry: listing, promotion gate, archive, reject (ML_CLASSIFICATION.md §9-§10)."""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any

import sklearn
from sqlalchemy.orm import Session

from app.core import clock
from app.core.config import Settings
from app.core.errors import ConflictError, NotFoundError
from app.ml import artifacts
from app.models import MlModel, MlTrainingRun
from app.repositories import ml as repo
from app.services import audit
from app.services.actors import Actor


def _major_minor(version: str) -> str:
    return ".".join(version.split(".")[:2])


def gate_problems(model: MlModel, run: MlTrainingRun, has_active: bool) -> list[str]:
    """Promotion gate. Returns the list of unmet conditions (empty = may promote)."""
    problems: list[str] = []
    if run.status != "succeeded":
        problems.append(f"training run is {run.status}")
        return problems
    metrics = run.metrics or {}
    leakage = run.leakage_checks or {}
    if leakage.get("failures"):
        problems.append("leakage checks failed")
    if leakage.get("warnings") and not run.warnings_acknowledged:
        problems.append("leakage warnings must be acknowledged with a note first")
    env = run.environment or {}
    if _major_minor(env.get("scikit_learn", "")) != _major_minor(sklearn.__version__):
        problems.append("artifact was built with a different scikit-learn version")
    if model.task == "classification":
        models = metrics.get("models", {})
        try:
            candidate = models["random_forest"]["test"]["macro_f1"]
            dummy = models["dummy_stratified"]["test"]["macro_f1"]
        except KeyError:
            problems.append("evaluation report is incomplete")
        else:
            if not candidate > dummy:
                problems.append(
                    f"test macro-F1 {candidate:.4f} does not beat the stratified "
                    f"dummy baseline {dummy:.4f}"
                )
        if has_active and "comparison" not in metrics:
            problems.append("no comparison report against the active model")
    if model.task == "anomaly":
        if not (metrics.get("threshold") and metrics.get("reference")):
            problems.append("threshold or reference-period report is missing")
        elif metrics["reference"].get("too_short"):
            problems.append("reference period is shorter than the configured minimum")
    if model.task == "web_payload_classification":
        models = metrics.get("models", {})
        try:
            candidate = models[metrics["primary_model"]]["test"]["macro_f1"]
            dummy = models["dummy_stratified"]["test"]["macro_f1"]
        except KeyError:
            problems.append("evaluation report is incomplete")
        else:
            if not candidate > dummy:
                problems.append(
                    f"test macro-F1 {candidate:.4f} does not beat the stratified "
                    f"dummy baseline {dummy:.4f}"
                )
    return problems


def _describe(model: MlModel, run: MlTrainingRun | None) -> dict[str, Any]:
    summary: dict[str, Any] = {}
    if run and run.metrics and model.task == "classification":
        rf = run.metrics.get("models", {}).get("random_forest", {}).get("test", {})
        summary = {
            "test_macro_f1": rf.get("macro_f1"),
            "test_weighted_f1": rf.get("weighted_f1"),
            "snapshot_hash": (run.dataset_snapshot or {}).get("snapshot_hash"),
            "split_strategy": run.split_strategy,
        }
    elif run and run.metrics and model.task == "web_payload_classification":
        test = run.metrics["models"][run.metrics["primary_model"]]["test"]
        summary = {
            "test_macro_f1": test.get("macro_f1"),
            "test_weighted_f1": test.get("weighted_f1"),
            "snapshot_hash": (run.dataset_snapshot or {}).get("snapshot_hash"),
            "split_strategy": run.split_strategy,
            "input": "single HTTP parameter value (text)",
        }
    elif run and run.metrics and model.task == "anomaly":
        summary = {
            "threshold": run.metrics.get("threshold"),
            "reference": run.metrics.get("reference"),
        }
    return {
        "model_id": model.model_id,
        "name": model.name,
        "version": model.version,
        "task": model.task,
        "algorithm": model.algorithm,
        "status": model.status,
        "training_run_id": model.training_run_id,
        "artifact_sha256": model.artifact_sha256,
        "feature_set_version": model.feature_set_version,
        "label_mapping_version": model.label_mapping_version,
        "class_labels": model.class_labels,
        "threshold": model.threshold,
        "created_at": model.created_at,
        "promoted_at": model.promoted_at,
        "status_note": model.status_note,
        "metrics_summary": summary,
    }


def list_models(
    session: Session, task: str | None, name: str | None, status: str | None
) -> list[dict[str, Any]]:
    from app.services.drift import latest_status

    with session.begin():
        models = list(repo.list_models(session, task, name, status))
        drift = latest_status(session, [m.model_id for m in models])
        return [_describe(m, None) | {"latest_drift": drift.get(m.model_id)} for m in models]


def get_model(session: Session, settings: Settings, model_id: uuid.UUID) -> dict[str, Any]:
    from app.services.drift import latest_status

    with session.begin():
        model = repo.get_model(session, model_id)
        if model is None:
            raise NotFoundError(f"model {model_id} not found")
        run = repo.get_run(session, model.training_run_id)
        active = repo.active_model(session, model.name)
        info = _describe(model, run)
        info["latest_drift"] = latest_status(session, [model.model_id]).get(model.model_id)
        info["promotion_gate"] = None
        if run is not None:
            other_active = active is not None and active.model_id != model.model_id
            problems = gate_problems(model, run, other_active)
            info["promotion_gate"] = {"eligible": not problems, "problems": problems}
    manifest_path = Path(model.artifact_path).parent / artifacts.MANIFEST_FILE
    if manifest_path.is_file():
        info["manifest"] = json.loads(manifest_path.read_text(encoding="utf-8"))
    return info


def promote(session: Session, actor: Actor, model_id: uuid.UUID) -> dict[str, Any]:
    with session.begin():
        model = repo.get_model(session, model_id, for_update=True)
        if model is None:
            raise NotFoundError(f"model {model_id} not found")
        if model.status != "candidate":
            raise ConflictError(f"only candidate models can be promoted (model is {model.status})")
        run = repo.get_run(session, model.training_run_id)
        assert run is not None
        current = repo.active_model(session, model.name, for_update=True)
        problems = gate_problems(model, run, current is not None)
        if problems:
            raise ConflictError("promotion gate not met", extra={"gate_problems": problems})
        if current is not None:
            current.status = "archived"
            current.status_note = f"superseded by version {model.version}"
            session.flush()
        model.status = "active"
        model.promoted_at = clock.now()
        model.promoted_by = actor.user_id
        audit.record(
            session,
            actor,
            "ml.model_promoted",
            target_type="ml_model",
            target_id=model.model_id,
            details={
                "name": model.name,
                "version": model.version,
                "previous_active": str(current.model_id) if current else None,
            },
        )
        session.flush()
        return _describe(model, run)


def archive(session: Session, actor: Actor, model_id: uuid.UUID) -> dict[str, Any]:
    with session.begin():
        model = repo.get_model(session, model_id, for_update=True)
        if model is None:
            raise NotFoundError(f"model {model_id} not found")
        if model.status == "active":
            raise ConflictError("the active model cannot be archived; promote another first")
        if model.status == "archived":
            raise ConflictError("model is already archived")
        model.status = "archived"
        audit.record(
            session, actor, "ml.model_archived", target_type="ml_model", target_id=model_id
        )
        session.flush()
        return _describe(model, None)


def reject(session: Session, actor: Actor, model_id: uuid.UUID, reason: str) -> dict[str, Any]:
    with session.begin():
        model = repo.get_model(session, model_id, for_update=True)
        if model is None:
            raise NotFoundError(f"model {model_id} not found")
        if model.status != "candidate":
            raise ConflictError("only candidate models can be rejected")
        model.status = "rejected"
        model.status_note = reason[:500]
        audit.record(
            session,
            actor,
            "ml.model_rejected",
            target_type="ml_model",
            target_id=model_id,
            details={"reason": reason[:500]},
        )
        session.flush()
        return _describe(model, None)


def orphan_artifacts(session: Session, settings: Settings) -> list[str]:
    with session.begin():
        registered = repo.all_artifact_paths(session)
    return [str(p) for p in artifacts.orphan_directories(settings.artifact_dir, registered)]
