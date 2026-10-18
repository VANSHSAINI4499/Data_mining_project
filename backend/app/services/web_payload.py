"""Web-attack payload classifier: training (CLI), registry integration, and inference.

The model classifies single HTTP parameter values; see ``app.ml.web_payload`` for its scope.
It is registered under task ``web_payload_classification`` and never receives network-flow
features (and the network-flow ``attack_classifier`` never receives payload text).
"""

from __future__ import annotations

import os
import platform
import time
import uuid
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

import numpy as np
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.core import clock
from app.core.config import Settings
from app.core.errors import ConflictError, FieldError, NotFoundError, ValidationFailedError
from app.core.pagination import DEFAULT_LIMIT, decode_cursor, encode_cursor
from app.ml import artifacts
from app.ml import web_payload as wp
from app.models import MlModel, MlScoringRun, MlTrainingRun
from app.repositories import ml as repo
from app.repositories import web_payload as wp_repo
from app.services import audit
from app.services import jobs as jobs_service
from app.services.actors import Actor

TASK = "web_payload_classification"
MODEL_NAME = "web_attack_classifier"
TRAIN_FILE = "payload_full.csv"
LEXICAL_FILE = "payload_test_lexical.csv"
MAX_BATCH = 100
SCORE_JOB = "ml.score_web_payloads"
SCORE_CHUNK = 5_000
SCOPE_NOTE = (
    "classifies individual HTTP parameter values only; it does not analyse full requests, "
    "sessions, or access logs, and it never blocks traffic. Scores are not probabilities."
)


def hardware() -> dict[str, Any]:
    info: dict[str, Any] = {
        "platform": platform.platform(),
        "processor": platform.processor(),
        "logical_cpus": os.cpu_count(),
        "gpu_used": False,
        "gpu_note": "scikit-learn models run on CPU only",
    }
    try:
        import ctypes

        class _Mem(ctypes.Structure):
            _fields_ = [
                ("length", ctypes.c_ulong),
                ("load", ctypes.c_ulong),
                ("total", ctypes.c_ulonglong),
                ("avail", ctypes.c_ulonglong),
                ("tp", ctypes.c_ulonglong),
                ("ap", ctypes.c_ulonglong),
                ("tv", ctypes.c_ulonglong),
                ("av", ctypes.c_ulonglong),
                ("ae", ctypes.c_ulonglong),
            ]

        mem = _Mem()
        mem.length = ctypes.sizeof(_Mem)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(mem)):
            info["ram_total_gb"] = round(mem.total / 1024**3, 2)
            info["ram_available_gb_at_start"] = round(mem.avail / 1024**3, 2)
    except (AttributeError, OSError):
        info["ram_total_gb"] = None
    return info


def _latency(pipeline: Any, samples: list[str]) -> dict[str, Any]:
    single = []
    for text in samples[:200]:
        t0 = time.perf_counter()
        pipeline.predict(np.asarray([text], dtype=object))
        single.append((time.perf_counter() - t0) * 1000)
    batch = np.asarray(samples[:1000], dtype=object)
    t0 = time.perf_counter()
    pipeline.predict(batch)
    batch_ms = (time.perf_counter() - t0) * 1000
    return {
        "single_payload_ms_p50": round(float(np.percentile(single, 50)), 3),
        "single_payload_ms_p95": round(float(np.percentile(single, 95)), 3),
        "batch_size": len(batch),
        "batch_total_ms": round(batch_ms, 2),
        "batch_per_payload_ms": round(batch_ms / max(1, len(batch)), 4),
    }


def train_from_directory(
    factory: sessionmaker[Session],
    settings: Settings,
    actor: Actor,
    dataset_dir: Path,
    *,
    seed: int = 42,
) -> dict[str, Any]:
    started = time.perf_counter()
    directory = dataset_dir.resolve()
    if not directory.is_relative_to(settings.import_root.resolve()) or not directory.is_dir():
        raise ValidationFailedError(
            f"dataset directory must be inside the import root {settings.import_root}"
        )
    full_path, lexical_path = directory / TRAIN_FILE, directory / LEXICAL_FILE
    if not full_path.is_file():
        raise ValidationFailedError(f"{TRAIN_FILE} not found in {directory}")
    hw = hardware()

    t0 = time.perf_counter()
    texts, labels, load_report = wp.load_csv(full_path)
    preprocessing_seconds = time.perf_counter() - t0

    config = {
        "name": MODEL_NAME,
        "dataset": "HTTPParamsDataset (Kaggle evg3n1j/httpparamsdataset)",
        "train_file": TRAIN_FILE,
        "random_seed": seed,
        "feature_set": wp.FEATURE_SET,
        "split": "StratifiedGroupKFold 80/20 test, then 80/20 validation, template groups",
        "candidates": sorted(wp.candidate_models(seed)),
    }
    with factory() as session, session.begin():
        run = MlTrainingRun(
            run_id=uuid.uuid4(),
            task=TASK,
            name=MODEL_NAME,
            status="running",
            config=config,
            random_seed=seed,
            feature_set_version=wp.FEATURE_SET,
            split_strategy="group_stratified",
            triggered_by=actor.user_id,
            label_mapping_version=wp.LABEL_MAPPING_VERSION,
        )
        session.add(run)
        session.flush()
        run_id = run.run_id
        audit.record(
            session,
            actor,
            "ml.training_started",
            target_type="ml_training_run",
            target_id=run_id,
            details={"task": TASK},
        )

    try:
        output = wp.train(texts, labels, seed)
        lexical = (
            wp.evaluate_lexical(output.pipeline, lexical_path) if lexical_path.is_file() else None
        )
        latency = _latency(output.pipeline, texts)
    except Exception as exc:
        with factory() as session, session.begin():
            failed = session.get(MlTrainingRun, run_id, with_for_update=True)
            assert failed is not None
            failed.status, failed.finished_at = "failed", clock.now()
            failed.error = {"code": type(exc).__name__, "message": str(exc)[:500]}
        raise

    env = artifacts.environment()
    snapshot = {
        "rows": load_report.rows_used,
        "rows_read": load_report.rows_read,
        "excluded": load_report.excluded,
        "file": TRAIN_FILE,
        "file_sha256": load_report.file_sha256,
        "snapshot_hash": load_report.file_sha256,
        "raw_label_counts": load_report.raw_label_counts,
        "label_mapping": wp.LABEL_MAP,
    }
    report = output.metrics | {
        "task": TASK,
        "scope": SCOPE_NOTE,
        "class_descriptions": {c: wp.CLASS_DESCRIPTIONS[c] for c in output.labels},
        "lexical_out_of_distribution": lexical,
        "latency": latency,
        "hardware": hw,
        "timings_seconds": {
            "preprocessing": round(preprocessing_seconds, 3),
            **{k.replace("_seconds", ""): round(v, 3) for k, v in output.timings.items()},
        },
        "leakage": {
            "failures": [],
            "warnings": [],
            "shortcut_features": [],
            "checks": [
                "template-signature groups never cross splits",
                "vectorizer fitted on the training split only",
                "malformed rows with glued-in label text excluded",
            ],
        },
    }
    with factory() as session, session.begin():
        version = repo.next_version(session, MODEL_NAME)
        model_id = uuid.uuid4()
        manifest = {
            "model_id": str(model_id),
            "name": MODEL_NAME,
            "version": version,
            "task": TASK,
            "algorithm": output.metrics["primary_model"],
            "feature_set": wp.FEATURE_SET,
            "input_schema": {
                "type": "string",
                "description": "one HTTP parameter value",
                "max_chars": wp.MAX_PAYLOAD_CHARS,
            },
            "class_labels": output.labels,
            "label_mapping_version": wp.LABEL_MAPPING_VERSION,
            "training_run_id": str(run_id),
            "random_seed": seed,
            "environment": env,
            "snapshot_hash": load_report.file_sha256,
            "created_at": clock.now(),
            "scope": SCOPE_NOTE,
        }
        path, sha = artifacts.save(
            settings.artifact_dir, MODEL_NAME, version, output.pipeline, manifest, report
        )
        report["model_size_bytes"] = path.stat().st_size
        session.add(
            MlModel(
                model_id=model_id,
                name=MODEL_NAME,
                version=version,
                task=TASK,
                algorithm=output.metrics["primary_model"],
                status="candidate",
                training_run_id=run_id,
                artifact_path=str(path),
                artifact_sha256=sha,
                feature_set_version=wp.FEATURE_SET,
                label_mapping_version=wp.LABEL_MAPPING_VERSION,
                class_labels=output.labels,
            )
        )
        done = session.get(MlTrainingRun, run_id, with_for_update=True)
        assert done is not None
        run = done
        report["timings_seconds"]["total_including_save"] = round(time.perf_counter() - started, 3)
        run.status, run.finished_at = "succeeded", clock.now()
        run.metrics = report
        run.dataset_snapshot = snapshot
        run.baseline_metrics = {"dummy_stratified": report["models"]["dummy_stratified"]}
        run.confusion_matrix = report["models"][report["primary_model"]]["test"]["confusion_matrix"]
        run.leakage_checks = report["leakage"]
        run.environment = env
        audit.record(
            session,
            actor,
            "ml.model_registered",
            target_type="ml_model",
            target_id=model_id,
            details={"name": MODEL_NAME, "version": version},
        )
    return {
        "run_id": str(run_id),
        "model_id": str(model_id),
        "version": version,
        "artifact_path": str(path),
        "report": report,
        "snapshot": snapshot,
    }


# --- inference ---------------------------------------------------------------------------------

_CACHE: dict[str, Any] = {}


def _active_model(session: Session, model_id: uuid.UUID | None) -> MlModel:
    stmt = select(MlModel).where(MlModel.task == TASK)
    stmt = (
        stmt.where(MlModel.model_id == model_id)
        if model_id
        else stmt.where(MlModel.name == MODEL_NAME, MlModel.status == "active")
    )
    model = session.scalar(stmt)
    if model is None:
        raise NotFoundError(
            "no such web payload model"
            if model_id
            else f"no active model named {MODEL_NAME!r}; train and promote one first"
        )
    return model


def classify(
    session: Session, settings: Settings, payloads: list[str], model_id: uuid.UUID | None = None
) -> dict[str, Any]:
    if len(payloads) > MAX_BATCH:
        raise ValidationFailedError(f"at most {MAX_BATCH} payloads per request")
    with session.begin():
        model = _active_model(session, model_id)
        info = {
            "model_id": model.model_id,
            "name": model.name,
            "version": model.version,
            "status": model.status,
            "algorithm": model.algorithm,
        }
        path, sha = model.artifact_path, model.artifact_sha256
    pipeline = _CACHE.get(sha)
    if pipeline is None:
        pipeline, _ = artifacts.load(settings.artifact_dir, path, sha)
        _CACHE.clear()
        _CACHE[sha] = pipeline
    return {"model": info, "results": wp.predict(pipeline, payloads), "note": SCOPE_NOTE}


# --- scoring stored HTTP events ----------------------------------------------------------------


def start_scoring(
    session: Session,
    actor: Actor,
    scope: dict[str, Any],
    model_id: uuid.UUID | None,
    *,
    enqueue: bool = True,
) -> MlScoringRun:
    """Queue classification of the decoded query parameters of stored HTTP events."""
    if not scope.get("batch_ids") and not (scope.get("from") and scope.get("to")):
        raise ValidationFailedError(
            "scope needs batch_ids or from/to",
            errors=[FieldError("scope", "required", "batch_ids or from+to")],
        )
    with session.begin():
        model = (
            repo.get_model(session, model_id)
            if model_id
            else repo.active_model(session, MODEL_NAME)
        )
        if model is None:
            raise NotFoundError(
                "no such model" if model_id else f"no active model named {MODEL_NAME!r}"
            )
        if model.task != TASK:
            raise ConflictError("model is not a web payload classification model")
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
            details={"model_id": str(model.model_id), "task": TASK},
        )
        session.flush()
        session.expunge(run)
        return run


def _param_pairs(value: Any) -> list[tuple[str, str]] | None:
    """The adapter stores ``[[name, value], ...]``; anything else is not scored."""
    if not isinstance(value, list):
        return None
    pairs = []
    for item in value:
        if not (
            isinstance(item, list) and len(item) == 2 and all(isinstance(x, str) for x in item)
        ):
            return None
        pairs.append((item[0], item[1]))
    return pairs


def _prediction_rows(
    pipeline: Any, chunk: list[dict[str, Any]], skipped: dict[str, int]
) -> list[dict[str, Any]]:
    keys: list[tuple[int, datetime, int, str]] = []
    values: list[str] = []
    for event in chunk:
        if event["query_params"] is None:
            skipped["no_query_params"] += 1
            continue
        pairs = _param_pairs(event["query_params"])
        if pairs is None:
            skipped["malformed_query_params"] += 1
            continue
        if not pairs:
            skipped["no_query_params"] += 1
            continue
        for index, (name, value) in enumerate(pairs):
            if value == "":
                skipped["empty_values"] += 1  # nothing to classify
                continue
            keys.append((int(event["event_id"]), event["event_time"], index, name))
            values.append(value)
    rows = []
    for (event_id, event_time, index, name), p in zip(
        keys, wp.predict(pipeline, values), strict=True
    ):
        rows.append(
            {
                "event_id": event_id,
                "event_time": event_time,
                "param_index": index,
                "param_name": name,
                "predicted_class": p["predicted_class"],
                "is_attack_like": p["is_attack_like"],
                "score": p["score"],
                "score_kind": p["score_kind"],
                "class_scores": p["class_scores"],
                "truncated": p["truncated"],
            }
        )
    return rows


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
    scored = 0
    skipped = {"no_query_params": 0, "malformed_query_params": 0, "empty_values": 0}
    http_events, flagged_events = 0, 0
    try:
        pipeline, manifest = artifacts.load(settings.artifact_dir, path, sha)
        if manifest.get("feature_set") != wp.FEATURE_SET:
            raise artifacts.ArtifactError(
                "FEATURE_SET_CHANGED",
                f"model needs {manifest.get('feature_set')}, have {wp.FEATURE_SET}",
            )
        with factory() as session:
            for chunk in wp_repo.http_events(session, scope, SCORE_CHUNK):
                session.rollback()  # end the read snapshot between chunks
                http_events += len(chunk)
                rows = _prediction_rows(pipeline, chunk, skipped)
                if not rows:
                    continue
                flagged_events += len(
                    {(r["event_id"], r["event_time"]) for r in rows if r["is_attack_like"]}
                )
                for r in rows:
                    r["model_id"], r["scoring_run_id"] = model_id, scoring_run_id
                with session.begin():
                    scored += wp_repo.insert_results(session, rows)
                if progress:
                    progress(scored, None, "parameters")
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
        # rows_scored = newly stored parameter predictions (a re-run skips existing ones);
        # the counters below describe the whole scope of this run.
        done.rows_scored = scored
        done.rows_skipped = skipped | {
            "http_events_in_scope": http_events,
            "events_with_attack_like_params": flagged_events,
        }
        session.flush()
        session.expunge(done)
        return done


def get_scoring_run(session: Session, run_id: uuid.UUID) -> MlScoringRun:
    with session.begin():
        run = repo.get_scoring_run(session, run_id)
        model = repo.get_model(session, run.model_id) if run else None
        if run is None or model is None or model.task != TASK:
            raise NotFoundError(f"web payload scoring run {run_id} not found")
        session.expunge(run)
        return run


# --- queries -----------------------------------------------------------------------------------


def _model_info(model: MlModel) -> dict[str, Any]:
    return {
        "model_id": model.model_id,
        "name": model.name,
        "version": model.version,
        "status": model.status,
    }


def list_results(
    session: Session,
    *,
    model_id: uuid.UUID | None,
    predicted_class: str | None,
    attack_like_only: bool,
    start: datetime | None,
    end: datetime | None,
    cursor: str | None,
    limit: int = DEFAULT_LIMIT,
) -> dict[str, Any]:
    key = decode_cursor(cursor, frozenset({"t", "id"}))
    after = (datetime.fromisoformat(key["t"]), int(key["id"])) if key else None
    with session.begin():
        model = _active_model(session, model_id)
        rows = wp_repo.list_results(
            session,
            model.model_id,
            predicted_class=predicted_class,
            attack_like_only=attack_like_only,
            start=start,
            end=end,
            after=after,
            limit=limit + 1,
        )
        info = _model_info(model)
    items = rows[:limit]
    nxt = None
    if len(rows) > limit:
        nxt = encode_cursor(
            {"t": items[-1]["event_time"].isoformat(), "id": items[-1]["result_id"]}
        )
    for r in items:
        r["event_id"] = str(r["event_id"])
        r["score_is_calibrated"] = False
    return {"model": info, "items": items, "next_cursor": nxt, "limit": limit, "note": SCOPE_NOTE}


def summary(
    session: Session, model_id: uuid.UUID | None, start: datetime | None, end: datetime | None
) -> dict[str, Any]:
    with session.begin():
        model = _active_model(session, model_id)
        counts = wp_repo.class_counts(session, model.model_id, start, end)
        info = _model_info(model)
    return {
        "model": info,
        "from": start,
        "to": end,
        "predictions_by_class": [
            {"predicted_class": c, "parameters": n, "events": e} for c, n, e in counts
        ],
        "note": SCOPE_NOTE,
    }


def event_results(session: Session, event_id: int, event_time: datetime) -> list[dict[str, Any]]:
    """Per-parameter predictions for one event (predictions, not observations)."""
    return [
        {
            "model": {"model_id": r[0].model_id, "name": r[1], "version": r[2], "status": r[3]},
            "result_id": str(r[0].result_id),
            "param_index": r[0].param_index,
            "param_name": r[0].param_name,
            "predicted_class": r[0].predicted_class,
            "is_attack_like": r[0].is_attack_like,
            "score": r[0].score,
            "score_kind": r[0].score_kind,
            "score_is_calibrated": False,
            "class_scores": r[0].class_scores,
            "truncated": r[0].truncated,
            "scored_at": r[0].scored_at,
        }
        for r in wp_repo.results_for_event(session, event_id, event_time)
    ]
