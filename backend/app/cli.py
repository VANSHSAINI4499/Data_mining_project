"""The ``cti`` command-line interface (DEPLOYMENT_GUIDE.md §15).

Commands run in-process with operator privileges and are audited with ``actor_type = cli``.
"""

from __future__ import annotations

import argparse
import getpass
import json
import signal
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from types import FrameType

from app.core.config import get_settings
from app.core.db import get_session_factory
from app.core.errors import DomainError
from app.core.logging import configure_logging
from app.core.security import Role
from app.services import jobs as jobs_service
from app.services import users as users_service
from app.services.actors import CLI_ACTOR


def _read_password(from_stdin: bool) -> str:
    if from_stdin:
        return sys.stdin.readline().rstrip("\r\n")
    first = getpass.getpass("Password: ")
    if first != getpass.getpass("Repeat password: "):
        raise SystemExit("error: passwords do not match")
    return first


def cmd_create_admin(args: argparse.Namespace) -> int:
    password = _read_password(args.password_stdin)
    with get_session_factory()() as session:
        user = users_service.create_user(session, CLI_ACTOR, args.username, password, Role.ADMIN)
    print(f"created admin {user.username!r} ({user.user_id})")
    return 0


def cmd_worker(args: argparse.Namespace) -> int:
    from app.jobs.registry import HANDLERS
    from app.jobs.worker import Worker

    settings = get_settings()
    stop = threading.Event()

    def _stop(signum: int, frame: FrameType | None) -> None:
        stop.set()

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)
    worker = Worker(get_session_factory(), settings, HANDLERS)
    if args.once:
        worker.reap_stale()
        ran = worker.run_once()
        print("ran one job" if ran else "no runnable job")
        return 0
    worker.run_forever(stop, Path(args.heartbeat_file) if args.heartbeat_file else None)
    return 0


def cmd_worker_healthcheck(args: argparse.Namespace) -> int:
    from app.jobs.worker import heartbeat_is_fresh

    fresh = heartbeat_is_fresh(Path(args.heartbeat_file), args.max_age_seconds)
    print("healthy" if fresh else "unhealthy")
    return 0 if fresh else 1


def cmd_diagnostic_job(args: argparse.Namespace) -> int:
    params = {
        "sleep_seconds": args.sleep_seconds,
        "steps": args.steps,
        "fail": args.fail,
        "transient_failures": args.transient_failures,
    }
    with get_session_factory()() as session:
        job = jobs_service.enqueue(session, CLI_ACTOR, "diagnostic", params)
    print(json.dumps({"job_id": str(job.job_id), "status": job.status}))
    return 0


def cmd_seed_reference(args: argparse.Namespace) -> int:
    from app.services.reference import seed_reference

    with get_session_factory()() as session:
        result = seed_reference(session, CLI_ACTOR)
    print(
        f"attack categories: {result.categories_created} created, "
        f"{result.categories_updated} updated; sources: {result.sources_created} created, "
        f"{result.sources_existing} already present; feeds: {result.feeds_created} created; "
        f"correlation rules: {result.rules_created} created"
    )
    return 0


def cmd_ingest(args: argparse.Namespace) -> int:
    from datetime import date

    from app.services import data_quality
    from app.services.ingestion import BatchOptions, create_cli_batch, process_batch

    settings = get_settings()
    options = BatchOptions(
        variant=args.variant,
        assume_event_date=date.fromisoformat(args.assume_event_date)
        if args.assume_event_date
        else None,
        timezone=args.timezone,
        date_order=args.date_order,
        dataset_partition=args.dataset_partition,
    )
    factory = get_session_factory()
    with factory() as session:
        batch, duplicate = create_cli_batch(
            session,
            settings,
            CLI_ACTOR,
            source_key=args.source,
            adapter_name=args.adapter,
            path=Path(args.path),
            options=options,
        )
    if duplicate:
        print(
            json.dumps(
                {
                    "batch_id": str(batch.batch_id),
                    "status": "duplicate",
                    "duplicate_of": str(batch.duplicate_of),
                }
            )
        )
        return 0
    outcome = process_batch(factory, settings, batch.batch_id, on_complete=data_quality.run_checks)
    print(
        json.dumps(
            {
                "batch_id": str(outcome.batch_id),
                "status": outcome.status,
                "records_total": outcome.records_total,
                "records_loaded": outcome.records_loaded,
                "records_rejected": outcome.records_rejected,
                "records_duplicate": outcome.records_duplicate,
                "error": outcome.error,
            }
        )
    )
    return 1 if outcome.status == "failed" else 0


def cmd_generate_synthetic(args: argparse.Namespace) -> int:
    from app.devtools.synthetic import write

    paths = write(
        Path(args.out), seed=args.seed, days=args.days, flows_per_hour=args.flows_per_hour
    )
    print(json.dumps({k: str(v) for k, v in paths.items()}))
    return 0


def cmd_train(args: argparse.Namespace) -> int:
    from app.ml.classification.training import TrainingError
    from app.services import classification

    if args.task == "anomaly":
        return _train_anomaly(args)
    if args.task == "web-payload":
        return _train_web_payload(args)
    config = classification.load_config_file(Path(args.config), args.batch_id or [])
    factory = get_session_factory()
    with factory() as session:
        run = classification.start_training(session, CLI_ACTOR, config, enqueue=False)
    try:
        done = classification.run_training(
            factory, get_settings(), run.run_id, lambda m: print(f"... {m}", file=sys.stderr)
        )
    except TrainingError as exc:
        print(json.dumps({"run_id": str(run.run_id), "status": "failed", "error": str(exc)}))
        return 1
    rf = (done.metrics or {}).get("models", {}).get("random_forest", {}).get("test", {})
    print(
        json.dumps(
            {
                "run_id": str(done.run_id),
                "status": done.status,
                "test_macro_f1": rf.get("macro_f1"),
                "test_weighted_f1": rf.get("weighted_f1"),
                "leakage_warnings": (done.leakage_checks or {}).get("warnings", []),
            }
        )
    )
    return 0


def cmd_score(args: argparse.Namespace) -> int:
    from app.services import classification

    if args.task == "anomaly":
        return _score_anomaly(args)
    if args.task == "web-payload":
        return _score_web_payload(args)
    scope: dict[str, object] = {}
    if args.batch_id:
        scope["batch_ids"] = args.batch_id
    if args.from_:
        scope["from"] = args.from_
    if args.to:
        scope["to"] = args.to
    factory = get_session_factory()
    with factory() as session:
        run = classification.start_scoring(session, CLI_ACTOR, scope, None, enqueue=False)
    done = classification.run_scoring(factory, get_settings(), run.scoring_run_id)
    print(
        json.dumps(
            {
                "scoring_run_id": str(done.scoring_run_id),
                "rows_scored": done.rows_scored,
                "rows_skipped": done.rows_skipped,
            }
        )
    )
    return 0


def _score_web_payload(args: argparse.Namespace) -> int:
    import uuid

    from app.services import web_payload

    scope: dict[str, object] = {}
    if args.batch_id:
        scope["batch_ids"] = args.batch_id
    if args.from_:
        scope["from"] = args.from_
    if args.to:
        scope["to"] = args.to
    factory = get_session_factory()
    model_id = uuid.UUID(args.model_id) if args.model_id else None
    with factory() as session:
        run = web_payload.start_scoring(session, CLI_ACTOR, scope, model_id, enqueue=False)
    done = web_payload.run_scoring(factory, get_settings(), run.scoring_run_id)
    print(
        json.dumps(
            {
                "scoring_run_id": str(done.scoring_run_id),
                "evaluation_only": done.evaluation_only,
                "parameters_scored": done.rows_scored,
                "details": done.rows_skipped,
            }
        )
    )
    return 0


def _train_anomaly(args: argparse.Namespace) -> int:
    from app.ml.classification.training import TrainingError
    from app.services import anomaly

    config_path = args.config
    if config_path.endswith("classifier_default.toml"):
        config_path = "config/ml/anomaly_account_1h.toml"
    config = anomaly.load_config_file(Path(config_path))
    factory = get_session_factory()
    with factory() as session:
        run = anomaly.start_training(session, CLI_ACTOR, config, enqueue=False)
    try:
        done = anomaly.run_training(factory, get_settings(), run.run_id)
    except TrainingError as exc:
        print(json.dumps({"run_id": str(run.run_id), "status": "failed", "error": str(exc)}))
        return 1
    metrics = done.metrics or {}
    print(
        json.dumps(
            {
                "run_id": str(done.run_id),
                "status": done.status,
                "threshold": metrics.get("threshold"),
                "reference": metrics.get("reference"),
            },
            default=str,
        )
    )
    return 0


def _score_anomaly(args: argparse.Namespace) -> int:
    import uuid as _uuid
    from datetime import datetime as _dt

    from app.services import anomaly

    if not (args.from_ and args.to):
        print("error: anomaly scoring needs --from and --to", file=sys.stderr)
        return 2
    factory = get_session_factory()
    with factory() as session:
        run = anomaly.start_scoring(
            session,
            CLI_ACTOR,
            start=_dt.fromisoformat(args.from_),
            end=_dt.fromisoformat(args.to),
            model_id=_uuid.UUID(args.model_id) if args.model_id else None,
            name=args.name or "account_window_1h_iforest",
            enqueue=False,
        )
    done = anomaly.run_scoring(factory, get_settings(), run.scoring_run_id)
    print(
        json.dumps(
            {
                "scoring_run_id": str(done.scoring_run_id),
                "rows_scored": done.rows_scored,
                "rows_skipped": done.rows_skipped,
            }
        )
    )
    return 0


def cmd_models(args: argparse.Namespace) -> int:
    import uuid as _uuid

    from app.services import models as models_service

    factory = get_session_factory()
    with factory() as session:
        if args.action == "list":
            rows = models_service.list_models(session, None, None, None)
            print(json.dumps(rows, default=str, indent=2))
            return 0
        if not args.model_id:
            print("error: model_id is required", file=sys.stderr)
            return 2
        model_id = _uuid.UUID(args.model_id)
        if args.action == "promote":
            result = models_service.promote(session, CLI_ACTOR, model_id)
        elif args.action == "archive":
            result = models_service.archive(session, CLI_ACTOR, model_id)
        else:
            result = models_service.reject(
                session, CLI_ACTOR, model_id, args.reason or "rejected via CLI"
            )
    print(json.dumps(result, default=str, indent=2))
    return 0


def cmd_db(args: argparse.Namespace) -> int:
    """Role separation: run as the schema owner (CTI_MIGRATION_DATABASE_URL, else
    CTI_DATABASE_URL). Prints a privilege report; exits 1 if the report has problems."""
    import psycopg

    from app.services import db_roles

    settings = get_settings()
    owner_url = (settings.migration_database_url or settings.database_url).get_secret_value()
    try:
        if args.action == "grant-app-role":
            report = db_roles.grant_app_role(owner_url, args.role)
        else:
            with psycopg.connect(owner_url.replace("+psycopg", "", 1)) as conn:
                row = conn.execute("SELECT current_user").fetchone()
                report = db_roles.privilege_report(conn, args.role, str(row[0] if row else ""))
    except db_roles.RoleSetupError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report.as_dict(), indent=2))
    return 0 if not report.problems else 1


def cmd_artifacts_gc(args: argparse.Namespace) -> int:
    import shutil

    from app.services import models as models_service

    with get_session_factory()() as session:
        orphans = models_service.orphan_artifacts(session, get_settings())
    for path in orphans:
        print(("would remove " if args.dry_run else "removing ") + path)
        if not args.dry_run:
            shutil.rmtree(path)
    print(f"{len(orphans)} orphan artifact directories")
    return 0


def _aware(value: str, name: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise SystemExit(f"error: --{name} needs a timezone offset, e.g. 2026-01-01T00:00:00Z")
    return parsed


def cmd_attack_import(args: argparse.Namespace) -> int:
    from app.services import threat_intel

    data = Path(args.path).read_bytes()
    with get_session_factory()() as session:
        result = threat_intel.import_attack(session, CLI_ACTOR, data)
    print(json.dumps(result, default=str))
    return 0


def cmd_ti_import(args: argparse.Namespace) -> int:
    from app.services import threat_intel

    settings = get_settings()
    path = Path(args.path)
    factory = get_session_factory()
    with factory() as session:
        feed_id = threat_intel.feed_id_for_key(session, args.feed)
    with factory() as session:
        run = threat_intel.start_import(
            session,
            settings,
            CLI_ACTOR,
            feed_id=feed_id,
            fmt=args.format,
            filename=path.name,
            data=path.read_bytes(),
            enqueue=False,
        )
    done = threat_intel.run_import(factory, settings, run.feed_run_id)
    print(
        json.dumps(
            {
                "feed_run_id": str(done.feed_run_id),
                "status": done.status,
                "received": done.indicators_received,
                "created": done.indicators_created,
                "updated": done.indicators_updated,
                "rejected": done.indicators_rejected,
            }
        )
    )
    return 0


def cmd_match_indicators(args: argparse.Namespace) -> int:
    from app.services import threat_intel

    if not args.batch_id and not (args.from_ and args.to):
        raise SystemExit("error: give --batch-id or both --from and --to")
    params = {
        "from": _aware(args.from_, "from").isoformat() if args.from_ else None,
        "to": _aware(args.to, "to").isoformat() if args.to else None,
        "batch_ids": args.batch_id or [],
        "include_expired": args.include_expired,
    }
    print(json.dumps(threat_intel.run_match(get_session_factory(), params, None)))
    return 0


def cmd_correlate(args: argparse.Namespace) -> int:
    from app.services import correlation

    with get_session_factory()() as session:
        summary = correlation.run_correlation(
            session,
            CLI_ACTOR,
            _aware(args.from_, "from"),
            _aware(args.to, "to"),
            args.rule or None,
        )
    print(json.dumps(summary, default=str))
    return 0


def cmd_retention(args: argparse.Namespace) -> int:
    from app.services import retention

    if args.dry_run == args.execute:
        raise SystemExit("error: give exactly one of --dry-run or --execute")
    with get_session_factory()() as session:
        report = retention.apply(session, get_settings(), CLI_ACTOR, dry_run=args.dry_run)
    print(json.dumps(report.as_dict(), indent=2))
    return 0


def cmd_process(args: argparse.Namespace) -> int:
    from app.services import incremental

    factory = get_session_factory()
    if args.consumer:
        results = [incremental.run_consumer(factory, get_settings(), CLI_ACTOR, args.consumer)]
    else:
        results = incremental.run_all(factory, get_settings(), CLI_ACTOR)
    print(json.dumps(results, default=str, indent=2))
    return 0


def cmd_watermarks(args: argparse.Namespace) -> int:
    from app.services import incremental

    with get_session_factory()() as session:
        print(json.dumps(incremental.watermarks(session), default=str, indent=2))
    return 0


def cmd_watch(args: argparse.Namespace) -> int:
    from app.services import inbox, incremental

    settings = get_settings()
    factory = get_session_factory()
    stop = threading.Event()

    def _stop(signum: int, frame: FrameType | None) -> None:
        stop.set()

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)
    while not stop.is_set():
        results = inbox.poll_once(
            factory,
            settings,
            CLI_ACTOR,
            Path(args.inbox),
            source_key=args.source,
            adapter=args.adapter,
        )
        for item in results:
            print(json.dumps(item.__dict__, default=str), flush=True)
        if results and args.process:
            for summary in incremental.run_all(factory, settings, CLI_ACTOR):
                print(json.dumps(summary, default=str), flush=True)
        if args.once:
            break
        stop.wait(args.interval)
    return 0


def cmd_demo_site(args: argparse.Namespace) -> int:
    import uvicorn

    from app.devtools.demo_site import create_demo_app

    log_path = get_settings().import_root / "demo" / "demoshop.access.log"
    app = create_demo_app(log_path)
    print(
        json.dumps(
            {
                "serving": f"http://{args.host}:{args.port}",
                "access_log": str(log_path),
                "note": "local demo target; inputs are logged and echoed, never executed",
                "next": f"cti tail --log {log_path} --process  (in another terminal)",
            }
        ),
        flush=True,
    )
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        raise DomainError("the demo site only binds to the loopback interface")
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
    return 0


def cmd_demo_traffic(args: argparse.Namespace) -> int:
    from app.devtools import demo_traffic

    log_path = (
        Path(args.log) if args.log else get_settings().import_root / "demo" / "demoshop.access.log"
    )
    log_path.parent.mkdir(parents=True, exist_ok=True)

    def append(line: str) -> None:
        with log_path.open("a", encoding="utf-8", newline="\n") as fh:
            fh.write(line)
        if args.rate > 0:
            time.sleep(1.0 / args.rate)

    written = demo_traffic.generate(
        append, count=args.count, attack_ratio=args.attack_ratio, seed=args.seed
    )
    print(json.dumps({"log": str(log_path), **written}), flush=True)
    return 0


def cmd_tail(args: argparse.Namespace) -> int:
    """Follow a growing access log: ingest newly appended complete lines, then (optionally)
    run incremental processing, so the dashboard updates live. Tracks a byte offset so each
    line is imported once; re-importing identical lines is deduplicated by the pipeline."""
    from app.services import data_quality, incremental
    from app.services.ingestion import BatchOptions, create_cli_batch, process_batch

    settings = get_settings()
    factory = get_session_factory()
    source_log = Path(args.log)
    chunk_dir = settings.import_root / "demo" / "tail"
    chunk_dir.mkdir(parents=True, exist_ok=True)
    stop = threading.Event()

    def _stop(signum: int, frame: FrameType | None) -> None:
        stop.set()

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)
    offset = source_log.stat().st_size if (args.from_end and source_log.is_file()) else 0
    while not stop.is_set():
        if source_log.is_file() and source_log.stat().st_size > offset:
            with source_log.open("rb") as fh:
                fh.seek(offset)
                data = fh.read()
            # Only whole lines; keep the trailing partial line for the next poll.
            cut = data.rfind(b"\n") + 1
            if cut:
                chunk_path = chunk_dir / f"chunk_{int(time.time() * 1000)}.log"
                chunk_path.write_bytes(data[:cut])
                offset += cut
                with factory() as session:
                    batch, duplicate = create_cli_batch(
                        session,
                        settings,
                        CLI_ACTOR,
                        source_key=args.source,
                        adapter_name=None,
                        path=chunk_path,
                        options=BatchOptions(),
                    )
                if not duplicate:
                    outcome = process_batch(
                        factory, settings, batch.batch_id, on_complete=data_quality.run_checks
                    )
                    print(
                        json.dumps(
                            {
                                "ingested": outcome.records_loaded,
                                "rejected": outcome.records_rejected,
                                "at_offset": offset,
                            }
                        ),
                        flush=True,
                    )
                    if args.process:
                        for summary in incremental.run_all(factory, settings, CLI_ACTOR):
                            if summary.get("status") == "processed":
                                print(json.dumps(summary, default=str), flush=True)
        if args.once:
            break
        stop.wait(args.interval)
    return 0


def cmd_drift(args: argparse.Namespace) -> int:
    import uuid

    from app.services import drift

    report = drift.compute(
        get_session_factory(),
        get_settings(),
        CLI_ACTOR,
        uuid.UUID(args.model_id),
        _aware(args.from_, "from"),
        _aware(args.to, "to"),
    )
    print(json.dumps(drift.report_out(report), default=str, indent=2))
    return 0


def cmd_mine_patterns(args: argparse.Namespace) -> int:
    from app.services import patterns

    params = patterns.parse(
        {
            "entity_type": args.entity_type,
            "start": _aware(args.from_, "from"),
            "end": _aware(args.to, "to"),
            "min_support": args.min_support,
            "max_length": args.max_length,
            "max_gap_minutes": args.max_gap_minutes,
            "min_malicious_ratio": args.min_malicious_ratio,
        }
    )
    with get_session_factory()() as session:
        record = patterns.run(session, CLI_ACTOR, params)
    print(json.dumps(patterns.out(record), default=str, indent=2))
    return 0


def _train_web_payload(args: argparse.Namespace) -> int:
    from app.services import web_payload

    result = web_payload.train_from_directory(
        get_session_factory(), get_settings(), CLI_ACTOR, Path(args.dataset_dir), seed=args.seed
    )
    report = result["report"]
    primary = report["primary_model"]
    test = report["models"][primary]["test"]
    print(
        json.dumps(
            {
                "run_id": result["run_id"],
                "model_id": result["model_id"],
                "version": result["version"],
                "artifact_path": result["artifact_path"],
                "selected_model": primary,
                "test_macro_f1": test["macro_f1"],
                "test_weighted_f1": test["weighted_f1"],
                "timings_seconds": report["timings_seconds"],
                "status": "candidate (promote with `cti models promote MODEL_ID`)",
            },
            indent=2,
        )
    )
    return 0


def cmd_classify_payload(args: argparse.Namespace) -> int:
    import uuid

    from app.services import web_payload

    payloads = list(args.payload)
    if args.file:
        payloads += Path(args.file).read_text(encoding="utf-8").splitlines()
    with get_session_factory()() as session:
        result = web_payload.classify(
            session,
            get_settings(),
            payloads,
            uuid.UUID(args.model_id) if args.model_id else None,
        )
    print(json.dumps(result, default=str, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cti", description="CTI Warehouse operator commands")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("create-admin", help="create an admin user")
    p.add_argument("--username", required=True)
    p.add_argument(
        "--password-stdin",
        action="store_true",
        help="read the password from the first line of stdin instead of prompting",
    )
    p.set_defaults(func=cmd_create_admin)

    p = sub.add_parser(
        "seed-reference", help="load attack categories, sources, default feed and rules"
    )
    p.set_defaults(func=cmd_seed_reference)

    p = sub.add_parser("ingest", help="import a file under the import root (runs inline)")
    p.add_argument("--source", required=True, help="source_key, e.g. synthetic")
    p.add_argument("--adapter", help="adapter name (default: the source's default adapter)")
    p.add_argument("--variant")
    p.add_argument("--assume-event-date", help="YYYY-MM-DD for files without timestamps")
    p.add_argument("--timezone", help="IANA timezone for naive timestamps (overrides source)")
    p.add_argument("--date-order", choices=["dmy", "mdy"])
    p.add_argument("--dataset-partition", choices=["training", "testing"])
    p.add_argument("path")
    p.set_defaults(func=cmd_ingest)

    p = sub.add_parser("generate-synthetic", help="write deterministic synthetic scenario files")
    p.add_argument("--scenario", choices=["full"], default="full")
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--days", type=int, default=10)
    p.add_argument("--flows-per-hour", type=int, default=8)
    p.add_argument("--out", required=True)
    p.set_defaults(func=cmd_generate_synthetic)

    p = sub.add_parser("train", help="train a model inline")
    p.add_argument("task", choices=["classifier", "anomaly", "web-payload"])
    p.add_argument(
        "--dataset-dir",
        default="data/external/httpparams",
        help="web-payload: HTTPParamsDataset folder inside CTI_IMPORT_ROOT",
    )
    p.add_argument("--seed", type=int, default=42, help="web-payload: random seed")
    p.add_argument("--config", default="config/ml/classifier_default.toml")
    p.add_argument("--batch-id", action="append")
    p.set_defaults(func=cmd_train)

    p = sub.add_parser("score", help="score events with the active model (inline)")
    p.add_argument("task", choices=["classifier", "anomaly", "web-payload"])
    p.add_argument("--batch-id", action="append")
    p.add_argument("--from", dest="from_")
    p.add_argument("--to")
    p.add_argument(
        "--model-id",
        help="anomaly / web-payload: score with this model (default: the active model)",
    )
    p.add_argument("--name", help="anomaly: registry name of the active model to use")
    p.set_defaults(func=cmd_score)

    p = sub.add_parser("models", help="model registry operations")
    p.add_argument("action", choices=["list", "promote", "archive", "reject"])
    p.add_argument("model_id", nargs="?")
    p.add_argument("--reason")
    p.set_defaults(func=cmd_models)

    p = sub.add_parser(
        "db", help="database role separation (run as the schema owner / migration role)"
    )
    p.add_argument("action", choices=["grant-app-role", "check-app-role"])
    p.add_argument("--role", required=True, help="DML-only application role (must exist)")
    p.set_defaults(func=cmd_db)

    p = sub.add_parser("artifacts", help="artifact maintenance")
    p.add_argument("action", choices=["gc"])
    p.add_argument("--dry-run", action="store_true")
    p.set_defaults(func=cmd_artifacts_gc)

    p = sub.add_parser("attack-import", help="import a MITRE ATT&CK Enterprise STIX bundle")
    p.add_argument("path")
    p.set_defaults(func=cmd_attack_import)

    p = sub.add_parser("ti-import", help="import a CSV or STIX 2.1 indicator file (inline)")
    p.add_argument("--feed", required=True, help="feed_key, e.g. local-csv")
    p.add_argument("--format", required=True, choices=["csv", "stix"])
    p.add_argument("path")
    p.set_defaults(func=cmd_ti_import)

    p = sub.add_parser("match-indicators", help="match indicators against stored events")
    p.add_argument("--batch-id", action="append")
    p.add_argument("--from", dest="from_")
    p.add_argument("--to")
    p.add_argument("--include-expired", action="store_true")
    p.set_defaults(func=cmd_match_indicators)

    p = sub.add_parser("correlate", help="run enabled correlation rules over a time range")
    p.add_argument("--from", dest="from_", required=True)
    p.add_argument("--to", required=True)
    p.add_argument("--rule", action="append", help="limit to this rule_key (repeatable)")
    p.set_defaults(func=cmd_correlate)

    p = sub.add_parser("retention", help="apply the data-retention policy (audited)")
    p.add_argument("action", choices=["apply"])
    p.add_argument("--dry-run", action="store_true", help="count only; change nothing")
    p.add_argument("--execute", action="store_true", help="delete per policy")
    p.set_defaults(func=cmd_retention)

    p = sub.add_parser("process", help="incremental matching, scoring, and correlation")
    p.add_argument(
        "--incremental",
        action="store_true",
        required=True,
        help="process only batches completed since each consumer's watermark",
    )
    p.add_argument(
        "--consumer",
        choices=["indicator_matching", "classifier_scoring", "anomaly_scoring", "correlation"],
    )
    p.set_defaults(func=cmd_process)

    p = sub.add_parser("watermarks", help="show incremental-processing watermarks")
    p.set_defaults(func=cmd_watermarks)

    p = sub.add_parser("watch", help="import files dropped into an inbox folder")
    p.add_argument("--inbox", required=True, help="folder inside CTI_IMPORT_ROOT")
    p.add_argument("--source", required=True)
    p.add_argument("--adapter")
    p.add_argument("--interval", type=float, default=10.0, help="seconds between polls")
    p.add_argument("--once", action="store_true", help="poll once, then exit")
    p.add_argument(
        "--process",
        action="store_true",
        help="run incremental processing after new files are imported",
    )
    p.set_defaults(func=cmd_watch)

    p = sub.add_parser("demo-site", help="run the local demo target website (loopback only)")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8800)
    p.set_defaults(func=cmd_demo_site)

    p = sub.add_parser(
        "demo-traffic", help="write synthetic benign+attack access-log lines for the demo"
    )
    p.add_argument("--log", help="access log to append to (default: the demo site's log)")
    p.add_argument("--count", type=int, default=60, help="number of log lines to write")
    p.add_argument("--attack-ratio", type=float, default=0.25, help="fraction that are attacks")
    p.add_argument("--rate", type=float, default=0.0, help="lines/sec (0 = as fast as possible)")
    p.add_argument("--seed", type=int, default=42)
    p.set_defaults(func=cmd_demo_traffic)

    p = sub.add_parser("tail", help="follow a growing access log and ingest new lines live")
    p.add_argument("--log", required=True, help="access-log file to follow")
    p.add_argument("--source", default="web-server")
    p.add_argument("--interval", type=float, default=3.0, help="seconds between polls")
    p.add_argument("--from-end", action="store_true", help="skip lines already in the file")
    p.add_argument("--once", action="store_true", help="process current content once, then exit")
    p.add_argument(
        "--process", action="store_true", help="run scoring and correlation after each ingest"
    )
    p.set_defaults(func=cmd_tail)

    p = sub.add_parser("drift", help="compute a drift report for a model (informational)")
    p.add_argument("model_id")
    p.add_argument("--from", dest="from_", required=True)
    p.add_argument("--to", required=True)
    p.set_defaults(func=cmd_drift)

    p = sub.add_parser("mine-patterns", help="mine candidate sequence rules (human review)")
    p.add_argument("--entity-type", required=True, choices=["account", "src_ip", "dst_ip", "host"])
    p.add_argument("--from", dest="from_", required=True)
    p.add_argument("--to", required=True)
    p.add_argument("--min-support", type=int, default=2)
    p.add_argument("--max-length", type=int, default=3)
    p.add_argument("--max-gap-minutes", type=int, default=30)
    p.add_argument("--min-malicious-ratio", type=float, default=0.5)
    p.set_defaults(func=cmd_mine_patterns)

    p = sub.add_parser(
        "classify-payload", help="classify HTTP parameter values with the web payload model"
    )
    p.add_argument("payload", nargs="*", help="parameter values to classify")
    p.add_argument("--file", help="text file with one parameter value per line")
    p.add_argument("--model-id", help="use this model instead of the active one")
    p.set_defaults(func=cmd_classify_payload)

    p = sub.add_parser("worker", help="run the background job worker")
    p.add_argument("--heartbeat-file", help="file touched every poll interval (health checks)")
    p.add_argument("--once", action="store_true", help="run at most one job, then exit")
    p.set_defaults(func=cmd_worker)

    p = sub.add_parser("worker-healthcheck", help="exit 0 if the worker heartbeat is fresh")
    p.add_argument("--heartbeat-file", required=True)
    p.add_argument("--max-age-seconds", type=float, default=60.0)
    p.set_defaults(func=cmd_worker_healthcheck)

    p = sub.add_parser("diagnostic-job", help="enqueue a diagnostic job to exercise the queue")
    p.add_argument("--sleep-seconds", type=float, default=0.0)
    p.add_argument("--steps", type=int, default=3)
    p.add_argument("--fail", action="store_true", help="make the job fail deliberately")
    p.add_argument(
        "--transient-failures",
        type=int,
        default=0,
        help="fail transiently on the first N attempts (exercises retries)",
    )
    p.set_defaults(func=cmd_diagnostic_job)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    configure_logging(get_settings().log_level)
    try:
        return int(args.func(args))
    except DomainError as exc:
        details = "; ".join(f"{e.field}: {e.message}" for e in exc.errors)
        print(f"error: {exc.detail}" + (f" ({details})" if details else ""), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
