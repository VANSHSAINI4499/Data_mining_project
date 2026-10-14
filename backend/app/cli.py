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
    p.add_argument("task", choices=["classifier", "anomaly"])
    p.add_argument("--config", default="config/ml/classifier_default.toml")
    p.add_argument("--batch-id", action="append")
    p.set_defaults(func=cmd_train)

    p = sub.add_parser("score", help="score events with the active model (inline)")
    p.add_argument("task", choices=["classifier", "anomaly"])
    p.add_argument("--batch-id", action="append")
    p.add_argument("--from", dest="from_")
    p.add_argument("--to")
    p.add_argument("--model-id", help="anomaly: score with this model (default: active --name)")
    p.add_argument("--name", help="anomaly: registry name of the active model to use")
    p.set_defaults(func=cmd_score)

    p = sub.add_parser("models", help="model registry operations")
    p.add_argument("action", choices=["list", "promote", "archive", "reject"])
    p.add_argument("model_id", nargs="?")
    p.add_argument("--reason")
    p.set_defaults(func=cmd_models)

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
