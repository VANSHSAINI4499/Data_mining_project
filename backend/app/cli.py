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
        f"{result.sources_existing} already present"
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

    p = sub.add_parser("seed-reference", help="load attack categories and default sources")
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
