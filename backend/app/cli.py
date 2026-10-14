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
