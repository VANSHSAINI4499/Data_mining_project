"""Job handler contract and the context handlers receive."""

from __future__ import annotations

import threading
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.orm import Session, sessionmaker

from app.services import jobs as jobs_service


class TransientJobError(Exception):
    """Raise for failures worth retrying (connection loss, deadlock, temporary I/O)."""


class JobCancelledError(Exception):
    """Raised by ``JobContext.check_cancelled`` when cancellation was requested."""


@dataclass
class JobContext:
    job_id: uuid.UUID
    job_type: str
    params: dict[str, Any]
    attempt: int
    session_factory: sessionmaker[Session]
    cancel_event: threading.Event = field(default_factory=threading.Event)

    def report_progress(self, done: int, total: int | None, unit: str) -> None:
        """Record honest progress; pass ``total=None`` when the total is unknown."""
        with self.session_factory() as session:
            jobs_service.report_progress(
                session, self.job_id, {"done": done, "total": total, "unit": unit}
            )

    def check_cancelled(self) -> None:
        if self.cancel_event.is_set():
            raise JobCancelledError()


JobHandler = Callable[[JobContext], dict[str, Any]]
