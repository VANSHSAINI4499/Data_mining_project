"""Ingestion use cases (DATA_INGESTION.md): create batches, load them, query them.

Transaction boundaries (DATABASE_DESIGN.md §10): batch creation + job + audit commit together;
loading commits one chunk at a time so a failure loses at most one chunk and can resume from
``last_committed_record``.
"""

from __future__ import annotations

import hashlib
import threading
import uuid
from collections import deque
from collections.abc import Callable, Iterable
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from pathlib import Path
from typing import IO, Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import psycopg
from sqlalchemy.engine import Connection
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import Session, sessionmaker

from app.core import clock
from app.core.config import Settings
from app.core.errors import (
    ConflictError,
    FieldError,
    NotFoundError,
    PayloadTooLargeError,
    UnsupportedMediaTypeError,
    ValidationFailedError,
)
from app.core.pagination import DEFAULT_LIMIT, decode_cursor, encode_cursor
from app.ingestion import errors as E
from app.ingestion.adapters import ADAPTERS, get_adapter_class
from app.ingestion.adapters.base import Adapter
from app.ingestion.errors import BatchFatalError
from app.ingestion.labels import LabelMapping, load_mapping
from app.ingestion.pipeline import Prepared, prepare_record
from app.ingestion.readers import BINARY_SNIFF_BYTES, looks_binary
from app.ingestion.records import BatchContext
from app.models import DimAsset, IngestionBatch, RejectedRecord
from app.repositories import ingestion as repo
from app.repositories import reference as reference_repo
from app.services import audit
from app.services import jobs as jobs_service
from app.services.actors import Actor

JOB_TYPE = "ingestion.process_batch"
ALLOWED_EXTENSIONS = frozenset({".csv", ".tsv", ".log", ".json", ".jsonl", ".ndjson"})
REJECTION_CHECK_AFTER = 10_000
COPY_CHUNK = 1024 * 1024
DATE_ORDERS = frozenset({"dmy", "mdy"})
DATASET_PARTITIONS = frozenset({"training", "testing"})
TERMINAL_OK = frozenset({"completed", "completed_with_errors", "duplicate"})


class BatchFailedError(Exception):
    """Raised to the job runner after a batch was marked failed (not retried)."""


@dataclass(frozen=True)
class BatchOptions:
    variant: str | None = None
    assume_event_date: date | None = None
    timezone: str | None = None  # overrides the source default for this batch
    date_order: str | None = None
    dataset_partition: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "variant": self.variant,
            "assume_event_date": self.assume_event_date.isoformat()
            if self.assume_event_date
            else None,
            "timezone": self.timezone,
            "date_order": self.date_order,
            "dataset_partition": self.dataset_partition,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BatchOptions:
        assumed = data.get("assume_event_date")
        return cls(
            variant=data.get("variant"),
            assume_event_date=date.fromisoformat(assumed) if assumed else None,
            timezone=data.get("timezone"),
            date_order=data.get("date_order"),
            dataset_partition=data.get("dataset_partition"),
        )


@dataclass
class BatchOutcome:
    batch_id: uuid.UUID
    status: str
    records_total: int
    records_loaded: int
    records_rejected: int
    records_duplicate: int
    error: dict[str, Any] | None = None


# --- adapters --------------------------------------------------------------------------------


def adapter_catalog() -> list[dict[str, Any]]:
    return [
        {
            "name": cls.name,
            "version": cls.version,
            "description": cls.description,
            "extensions": sorted(cls.extensions),
            "event_types": list(cls.event_types),
            "variants": list(cls.variants),
            "label_mapping": cls.label_mapping,
        }
        for cls in sorted(ADAPTERS.values(), key=lambda c: c.name)
    ]


def _adapter_class(name: str) -> type[Adapter]:
    cls = get_adapter_class(name)
    if cls is None:
        raise ValidationFailedError(
            f"unknown adapter {name!r}",
            errors=[FieldError("adapter", "unknown_adapter", f"supported: {sorted(ADAPTERS)}")],
        )
    return cls


def validate_options(options: BatchOptions, adapter_cls: type[Adapter]) -> None:
    problems: list[FieldError] = []
    if options.variant is not None and options.variant not in adapter_cls.variants:
        problems.append(
            FieldError("variant", "unknown_variant", f"supported: {list(adapter_cls.variants)}")
        )
    if options.timezone is not None:
        try:
            ZoneInfo(options.timezone)
        except (ZoneInfoNotFoundError, ValueError):
            problems.append(FieldError("timezone", "unknown_timezone", "not an IANA timezone"))
    if options.date_order is not None and options.date_order not in DATE_ORDERS:
        problems.append(FieldError("date_order", "invalid_choice", "use dmy or mdy"))
    if (
        options.dataset_partition is not None
        and options.dataset_partition not in DATASET_PARTITIONS
    ):
        problems.append(
            FieldError("dataset_partition", "invalid_choice", "use training or testing")
        )
    if problems:
        raise ValidationFailedError("invalid ingestion options", errors=problems)


def _check_extension(filename: str, adapter_cls: type[Adapter]) -> str:
    ext = Path(filename).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise UnsupportedMediaTypeError(
            f"file extension {ext or '(none)'!r} is not allowed; allowed: "
            f"{', '.join(sorted(ALLOWED_EXTENSIONS))} (compressed files are not supported)"
        )
    if ext not in adapter_cls.extensions:
        raise UnsupportedMediaTypeError(
            f"adapter {adapter_cls.name!r} does not accept {ext!r} files; it accepts "
            f"{', '.join(sorted(adapter_cls.extensions))}"
        )
    return ext


# --- creating batches --------------------------------------------------------------------------


def _resolve_source_and_adapter(
    session: Session, source_id: int | None, source_key: str | None, adapter_name: str | None
) -> tuple[int, type[Adapter]]:
    with session.begin():
        source = (
            repo.get_source(session, source_id)
            if source_id is not None
            else repo.get_source_by_key(session, source_key or "")
        )
        if source is None:
            raise NotFoundError(f"source {source_id or source_key!r} not found")
        if not source.is_active:
            raise ConflictError(f"source {source.source_key!r} is inactive")
        name = adapter_name or source.default_adapter
        sid = source.source_id
    if not name:
        raise ValidationFailedError(
            "no adapter given and the source has no default adapter",
            errors=[FieldError("adapter", "required", "choose an adapter")],
        )
    return sid, _adapter_class(name)


def _register_batch(
    session: Session,
    actor: Actor,
    *,
    batch_id: uuid.UUID,
    source_id: int,
    adapter_cls: type[Adapter],
    original_filename: str,
    stored_path: str,
    file_sha256: str,
    size: int,
    options: BatchOptions,
    enqueue: bool,
) -> tuple[IngestionBatch, bool]:
    """Insert the batch (or a ``duplicate`` marker). Returns (batch, is_duplicate)."""
    common = dict(
        source_id=source_id,
        adapter=adapter_cls.name,
        adapter_version=adapter_cls.version,
        original_filename=original_filename[:255],
        file_sha256=file_sha256,
        file_size_bytes=size,
        batch_metadata={"options": options.as_dict()},
        created_by=actor.user_id,
    )
    for _attempt in range(2):
        try:
            with session.begin():
                existing = repo.find_ingested_file(
                    session, source_id, file_sha256, adapter_cls.name, adapter_cls.version
                )
                if existing is not None:
                    batch = IngestionBatch(
                        batch_id=batch_id,
                        status="duplicate",
                        stored_path=existing.stored_path,
                        duplicate_of=existing.batch_id,
                        finished_at=clock.now(),
                        **common,
                    )
                    session.add(batch)
                    session.flush()
                    audit.record(
                        session,
                        actor,
                        "ingestion.upload",
                        target_type="ingestion_batch",
                        target_id=batch_id,
                        details={"duplicate_of": str(existing.batch_id)},
                    )
                    return batch, True
                batch = IngestionBatch(
                    batch_id=batch_id, status="pending", stored_path=stored_path, **common
                )
                session.add(batch)
                session.flush()
                if enqueue:
                    job = jobs_service.enqueue_in_transaction(
                        session, actor, JOB_TYPE, {"batch_id": str(batch_id)}
                    )
                    batch.job_id = job.job_id
                audit.record(
                    session,
                    actor,
                    "ingestion.upload",
                    target_type="ingestion_batch",
                    target_id=batch_id,
                    details={"adapter": adapter_cls.name, "size": size, "sha256": file_sha256},
                )
                return batch, False
        except IntegrityError:
            continue  # a concurrent upload of the same file won the race; re-check as duplicate
    raise ConflictError("the same file is being registered concurrently; retry")


def create_upload_batch(
    session: Session,
    settings: Settings,
    actor: Actor,
    *,
    source_id: int,
    adapter_name: str | None,
    filename: str,
    fileobj: IO[bytes],
    options: BatchOptions,
) -> tuple[IngestionBatch, bool]:
    sid, adapter_cls = _resolve_source_and_adapter(session, source_id, None, adapter_name)
    validate_options(options, adapter_cls)
    ext = _check_extension(filename, adapter_cls)

    batch_id = uuid.uuid4()
    settings.upload_dir.mkdir(parents=True, exist_ok=True)
    dest = settings.upload_dir / f"{batch_id}{ext}"  # server-generated name only
    limit = settings.max_upload_mb * 1024 * 1024
    digest = hashlib.sha256()
    size = 0
    try:
        with dest.open("xb") as out:
            first = True
            while chunk := fileobj.read(COPY_CHUNK):
                if first and looks_binary(chunk[:BINARY_SNIFF_BYTES]):
                    raise UnsupportedMediaTypeError("file looks binary (contains NUL bytes)")
                first = False
                size += len(chunk)
                if size > limit:
                    raise PayloadTooLargeError(
                        f"upload exceeds {settings.max_upload_mb} MB; use `cti ingest` for "
                        "large files"
                    )
                digest.update(chunk)
                out.write(chunk)
        if size == 0:
            raise ValidationFailedError(
                "the uploaded file is empty", errors=[FieldError("file", "empty", "no content")]
            )
        batch, duplicate = _register_batch(
            session,
            actor,
            batch_id=batch_id,
            source_id=sid,
            adapter_cls=adapter_cls,
            original_filename=Path(filename).name,
            stored_path=str(dest),
            file_sha256=digest.hexdigest(),
            size=size,
            options=options,
            enqueue=True,
        )
    except BaseException:
        dest.unlink(missing_ok=True)
        raise
    if duplicate:
        dest.unlink(missing_ok=True)
    return batch, duplicate


def resolve_import_path(settings: Settings, path: Path) -> Path:
    root = settings.import_root.resolve()
    resolved = path.resolve()
    if not resolved.is_relative_to(root):
        raise ValidationFailedError(
            f"path is outside the import root {root}",
            errors=[
                FieldError("path", "outside_import_root", "move the file under the import root")
            ],
        )
    if not resolved.is_file():
        raise NotFoundError(f"file not found: {resolved.name}")
    return resolved


def _hash_file(path: Path) -> tuple[str, int, bytes]:
    digest = hashlib.sha256()
    size = 0
    head = b""
    with path.open("rb") as fh:
        while chunk := fh.read(COPY_CHUNK):
            if not head:
                head = chunk[:BINARY_SNIFF_BYTES]
            size += len(chunk)
            digest.update(chunk)
    return digest.hexdigest(), size, head


def create_cli_batch(
    session: Session,
    settings: Settings,
    actor: Actor,
    *,
    source_key: str,
    adapter_name: str | None,
    path: Path,
    options: BatchOptions,
) -> tuple[IngestionBatch, bool]:
    sid, adapter_cls = _resolve_source_and_adapter(session, None, source_key, adapter_name)
    validate_options(options, adapter_cls)
    resolved = resolve_import_path(settings, path)
    _check_extension(resolved.name, adapter_cls)
    sha, size, head = _hash_file(resolved)
    if size == 0:
        raise ValidationFailedError("the file is empty")
    if looks_binary(head):
        raise UnsupportedMediaTypeError("file looks binary (contains NUL bytes)")
    return _register_batch(
        session,
        actor,
        batch_id=uuid.uuid4(),
        source_id=sid,
        adapter_cls=adapter_cls,
        original_filename=resolved.name,
        stored_path=str(resolved),
        file_sha256=sha,
        size=size,
        options=options,
        enqueue=False,
    )


# --- loading -----------------------------------------------------------------------------------


@dataclass
class _LoadState:
    metadata: dict[str, Any]
    total: int
    rejected: int
    naive_timestamps: int = 0
    warnings: dict[str, dict[str, int]] = field(default_factory=dict)

    def warn(self, field_name: str, code: str) -> None:
        bucket = self.warnings.setdefault(field_name, {})
        bucket[code] = bucket.get(code, 0) + 1


class _AssetIndex:
    def __init__(self, versions: Iterable[DimAsset]) -> None:
        self.by_ip: dict[str, list[DimAsset]] = {}
        self.by_host: dict[str, list[DimAsset]] = {}
        for v in versions:
            if v.ip_address:
                self.by_ip.setdefault(str(v.ip_address).split("/")[0], []).append(v)
            if v.hostname:
                self.by_host.setdefault(v.hostname.lower(), []).append(v)

    @staticmethod
    def _at(candidates: list[DimAsset] | None, when: datetime) -> int | None:
        best: DimAsset | None = None
        for v in candidates or []:
            valid_now = v.valid_from <= when and (v.valid_to is None or when < v.valid_to)
            if valid_now and (best is None or v.valid_from > best.valid_from):
                best = v
        return best.asset_key if best else None

    def resolve(self, event: dict[str, Any]) -> tuple[int | None, int | None]:
        when = event["event_time"]
        src = self._at(self.by_ip.get(event["src_ip"]) if event.get("src_ip") else None, when)
        if src is None and event.get("host_name"):
            src = self._at(self.by_host.get(event["host_name"].lower()), when)
        dst = self._at(self.by_ip.get(event["dst_ip"]) if event.get("dst_ip") else None, when)
        return src, dst


def make_storable(value: Any) -> tuple[Any, bool]:
    """PostgreSQL text/jsonb cannot hold NUL or unpaired surrogates; escape them visibly."""
    escaped = False

    def fix(item: Any) -> Any:
        nonlocal escaped
        if isinstance(item, str):
            if item.isascii() and "\x00" not in item:
                return item  # fast path: ASCII always encodes and needs no escaping
            if "\x00" in item:
                escaped = True
                item = item.replace("\x00", "\\x00")
            try:
                item.encode("utf-8")
            except UnicodeEncodeError:
                escaped = True
                item = item.encode("utf-8", "backslashreplace").decode("utf-8")
            return item
        if isinstance(item, dict):
            return {fix(str(k)): fix(v) for k, v in item.items()}
        if isinstance(item, list):
            return [fix(v) for v in item]
        return item

    return fix(value), escaped


def _start(session: Session, batch_id: uuid.UUID) -> IngestionBatch | None:
    """Lock the batch and move it to ``processing``; None if there is nothing to do."""
    with session.begin():
        batch = repo.get_batch(session, batch_id, for_update=True)
        if batch is None:
            raise NotFoundError(f"batch {batch_id} not found")
        if batch.status in TERMINAL_OK:
            return None
        if batch.status not in ("pending", "processing", "failed"):
            raise ConflictError(f"batch is {batch.status}")
        batch.status = "processing"
        batch.started_at = batch.started_at or clock.now()
        batch.error_summary = None
        session.flush()
        session.expunge(batch)
        return batch


def _finish(
    session: Session,
    batch_id: uuid.UUID,
    status: str,
    *,
    error: dict[str, Any] | None,
    metadata: dict[str, Any],
    timezone_assumption: str | None,
    label_mapping_version: str | None,
) -> IngestionBatch:
    with session.begin():
        batch = repo.get_batch(session, batch_id, for_update=True)
        assert batch is not None
        batch.status = status
        batch.error_summary = error
        batch.finished_at = clock.now()
        batch.batch_metadata = metadata
        batch.timezone_assumption = timezone_assumption
        batch.label_mapping_version = label_mapping_version
        session.flush()
        session.expunge(batch)
        return batch


def _outcome(batch: IngestionBatch) -> BatchOutcome:
    return BatchOutcome(
        batch.batch_id,
        batch.status,
        batch.records_total,
        batch.records_loaded,
        batch.records_rejected,
        batch.records_duplicate,
        batch.error_summary,
    )


@dataclass
class _ChunkRows:
    """A chunk with its storable rows built (pure Python, no database access)."""

    chunk: list[Prepared]
    raw_rows: list[dict[str, Any]]
    # (position in chunk, event row without raw_record_id / asset keys)
    event_rows: list[tuple[int, dict[str, Any]]]
    # Adapter statistics as of the end of this chunk (taken on the reading thread).
    adapter_metadata: dict[str, Any]


def _build_rows(batch: IngestionBatch, chunk: list[Prepared], adapter: Adapter) -> _ChunkRows:
    raw_rows = []
    for p in chunk:
        payload, escaped_payload = make_storable(p.raw.payload)
        text, escaped_text = make_storable(p.raw.raw_text)
        raw_rows.append(
            {
                "batch_id": batch.batch_id,
                "record_number": p.raw.record_number,
                "raw_payload": repo.json_text(payload),
                "raw_text": text,
                "raw_truncated": p.raw.truncated,
                "raw_nul_escaped": escaped_payload or escaped_text,
                "record_sha256": p.raw.sha256,
            }
        )
    event_rows = []
    for i, p in enumerate(chunk):
        if p.event is None:
            continue
        row = dict(p.event)
        row["attributes"] = repo.json_text(make_storable(row["attributes"])[0])
        for key in ("process_command_line", "url", "file_path", "signature"):
            if isinstance(row.get(key), str):
                row[key], _ = make_storable(row[key])
        row.update(source_id=batch.source_id, batch_id=batch.batch_id)
        event_rows.append((i, row))
    metadata = {"encodings": dict(adapter.stats.encodings), **adapter.metadata}
    return _ChunkRows(chunk, raw_rows, event_rows, metadata)


CHUNK_LOCK_TIMEOUT_MS = 30_000


class _ChunkAborted(Exception):
    """A later chunk is rolled back because an earlier one failed (not the root cause)."""


class _CommitOrder:
    """Chunks are written concurrently but commit strictly in sequence.

    ``wait_turn(seq)`` returns once every earlier chunk has committed, or raises
    ``_ChunkAborted`` if an earlier chunk failed (or asked later chunks to stop).
    Waiting happens in Python, never while holding locks an earlier chunk needs: a later
    chunk may block on an earlier chunk's uncommitted rows (duplicate fingerprints), never
    the reverse, so there is no deadlock.
    """

    def __init__(self) -> None:
        self._next = 0
        self._stop_from: int | None = None
        self._cv = threading.Condition()

    def wait_turn(self, seq: int) -> None:
        with self._cv:
            while True:
                if self._stop_from is not None and seq >= self._stop_from:
                    raise _ChunkAborted()
                if self._next == seq:
                    return
                self._cv.wait()

    def finish(self, seq: int, *, committed: bool, stop_later: bool = False) -> None:
        with self._cv:
            stop: int | None = None
            if not committed:
                stop = seq
            elif stop_later:
                stop = seq + 1
            if stop is not None:
                self._stop_from = stop if self._stop_from is None else min(self._stop_from, stop)
            if committed:
                self._next = seq + 1
            self._cv.notify_all()


@dataclass
class _ChunkResult:
    loaded: int
    rejected: int
    duplicate: int
    warnings: list[tuple[str, str]]
    naive_timestamps: int
    unmapped_labels: list[str]


def _insert_chunk(
    session: Session, batch: IngestionBatch, rows: _ChunkRows, category_ids: dict[str, int]
) -> _ChunkResult:
    """The heavy part of a chunk (inside the caller's transaction); touches no shared state."""
    chunk = rows.chunk
    repo.use_generic_plans(session)
    valid = [p for p in chunk if p.event is not None]
    raw_ids = repo.insert_raw_records(session, rows.raw_rows)

    assets = _AssetIndex([])
    if valid:
        ips = {
            v for p in valid if p.event for v in (p.event.get("src_ip"), p.event.get("dst_ip")) if v
        }
        hosts = {p.event["host_name"] for p in valid if p.event and p.event.get("host_name")}
        assets = _AssetIndex(repo.find_asset_versions(session, sorted(ips), sorted(hosts)))

    event_rows = []
    for i, row in rows.event_rows:
        row["src_asset_key"], row["dst_asset_key"] = assets.resolve(row)
        row["raw_record_id"] = raw_ids[i]
        event_rows.append(row)
    inserted = repo.insert_events(session, event_rows)
    new_keys = {(fp, t): eid for eid, t, fp in inserted}

    truths = []
    unmapped: list[str] = []
    for p in valid:
        assert p.event is not None
        identity = (p.event["event_fingerprint"], p.event["event_time"])
        event_id = new_keys.pop(identity, None)  # pop: in-chunk duplicates get no second label
        if event_id is not None and p.ground_truth is not None:
            gt = p.ground_truth
            truths.append(
                {
                    "event_id": event_id,
                    "event_time": p.event["event_time"],
                    "label_raw": make_storable(gt.label_raw)[0],
                    "attack_category_id": category_ids.get(gt.category_code)
                    if gt.category_code
                    else None,
                    "is_attack": gt.is_attack,
                    "mapping_status": gt.mapping_status,
                    "label_mapping_version": gt.mapping_version,
                }
            )
            if gt.mapping_status != "mapped":
                unmapped.append(gt.label_raw)
    repo.insert_ground_truth(session, truths)

    rejections = [
        {
            "batch_id": batch.batch_id,
            "raw_record_id": raw_id,
            "record_number": p.raw.record_number,
            "error_code": p.rejection.code,
            "field_name": p.rejection.field,
            "error_detail": make_storable(p.rejection.detail[:1024])[0],
        }
        for p, raw_id in zip(chunk, raw_ids, strict=True)
        if p.rejection is not None
    ]
    repo.insert_rejections(session, rejections)
    return _ChunkResult(
        loaded=len(inserted),
        rejected=len(rejections),
        duplicate=len(valid) - len(inserted),
        warnings=[w for p in valid for w in p.warnings],
        naive_timestamps=sum(int(p.naive_timestamp) for p in valid),
        unmapped_labels=unmapped,
    )


def _apply_result(state: _LoadState, rows: _ChunkRows, result: _ChunkResult) -> None:
    """Fold one chunk into the batch state (called in commit order)."""
    state.metadata.update(rows.adapter_metadata)
    if result.unmapped_labels:
        labels = state.metadata.setdefault("unmapped_labels", {})
        for label in result.unmapped_labels:
            if len(labels) < 200 or label in labels:
                labels[label] = labels.get(label, 0) + 1
    for field_name, code in result.warnings:
        state.warn(field_name, code)
    state.naive_timestamps += result.naive_timestamps
    state.metadata["field_warnings"] = state.warnings
    state.metadata["naive_timestamps"] = state.naive_timestamps
    state.total += len(rows.chunk)
    state.rejected += result.rejected


def _write_chunk(
    factory: sessionmaker[Session],
    batch: IngestionBatch,
    rows: _ChunkRows,
    seq: int,
    order: _CommitOrder,
    category_ids: dict[str, int],
    state: _LoadState,
    settings: Settings,
    progress: Callable[[int, int | None, str], None] | None,
    check_cancel: Callable[[], None] | None,
) -> None:
    """Write one chunk on its own connection; commit only after all earlier chunks."""
    committed = False
    try:
        with factory() as session:
            with session.begin():
                try:
                    # Backstop: a chunk holding locks waits for its turn in Python, which
                    # PostgreSQL cannot see as part of a deadlock. Concurrent batches of one
                    # source could still form such a cycle; time out instead of hanging.
                    repo.set_lock_timeout(session, CHUNK_LOCK_TIMEOUT_MS)
                    result = _insert_chunk(session, batch, rows, category_ids)
                except OperationalError as exc:
                    if not isinstance(exc.orig, psycopg.errors.LockNotAvailable):
                        raise
                    raise BatchFatalError(
                        E.LOCK_TIMEOUT,
                        "waited too long for rows locked by another load; retry to resume",
                    ) from exc
                order.wait_turn(seq)
                # --- ordered phase: everything below runs in chunk order ---
                if check_cancel is not None:
                    try:
                        check_cancel()
                    except Exception as exc:
                        raise BatchFatalError(
                            E.CANCELLED, "cancelled on request; retry to resume"
                        ) from exc
                _apply_result(state, rows, result)
                repo.add_progress(
                    session,
                    batch.batch_id,
                    total=len(rows.chunk),
                    loaded=result.loaded,
                    rejected=result.rejected,
                    duplicate=result.duplicate,
                    last_record=rows.chunk[-1].raw.record_number,
                    metadata=state.metadata,
                    now=clock.now(),
                )
            committed = True
        too_many_rejected = (
            state.total >= REJECTION_CHECK_AFTER
            and state.rejected / state.total > settings.max_reject_ratio
        )
        order.finish(seq, committed=True, stop_later=too_many_rejected)
        if progress is not None:
            progress(state.total, None, "records")
        if too_many_rejected:
            raise BatchFatalError(
                E.ADAPTER_MISMATCH_SUSPECTED,
                f"{state.rejected} of {state.total} records rejected "
                f"(> {settings.max_reject_ratio:.0%}); check the adapter and variant",
            )
    except BaseException:
        if not committed:
            order.finish(seq, committed=False)
        raise


def process_batch(
    factory: sessionmaker[Session],
    settings: Settings,
    batch_id: uuid.UUID,
    *,
    progress: Callable[[int, int | None, str], None] | None = None,
    check_cancel: Callable[[], None] | None = None,
    on_complete: Callable[[Session, uuid.UUID], object] | None = None,
) -> BatchOutcome:
    """Load one batch. Idempotent: completed batches are a no-op; failed ones resume.

    ``on_complete`` runs after the final status is committed (data-quality checks).
    """
    with factory() as session:
        batch = _start(session, batch_id)
        if batch is None:
            return _outcome(repo_get(session, batch_id))

        with session.begin():
            source = repo.get_source(session, batch.source_id)
            assert source is not None
            category_ids = reference_repo.category_ids_by_code(session)
            source_key, source_tz = source.source_key, source.default_timezone

        options = BatchOptions.from_dict(batch.batch_metadata.get("options", {}))
        timezone = options.timezone or source_tz
        ctx = BatchContext(
            source_key=source_key,
            timezone=timezone,
            assume_event_date=options.assume_event_date,
            variant=options.variant,
            date_order=options.date_order,
            dataset_partition=options.dataset_partition,
        )
        state = _LoadState(
            metadata=dict(batch.batch_metadata),
            total=batch.records_total,
            rejected=batch.records_rejected,
            warnings={
                k: dict(v) for k, v in batch.batch_metadata.get("field_warnings", {}).items()
            },
            naive_timestamps=int(batch.batch_metadata.get("naive_timestamps", 0)),
        )
        adapter: Adapter | None = None
        mapping: LabelMapping | None = None
        status, error = "failed", None
        try:
            adapter_cls = _adapter_class(batch.adapter)
            if adapter_cls.version != batch.adapter_version:
                raise BatchFatalError(
                    "ADAPTER_VERSION_CHANGED",
                    f"batch was registered for {batch.adapter}@{batch.adapter_version} but "
                    f"{adapter_cls.version} is installed; upload again to re-process",
                )
            adapter = adapter_cls(ctx)
            if adapter_cls.label_mapping:
                mapping = load_mapping(adapter_cls.label_mapping)
            _load_file(
                factory,
                batch,
                adapter,
                mapping,
                category_ids,
                state,
                settings,
                progress,
                check_cancel,
            )
            status = "completed_with_errors" if state.rejected else "completed"
        except BatchFatalError as exc:
            session.rollback()
            committed = repo_get(session, batch_id).last_committed_record
            error = {"code": exc.code, "detail": exc.detail, "last_committed_record": committed}
            state.metadata = {
                **repo_get(session, batch_id).batch_metadata,
                **{k: v for k, v in state.metadata.items() if k == "header_map"},
            }

        state.metadata.update(_adapter_metadata(adapter, timezone, state))
        finished = _finish(
            session,
            batch_id,
            status,
            error=error,
            metadata=state.metadata,
            timezone_assumption=timezone if state.naive_timestamps else None,
            label_mapping_version=mapping.version_tag if mapping else None,
        )
        if on_complete is not None:
            on_complete(session, batch_id)
        return _outcome(finished)


def _load_file(
    factory: sessionmaker[Session],
    batch: IngestionBatch,
    adapter: Adapter,
    mapping: LabelMapping | None,
    category_ids: dict[str, int],
    state: _LoadState,
    settings: Settings,
    progress: Callable[[int, int | None, str], None] | None,
    check_cancel: Callable[[], None] | None,
) -> None:
    path = Path(batch.stored_path)
    if not path.is_file():
        raise BatchFatalError(E.FILE_NOT_FOUND, "the stored file no longer exists")
    if _hash_file(path)[0] != batch.file_sha256:
        raise BatchFatalError(E.FILE_CHANGED, "file content changed since registration")
    resume_after = batch.last_committed_record
    if resume_after:
        state.metadata["resumed_after_record"] = resume_after

    # Records are read and prepared on this thread; chunks are written by
    # ``settings.ingest_writers`` threads, each on its own connection, and commit strictly
    # in order (``_CommitOrder``), so ``last_committed_record`` and resume semantics are
    # those of a sequential load. psycopg releases the GIL while PostgreSQL works.
    order = _CommitOrder()
    writers = max(1, settings.ingest_writers)
    if isinstance(factory.kw.get("bind"), Connection):
        # Every session shares one connection (test harness); a connection must never be
        # used from two threads at once, so write one chunk at a time.
        writers = 1
    # Each in-flight chunk with the event identities it may insert (uncommitted until done).
    in_flight: deque[tuple[Future[None], set[tuple[str, datetime]]]] = deque()
    ensured_months: set[tuple[int, int]] = set()

    def drain(limit: int) -> None:
        while len(in_flight) > limit:
            in_flight[0][0].result()  # in submission order: the first failure wins
            in_flight.popleft()

    def dispatch(pool: ThreadPoolExecutor, chunk: list[Prepared], seq: int) -> None:
        rows = _build_rows(batch, chunk, adapter)
        drain(writers - 1)
        # An event already in an uncommitted earlier chunk is a duplicate here. Dropping it
        # up front means no chunk ever blocks on another chunk's uncommitted rows (a later
        # chunk inserting first would otherwise deadlock with the commit order).
        held = set().union(*(ids for _, ids in in_flight))
        identities: set[tuple[str, datetime]] = set()
        kept = []
        for i, row in rows.event_rows:
            key = (row["event_fingerprint"], row["event_time"])
            if key not in held:
                identities.add(key)
                kept.append((i, row))
        rows.event_rows = kept
        if kept:
            times = [row["event_time"] for _, row in kept]
            months = {(t.astimezone(UTC).year, t.astimezone(UTC).month) for t in times}
            if not months <= ensured_months:
                # Creating a partition locks the parent table; never do it while writes are
                # in flight (their row locks plus the commit order could form a cycle).
                drain(0)
                with factory() as session, session.begin():
                    repo.ensure_partitions(session, min(times), max(times))
                ensured_months.update(months)
        future = pool.submit(
            _write_chunk,
            factory,
            batch,
            rows,
            seq,
            order,
            category_ids,
            state,
            settings,
            progress,
            check_cancel,
        )
        in_flight.append((future, identities))

    with ThreadPoolExecutor(max_workers=writers, thread_name_prefix="ingest-writer") as pool:
        try:
            seq = 0
            with path.open("rb") as fh:
                chunk: list[Prepared] = []
                for raw in adapter.read(fh):
                    if raw.record_number <= resume_after:
                        continue
                    chunk.append(prepare_record(adapter, raw, mapping))
                    if len(chunk) >= settings.ingest_chunk_size:
                        dispatch(pool, chunk, seq)
                        seq += 1
                        chunk = []
                if chunk:
                    dispatch(pool, chunk, seq)
            drain(0)
        except BaseException as exc:
            # Let in-flight writes finish (each commits or rolls back on its own) and report
            # the earliest real failure rather than a follow-on abort.
            first: BaseException | None = None if isinstance(exc, _ChunkAborted) else exc
            while in_flight:
                error = in_flight.popleft()[0].exception()
                if first is None and error is not None and not isinstance(error, _ChunkAborted):
                    first = error
            if first is None or first is exc:
                raise
            raise first from None


def _adapter_metadata(
    adapter: Adapter | None, timezone: str | None, state: _LoadState
) -> dict[str, Any]:
    if adapter is None:
        return {}
    meta: dict[str, Any] = {"encodings": dict(adapter.stats.encodings), **adapter.metadata}
    meta["timezone_used"] = timezone if state.naive_timestamps else None
    return meta


def repo_get(session: Session, batch_id: uuid.UUID) -> IngestionBatch:
    with session.begin():
        batch = repo.get_batch(session, batch_id)
        if batch is None:
            raise NotFoundError(f"batch {batch_id} not found")
        session.expunge(batch)
        return batch


# --- retry and queries -------------------------------------------------------------------------


def retry_batch(session: Session, actor: Actor, batch_id: uuid.UUID) -> IngestionBatch:
    with session.begin():
        batch = repo.get_batch(session, batch_id, for_update=True)
        if batch is None:
            raise NotFoundError(f"batch {batch_id} not found")
        if batch.status != "failed":
            raise ConflictError(f"only failed batches can be retried (batch is {batch.status})")
        history = list(batch.batch_metadata.get("failures", []))
        history.append(batch.error_summary or {})
        batch.batch_metadata = {**batch.batch_metadata, "failures": history}
        batch.status = "pending"
        job = jobs_service.enqueue_in_transaction(
            session, actor, JOB_TYPE, {"batch_id": str(batch_id)}
        )
        batch.job_id = job.job_id
        audit.record(
            session, actor, "ingestion.retry", target_type="ingestion_batch", target_id=batch_id
        )
        session.flush()
        session.expunge(batch)
        return batch


@dataclass(frozen=True)
class Page[T]:
    items: list[T]
    next_cursor: str | None
    limit: int


def get_batch(session: Session, batch_id: uuid.UUID) -> IngestionBatch:
    return repo_get(session, batch_id)


def list_batches(
    session: Session,
    *,
    source_id: int | None = None,
    statuses: list[str] | None = None,
    created_after: datetime | None = None,
    created_before: datetime | None = None,
    cursor: str | None = None,
    limit: int = DEFAULT_LIMIT,
) -> Page[IngestionBatch]:
    key = decode_cursor(cursor, frozenset({"created_at", "batch_id"}))
    after = None
    if key is not None:
        try:
            after = (datetime.fromisoformat(key["created_at"]), uuid.UUID(key["batch_id"]))
        except (TypeError, ValueError) as exc:
            raise ValidationFailedError(
                "invalid cursor", errors=[FieldError("cursor", "invalid_cursor", "malformed")]
            ) from exc
    with session.begin():
        rows = repo.list_batches(
            session,
            source_id=source_id,
            statuses=statuses,
            created_after=created_after,
            created_before=created_before,
            after=after,
            limit=limit + 1,
        )
    items = rows[:limit]
    next_cursor = None
    if len(rows) > limit:
        last = items[-1]
        next_cursor = encode_cursor(
            {"created_at": last.created_at.isoformat(), "batch_id": str(last.batch_id)}
        )
    return Page(items, next_cursor, limit)


def list_rejections(
    session: Session, batch_id: uuid.UUID, cursor: str | None, limit: int = DEFAULT_LIMIT
) -> tuple[Page[RejectedRecord], int]:
    key = decode_cursor(cursor, frozenset({"record_number", "id"}))
    after = (int(key["record_number"]), int(key["id"])) if key else None
    with session.begin():
        if repo.get_batch(session, batch_id) is None:
            raise NotFoundError(f"batch {batch_id} not found")
        rows = repo.list_rejections(session, batch_id, after, limit + 1)
        total = repo.count_rejections(session, batch_id)
    items = rows[:limit]
    next_cursor = None
    if len(rows) > limit:
        last = items[-1]
        next_cursor = encode_cursor(
            {"record_number": last.record_number, "id": last.rejected_record_id}
        )
    return Page(items, next_cursor, limit), total
