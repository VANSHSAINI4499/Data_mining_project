"""Adapter contract (DATA_INGESTION.md §4) and the shared adapter registry."""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from collections.abc import Iterator, Sequence
from typing import IO, Any, ClassVar

from app.ingestion.errors import Rejection
from app.ingestion.readers import ReadStats
from app.ingestion.records import BatchContext, MappedRecord, RawRecord

_NON_WORD = re.compile(r"[^0-9a-z]+")
TRUE_VALUES = frozenset({"1", "true", "yes", "y", "t"})
FALSE_VALUES = frozenset({"0", "false", "no", "n", "f"})


class Adapter(ABC):
    """One input format. Subclasses declare metadata as class variables.

    Bump ``version``'s **major** part whenever mapping or fingerprint logic changes in a way
    that changes deduplication (DATA_INGESTION.md §6).
    """

    name: ClassVar[str]
    version: ClassVar[str]
    description: ClassVar[str]
    extensions: ClassVar[frozenset[str]]
    event_types: ClassVar[tuple[str, ...]]
    variants: ClassVar[tuple[str, ...]] = ()
    encodings: ClassVar[tuple[str, ...]] = ("utf-8",)
    label_mapping: ClassVar[str | None] = None
    # Canonical fields expected to be populated, with the null-rate above which data quality
    # warns (DATA_INGESTION.md §10).
    expected_fields: ClassVar[dict[str, float]] = {}

    def __init__(self, ctx: BatchContext) -> None:
        self.ctx = ctx
        self.stats = ReadStats()
        self.metadata: dict[str, Any] = {}

    @property
    def tag(self) -> str:
        return f"{self.name}@{self.version}"

    @abstractmethod
    def read(self, stream: IO[bytes]) -> Iterator[RawRecord]:
        """Parse the file into raw records (structural problems are attached, not raised)."""

    @abstractmethod
    def map(self, raw: RawRecord) -> MappedRecord | Rejection:
        """Map one structurally valid record to canonical field names."""

    def fingerprint_values(self, values: dict[str, Any], mapped: MappedRecord) -> Sequence[Any]:
        """Identity values for dedup. Default: every canonical value plus label and extras."""
        identity = [values.get(k) for k in sorted(mapped.fields)]
        return [*identity, mapped.label_raw, *mapped.fingerprint_extra]


def attribute_key(name: str) -> str:
    return _NON_WORD.sub("_", name.lower()).strip("_") or "field"


def to_attributes(items: dict[str, Any]) -> dict[str, Any]:
    """Source-specific extras with snake_case keys; collisions get numeric suffixes."""
    result: dict[str, Any] = {}
    for key, value in items.items():
        base = attribute_key(str(key))
        candidate, n = base, 1
        while candidate in result:
            n += 1
            candidate = f"{base}_{n}"
        result[candidate] = value
    return result


def parse_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if value is None:
        return None
    text = str(value).strip().lower()
    if text in TRUE_VALUES:
        return True
    if text in FALSE_VALUES:
        return False
    return None


ADAPTERS: dict[str, type[Adapter]] = {}


def register(cls: type[Adapter]) -> type[Adapter]:
    if cls.name in ADAPTERS:
        raise ValueError(f"duplicate adapter {cls.name}")
    ADAPTERS[cls.name] = cls
    return cls
