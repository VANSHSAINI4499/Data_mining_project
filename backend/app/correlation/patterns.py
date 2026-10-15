"""Sequential pattern mining for candidate correlation rules (ATTACK_CORRELATION.md §10).

Pure functions, no database. Per-entity token sequences are split at inactivity gaps; a
PrefixSpan-style search finds ordered token patterns (gaps between tokens allowed) present in
at least ``min_support`` sequences. Where dataset labels exist, each pattern is contrasted
between sequences that contain labelled-malicious events and those that do not. The output is
a list of *candidates* for human review — they are never enabled automatically.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

WINDOWS = [("5m", 5), ("15m", 15), ("1h", 60), ("2h", 120), ("6h", 360), ("24h", 1440)]


@dataclass(frozen=True)
class Token:
    entity: str
    time: datetime
    token: str
    malicious: bool = False


@dataclass
class Sequence:
    entity: str
    tokens: list[str]
    start: datetime
    end: datetime
    malicious: bool
    counts: list[int] = field(default_factory=list)  # repeats collapsed into each token


def build_sequences(
    items: Iterable[Token], max_gap: timedelta, max_length: int = 200
) -> list[Sequence]:
    """Group by entity, sort by time, split when the gap exceeds ``max_gap``, and collapse
    consecutive repeats of the same token (their count is kept in ``counts``)."""
    by_entity: dict[str, list[Token]] = {}
    for item in items:
        by_entity.setdefault(item.entity, []).append(item)
    out: list[Sequence] = []
    for entity, tokens in sorted(by_entity.items()):
        tokens.sort(key=lambda t: (t.time, t.token))
        current: Sequence | None = None
        last_time: datetime | None = None
        for t in tokens:
            if current is None or last_time is None or t.time - last_time > max_gap:
                current = Sequence(entity, [], t.time, t.time, False, [])
                out.append(current)
            if current.tokens and current.tokens[-1] == t.token:
                current.counts[-1] += 1
            elif len(current.tokens) < max_length:
                current.tokens.append(t.token)
                current.counts.append(1)
            current.end = t.time
            current.malicious = current.malicious or t.malicious
            last_time = t.time
    return out


def prefixspan(
    sequences: list[list[str]], min_support: int, max_length: int
) -> dict[tuple[str, ...], set[int]]:
    """Frequent ordered patterns (length ≥ 1) → indices of supporting sequences."""
    results: dict[tuple[str, ...], set[int]] = {}

    def grow(prefix: tuple[str, ...], projected: list[tuple[int, int]]) -> None:
        if len(prefix) >= max_length:
            return
        seen: dict[str, dict[int, int]] = {}
        for seq_idx, start in projected:
            seq = sequences[seq_idx]
            for pos in range(start, len(seq)):
                first = seen.setdefault(seq[pos], {})
                if seq_idx not in first:
                    first[seq_idx] = pos  # first occurrence after the prefix
        for token in sorted(seen):
            occurrences = seen[token]
            if len(occurrences) < min_support:
                continue
            pattern = (*prefix, token)
            results[pattern] = set(occurrences)
            grow(pattern, [(i, p + 1) for i, p in occurrences.items()])

    grow((), [(i, 0) for i in range(len(sequences))])
    return results


def _positions(tokens: list[str], pattern: tuple[str, ...]) -> list[int] | None:
    """Greedy left-most embedding of ``pattern`` in ``tokens``."""
    found, start = [], 0
    for token in pattern:
        try:
            pos = tokens.index(token, start)
        except ValueError:
            return None
        found.append(pos)
        start = pos + 1
    return found


def _step(token: str, index: int, previous: str | None, min_count: int) -> dict[str, Any]:
    kind, _, value = token.partition(":")
    step: dict[str, Any] = {"id": f"s{index + 1}", "min_count": max(1, min_count)}
    if kind == "auth":
        step |= {"evidence": "event", "where": {"event_type": "auth", "auth_result": value}}
    elif kind == "ids":
        step |= {"evidence": "event", "where": {"event_type": "ids_alert"}}
        if value.isdigit():
            step["where"]["signature_id"] = int(value)
    elif kind == "class":
        step |= {
            "evidence": "classification_result",
            "where": {"predicted_category": value, "min_predicted_score": 0.6},
        }
    elif kind == "anomaly":
        step |= {"evidence": "anomaly_result", "where": {}}
    else:
        step |= {"evidence": "event", "where": {"event_type": value or kind}}
    if previous is not None:
        step["after"] = previous
    return step


def _window(minutes: float) -> str:
    for name, limit in WINDOWS:
        if minutes <= limit:
            return name
    return "24h"


def candidates(
    sequences: list[Sequence],
    *,
    entity_type: str,
    min_support: int,
    max_length: int,
    min_malicious_ratio: float,
    limit: int = 20,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    token_lists = [s.tokens for s in sequences]
    patterns = prefixspan(token_lists, min_support, max_length)
    labelled = sum(1 for s in sequences if s.malicious)
    stats = {
        "sequences": len(sequences),
        "sequences_with_labelled_malicious_events": labelled,
        "frequent_patterns": len(patterns),
    }
    out: list[dict[str, Any]] = []
    for pattern, support in patterns.items():
        if len(pattern) < 2:
            continue
        malicious = sum(1 for i in support if sequences[i].malicious)
        ratio = malicious / len(support)
        if labelled and ratio < min_malicious_ratio:
            continue
        spans = [(sequences[i].end - sequences[i].start).total_seconds() / 60 for i in support]
        # Smallest observed run length per step across supporting sequences.
        repeats = [10**9] * len(pattern)
        for i in support:
            positions = _positions(sequences[i].tokens, pattern)
            if positions is not None:
                for k, pos in enumerate(positions):
                    repeats[k] = min(repeats[k], sequences[i].counts[pos])
        steps: list[dict[str, Any]] = []
        for index, token in enumerate(pattern):
            count = repeats[index] if repeats[index] < 10**9 else 1
            steps.append(_step(token, index, steps[-1]["id"] if steps else None, count))
        out.append(
            {
                "pattern": list(pattern),
                "support": len(support),
                "malicious_support": malicious,
                "benign_support": len(support) - malicious,
                "malicious_ratio": round(ratio, 4),
                "label_basis": "dataset labels" if labelled else "no labelled events in scope",
                "max_span_minutes": round(max(spans), 1),
                "example_entities": sorted({sequences[i].entity for i in support})[:5],
                "draft_rule": {
                    "entity_type": entity_type,
                    "window": _window(max(spans)),
                    "base_severity": "medium",
                    "enabled": False,
                    "steps": steps,
                },
                "status": "candidate — requires human review; never enabled automatically",
            }
        )

    def order(c: dict[str, Any]) -> tuple[float, int, int, list[str]]:
        return (-float(c["malicious_ratio"]), -len(c["pattern"]), -int(c["support"]), c["pattern"])

    out.sort(key=order)
    return out[:limit], stats
