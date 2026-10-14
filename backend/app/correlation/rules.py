"""Correlation rule DSL and pure sequence matching (ATTACK_CORRELATION.md §3-§5).

Rules are data, validated against an allow-list of fields and operators. Nothing in a rule is
evaluated as code, SQL, or a regular expression.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

WINDOWS = {
    "5m": timedelta(minutes=5),
    "15m": timedelta(minutes=15),
    "1h": timedelta(hours=1),
    "2h": timedelta(hours=2),
    "6h": timedelta(hours=6),
    "24h": timedelta(hours=24),
}
EvidenceType = Literal["event", "classification_result", "anomaly_result", "indicator_match"]
ENTITY_TYPES = ("account", "src_ip", "dst_ip", "host")

# Allow-listed `where` keys per evidence type, with the expected value kinds.
ALLOWED_WHERE: dict[str, dict[str, str]] = {
    "event": {
        "event_type": "str_or_list",
        "auth_result": "str_or_list",
        "dst_port": "int_or_list",
        "protocol": "str_or_list",
        "signature_id": "int_or_list",
        "app_protocol": "str_or_list",
    },
    "classification_result": {
        "predicted_category": "str_or_list",
        "exclude_benign": "bool",
        "min_predicted_score": "unit_float",
    },
    "anomaly_result": {"min_score_percentile": "percent"},
    "indicator_match": {
        "min_confidence": "percent",
        "indicator_state": "str_or_list",
        "indicator_type": "str_or_list",
    },
}


def _check_value(kind: str, value: Any) -> bool:
    def is_str(v: Any) -> bool:
        return isinstance(v, str) and 0 < len(v) <= 64

    def is_int(v: Any) -> bool:
        return isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= 2**31

    if kind == "str_or_list":
        return is_str(value) or (
            isinstance(value, list) and 0 < len(value) <= 50 and all(is_str(v) for v in value)
        )
    if kind == "int_or_list":
        return is_int(value) or (
            isinstance(value, list) and 0 < len(value) <= 50 and all(is_int(v) for v in value)
        )
    if kind == "bool":
        return isinstance(value, bool)
    if kind == "unit_float":
        return isinstance(value, int | float) and not isinstance(value, bool) and 0 <= value <= 1
    if kind == "percent":
        return isinstance(value, int | float) and not isinstance(value, bool) and 0 <= value <= 100
    return False


class RuleStep(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^[a-z][a-z0-9_]{0,31}$")
    evidence: EvidenceType
    where: dict[str, Any] = Field(default_factory=dict)
    min_count: int = Field(default=1, ge=1, le=100_000)
    after: str | None = None
    # Require min_count items sharing one value of this event field (e.g. one signature).
    same: Literal["signature_id", "dst_port", "dst_ip"] | None = None

    @model_validator(mode="after")
    def _where(self) -> RuleStep:
        if self.same is not None and self.evidence != "event":
            raise ValueError("'same' is only supported for event evidence")
        allowed = ALLOWED_WHERE[self.evidence]
        for key, value in self.where.items():
            if key not in allowed:
                raise ValueError(
                    f"'{key}' is not an allowed filter for {self.evidence} evidence "
                    f"(allowed: {sorted(allowed)})"
                )
            if not _check_value(allowed[key], value):
                raise ValueError(f"invalid value for {self.evidence}.{key}")
        return self


class RuleDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    key: str = Field(pattern=r"^[a-z][a-z0-9_]{2,63}$")
    version: int = Field(default=1, ge=1)
    name: str = Field(min_length=3, max_length=200)
    description: str = Field(min_length=3, max_length=2000)
    entity_type: Literal["account", "src_ip", "dst_ip", "host"]
    window: Literal["5m", "15m", "1h", "2h", "6h", "24h"]
    base_severity: Literal["low", "medium", "high", "critical"]
    enabled: bool = True
    steps: list[RuleStep] = Field(min_length=1, max_length=5)

    @field_validator("steps")
    @classmethod
    def _order(cls, steps: list[RuleStep]) -> list[RuleStep]:
        seen: set[str] = set()
        for step in steps:
            if step.id in seen:
                raise ValueError(f"duplicate step id {step.id!r}")
            if step.after is not None and step.after not in seen:
                raise ValueError(
                    f"step {step.id!r} refers to {step.after!r}, which is not an earlier step"
                )
            seen.add(step.id)
        return steps

    @property
    def window_delta(self) -> timedelta:
        return WINDOWS[self.window]

    def definition(self) -> dict[str, Any]:
        return self.model_dump(
            mode="json",
            exclude={"key", "version", "name", "description", "base_severity", "enabled"},
        )


# --- matching ------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Evidence:
    step_id: str
    evidence_type: str
    ref: int
    entity: str
    time: datetime
    data: dict[str, Any] = field(default_factory=dict, hash=False, compare=False)


@dataclass
class Match:
    entity: str
    start: datetime
    end: datetime
    evidence: list[Evidence]


def find_matches(rule: RuleDefinition, evidence: list[Evidence]) -> list[Match]:
    """Per entity, slide a window anchored at each first-step item; a match needs every step's
    ``min_count`` inside the window, and ``after`` steps strictly after the referenced step
    reached its ``min_count``. Matches for one entity do not overlap."""
    by_entity: dict[str, dict[str, list[Evidence]]] = {}
    for item in evidence:
        by_entity.setdefault(item.entity, {}).setdefault(item.step_id, []).append(item)
    first = rule.steps[0].id
    matches: list[Match] = []
    for entity, steps in sorted(by_entity.items()):
        for items in steps.values():
            items.sort(key=lambda e: (e.time, e.ref))
        resume_after: datetime | None = None
        for anchor in steps.get(first, []):
            if resume_after is not None and anchor.time <= resume_after:
                continue
            window_end = anchor.time + rule.window_delta
            reached: dict[str, datetime] = {}
            chosen: list[Evidence] = []
            ok = True
            for step in rule.steps:
                lower = anchor.time
                strict = False
                if step.after is not None:
                    lower, strict = reached[step.after], True
                inside = [
                    e
                    for e in steps.get(step.id, [])
                    if (e.time > lower if strict else e.time >= lower) and e.time <= window_end
                ]
                if step.same is not None:
                    inside = _first_full_group(inside, step.same, step.min_count)
                if len(inside) < step.min_count:
                    ok = False
                    break
                reached[step.id] = inside[step.min_count - 1].time
                chosen.extend(inside)
            if ok:
                end = max(e.time for e in chosen)
                matches.append(Match(entity, anchor.time, end, chosen))
                resume_after = end
    return matches


def _first_full_group(items: list[Evidence], key: str, min_count: int) -> list[Evidence]:
    """Items of the value group that reaches ``min_count`` first (empty if none does)."""
    groups: dict[Any, list[Evidence]] = {}
    for item in items:
        group = groups.setdefault(item.data.get(key), [])
        group.append(item)
        if len(group) == min_count and item.data.get(key) is not None:
            return [e for e in items if e.data.get(key) == item.data.get(key)]
    return []


def dedup_key(rule_key: str, entity_type: str, entity: str) -> str:
    import hashlib

    return f"{rule_key}:{entity_type}:{hashlib.sha256(entity.encode()).hexdigest()[:16]}"
