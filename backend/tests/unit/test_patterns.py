"""Sequential pattern mining (ATTACK_CORRELATION.md §10, AC-8.3)."""

from __future__ import annotations

import random
from datetime import UTC, datetime, timedelta

from app.correlation.patterns import Token, build_sequences, candidates, prefixspan
from app.correlation.rules import RuleDefinition

T0 = datetime(2026, 1, 1, tzinfo=UTC)


def test_prefixspan_counts_each_sequence_once() -> None:
    found = prefixspan([["a", "b", "c"], ["a", "c"], ["b", "a", "c", "c"]], 2, 3)
    assert found[("a", "c")] == {0, 1, 2}
    assert found[("b", "c")] == {0, 2}
    assert ("c", "a") not in found
    assert ("a", "b", "c") not in found  # only one sequence has a, b, c in order


def test_sequences_split_on_gaps_and_collapse_repeats() -> None:
    items = [
        Token("alice", T0 + timedelta(minutes=m), tok)
        for m, tok in [
            (0, "auth:failure"),
            (1, "auth:failure"),
            (2, "auth:success"),
            (200, "auth:failure"),
        ]
    ]
    seqs = build_sequences(items, timedelta(minutes=30))
    assert [s.tokens for s in seqs] == [["auth:failure", "auth:success"], ["auth:failure"]]
    assert seqs[0].counts == [2, 1]


def test_planted_sequence_is_recovered_as_a_valid_disabled_rule() -> None:
    rng = random.Random(7)
    items: list[Token] = []
    for n in range(60):
        entity = f"user{n}"
        start = T0 + timedelta(hours=n)
        if n < 8:  # planted: 6+ failures then a success, labelled malicious
            for k in range(6 + n % 3):
                items.append(Token(entity, start + timedelta(seconds=10 * k), "auth:failure", True))
            items.append(Token(entity, start + timedelta(minutes=3), "auth:success", True))
        else:  # benign noise: successes, occasional single failure afterwards
            items.append(Token(entity, start, "auth:success"))
            if rng.random() < 0.3:
                items.append(Token(entity, start + timedelta(minutes=5), "auth:failure"))
    seqs = build_sequences(items, timedelta(minutes=30))
    found, stats = candidates(
        seqs, entity_type="account", min_support=5, max_length=3, min_malicious_ratio=0.8
    )
    assert stats["sequences_with_labelled_malicious_events"] == 8
    top = found[0]
    assert top["pattern"] == ["auth:failure", "auth:success"]
    assert (top["support"], top["malicious_support"], top["malicious_ratio"]) == (8, 8, 1.0)
    draft = top["draft_rule"]
    assert draft["enabled"] is False and draft["steps"][0]["min_count"] == 6
    rule = RuleDefinition.model_validate(
        {"key": "mined_candidate", "name": "Mined candidate", "description": "from mining", **draft}
    )
    assert rule.enabled is False and rule.steps[1].after == "s1"
    # The benign reverse order is not proposed.
    assert all(c["pattern"] != ["auth:success", "auth:failure"] for c in found)
