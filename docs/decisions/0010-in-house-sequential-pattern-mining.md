# 0010. In-house PrefixSpan-style sequential pattern mining

- Status: accepted
- Date: 2026-10-15
- Related: [ATTACK_CORRELATION.md §10](../../ATTACK_CORRELATION.md#10-future-temporal-pattern-mining-phase-8), [ACCEPTANCE_CRITERIA.md AC-8.3](../../ACCEPTANCE_CRITERIA.md#phase-8--temporal-pattern-mining-incremental-ingestion-concept-drift)

## Context

Phase 8 mines ordered token patterns (e.g. `auth:failure → auth:success`) from per-entity event sequences to propose candidate correlation rules. The specification asks for the algorithm choice to be recorded and prefers an in-house implementation over a new dependency. Sequences are short (repeats collapsed, at most 200 tokens, split at inactivity gaps) and patterns are limited to 2–5 tokens.

## Decision

We will use a small in-house PrefixSpan-style miner (`app/correlation/patterns.py`): projected databases over single-token elements, support counted once per sequence, gaps between pattern tokens allowed, inactivity-gap segmentation done before mining. Each pattern is contrasted between sequences with and without labelled-malicious events. Output is a list of **disabled** draft rules in the existing rule DSL; nothing is enabled or inserted automatically.

## Alternatives considered

- Third-party sequential-pattern libraries — a new dependency for a ~100-line algorithm, with little control over memory limits and output format.
- SPADE / episode mining with explicit time constraints — more expressive, but unnecessary while sequences are already segmented by inactivity gaps.

## Consequences

- No new dependency; the algorithm is fully unit-tested (planted-sequence recovery).
- Exponential worst case is bounded by `max_length ≤ 5`, collapsed repeats, and a 500,000-token cap per run (reported when reached).
- Single-token elements only (no itemsets of simultaneous events); timestamps beyond ordering are used only for segmentation and the suggested rule window.
