# 0007. Leakage-aware ML evaluation

- Status: accepted
- Date: 2026-10-14

## Context

Public IDS datasets contain duplicates and shortcut features that inflate naive metrics.

## Decision

We will use group-aware stratified splits, fit preprocessing on training data only, run automated leakage checks, and report per-class precision/recall, macro- and weighted-F1, and confusion matrices — never accuracy alone.

## Alternatives considered

Random row splits reported with accuracy (common, misleading).

## Consequences

- Lower but more honest metrics.
- More implementation and test effort in Phase 3.
