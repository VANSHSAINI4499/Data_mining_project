# 0003. PostgreSQL as warehouse and application store

- Status: accepted
- Date: 2026-10-14

## Context

We need transactions, concurrency, `inet`/`jsonb` types, partitioning, and mature migrations for both warehouse data and application state.

## Decision

We will use PostgreSQL for everything, with monthly range partitioning of `fact_security_event` (from Phase 2).

## Alternatives considered

DuckDB (embedded, single writer), ClickHouse (extra infrastructure), SQLite (no `inet`, weak concurrency).

## Consequences

- One store to operate and back up.
- Analytical scans are slower than in a columnar engine; revisit only with measurements.
