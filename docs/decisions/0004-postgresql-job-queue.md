# 0004. PostgreSQL-backed job queue

- Status: accepted
- Date: 2026-10-14

## Context

Ingestion, training, scoring, matching, and correlation must run outside request handlers. Celery + Redis would add two components.

## Decision

We will use a `job` table claimed with `FOR UPDATE SKIP LOCKED`, heartbeats, back-off retries for transient errors, a stale-job reaper, and cooperative cancellation, behind an `enqueue()` service function.

## Alternatives considered

Celery + Redis, RQ, Dramatiq (all need a broker).

## Consequences

- No extra infrastructure; jobs are visible and auditable in SQL.
- No built-in scheduling or priorities; revisit in Phase 8 (OD-6).
- Verified in Phase 1 by `test_concurrent_workers_never_claim_the_same_job`.
