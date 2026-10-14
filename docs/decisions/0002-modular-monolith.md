# 0002. Modular monolith

- Status: accepted
- Date: 2026-10-14

## Context

One developer, one laptop, an MVP with ingestion, ML, TI, correlation, and a dashboard. Distributed systems add deployment, consistency, and debugging cost without a demonstrated need.

## Decision

We will build one backend codebase deployed as two processes (API and worker) sharing PostgreSQL, with module boundaries enforced by an import test (`backend/tests/unit/test_architecture.py`).

## Alternatives considered

Microservices (premature); a single process without a worker (long jobs would block requests).

## Consequences

- Simple local setup and transactions across modules.
- Boundaries must be kept by discipline and tests; the scaling path is in [ARCHITECTURE.md §10](../../ARCHITECTURE.md#10-scalability-path-future--only-with-a-demonstrated-requirement).
