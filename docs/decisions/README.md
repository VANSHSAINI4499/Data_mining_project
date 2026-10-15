# Architecture Decision Records (ADRs)

A lightweight record of important technical decisions, following Michael Nygard's format ("Documenting Architecture Decisions", <https://cognitect.com/blog/2011/11/15/documenting-architecture-decisions>, verified): **Title, Status, Context, Decision, Consequences**.

## When an ADR is required

- Adding, replacing, or removing a runtime dependency or infrastructure component ([TECH_STACK.md §9](../../TECH_STACK.md#9-conditions-for-introducing-new-technology)).
- Changing architecture boundaries, the job execution model, authentication model, or deployment topology.
- Changing data-model semantics (e.g., fingerprint rules, ground-truth handling, partitioning), ML evaluation methodology, or risk-scoring formula.
- Accepting a known security or data-quality trade-off.
- Resolving any item in [Open decisions](#open-decisions).

Not required for: bug fixes, refactors inside a module, new tests, dev-only tooling (one-line justification in the change instead).

## Process

1. Copy the template to `docs/decisions/NNNN-short-title.md` (next free four-digit number).
2. Status `proposed`; open it in the same change as (or before) the implementation.
3. Discuss/review; set status to `accepted` or `rejected` with the date.
4. Update affected specs in the same change and link the ADR from them.
5. Never edit the decision of an accepted ADR; supersede it with a new ADR (`superseded by NNNN`) and mark the old one.
6. Keep it short — one or two pages.

## Template

```markdown
# NNNN. <Short noun phrase>

- Status: proposed | accepted | rejected | deprecated | superseded by NNNN
- Date: YYYY-MM-DD
- Related: <spec links, issues>

## Context
Forces at play: requirements, constraints, measurements, risks.

## Decision
"We will …" — active voice, specific.

## Alternatives considered
Option — why not.

## Consequences
Positive, negative, and neutral results; follow-up work; how to reverse.
```

## Index

| ADR | Title | Status |
|---|---|---|
| [0001](0001-record-architecture-decisions.md) | Record architecture decisions | accepted |
| [0002](0002-modular-monolith.md) | Modular monolith | accepted |
| [0003](0003-postgresql-warehouse.md) | PostgreSQL as warehouse and application store | accepted |
| [0004](0004-postgresql-job-queue.md) | PostgreSQL-backed job queue | accepted |
| [0005](0005-session-authentication.md) | Server-side sessions with CSRF protection and three roles | accepted |
| [0006](0006-separate-facts-predictions-conclusions.md) | Separate facts, predictions, hypotheses, and conclusions | accepted |
| [0007](0007-leakage-aware-evaluation.md) | Leakage-aware ML evaluation | accepted |
| [0008](0008-uv-and-npm.md) | uv for Python, npm for the frontend | accepted |
| [0009](0009-phase-1-version-baseline.md) | Phase 1 dependency version baseline | accepted |
| [0010](0010-in-house-sequential-pattern-mining.md) | In-house PrefixSpan-style sequential pattern mining | accepted |

## Baseline decisions (captured as ADR-0001…0008 in Phase 1)

| Proposed ADR | Decision | Where documented |
|---|---|---|
| 0001 | Record architecture decisions with ADRs (this process). | This file |
| 0002 | Modular monolith (API + worker processes, one codebase), no microservices. | [ARCHITECTURE.md](../../ARCHITECTURE.md) |
| 0003 | PostgreSQL as warehouse and application store; monthly partitioning of `fact_security_event`. | [DATABASE_DESIGN.md](../../DATABASE_DESIGN.md) |
| 0004 | PostgreSQL-backed job queue (`SKIP LOCKED`) instead of Celery/Redis for the MVP. | [ARCHITECTURE.md §7](../../ARCHITECTURE.md#7-background-jobs) |
| 0005 | Server-side opaque sessions in HttpOnly cookies + CSRF header; roles viewer/analyst/admin. | [SECURITY_REQUIREMENTS.md](../../SECURITY_REQUIREMENTS.md) |
| 0006 | Facts, predictions, hypotheses, and analyst conclusions stored separately; ground truth immutable. | [DATA_DICTIONARY.md](../../DATA_DICTIONARY.md) |
| 0007 | Leakage-aware group splitting and per-class metrics as the ML evaluation standard. | [ML_CLASSIFICATION.md](../../ML_CLASSIFICATION.md) |
| 0008 | `uv` for Python dependency management; npm for the frontend. | [TECH_STACK.md](../../TECH_STACK.md) |

## Open decisions

Unresolved items. Each needs an ADR before it is implemented; until then the documented default applies.

| # | Question | Current default | Decide by |
|---|---|---|---|
| OD-1 | Model artifact format: joblib (pickle-based) vs `skops` (non-pickle). | joblib with hash + path checks ([SECURITY_REQUIREMENTS.md §9](../../SECURITY_REQUIREMENTS.md#9-ml-artifact-safety)). | Phase 3 |
| OD-2 | Production frontend serving, reverse proxy, and TLS termination. | Not provided; local Vite dev server only. | Phase 7 |
| OD-3 | Project licence. | Unlicensed (all rights reserved) until chosen. | Before any public release |
| OD-4 | Timezone of naive timestamps in each public dataset variant (e.g., CIC-IDS2017). | Must be set explicitly by the user per source; adapter refuses otherwise. | Phase 2, per dataset, with cited evidence |
| OD-5 | Partition `raw_record`, `classification_result`, `indicator_match`? | Not partitioned. | Phase 7 measurements |
| OD-6 | Move from PostgreSQL job queue to Celery + Redis (scheduling, priorities). | Stay with PostgreSQL queue. | Phase 8 |
| OD-7 | Browser-level E2E tests (Playwright). | API-level E2E only. | Phase 7 |
| OD-8 | Sequential pattern-mining algorithm and implementation (in-house vs library). | In-house PrefixSpan-style preferred. | Phase 8 |
| OD-9 | Use analyst feedback labels in retraining by default. | Off (`include_feedback_labels = false`). | After Phase 5 feedback volume is known |
| OD-10 | Adopt Python 3.13 runtime. | Python 3.12. | Any phase, after full test pass on 3.13 |
| OD-11 | CIDR and parent-domain indicator matching. | Exact matching only. | Phase 8 |
| OD-12 | Exact pinned dependency versions. | **Resolved** by [ADR-0009](0009-phase-1-version-baseline.md). | Done (Phase 1) |
