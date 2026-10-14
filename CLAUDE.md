# CLAUDE.md — Instructions for Claude Code

CTI Warehouse is a Cyber Threat Intelligence data warehouse. It ingests and preserves security events, classifies known attack patterns (supervised ML), mines anomalous behaviour (unsupervised ML), enriches events with threat intelligence and MITRE ATT&CK references, correlates related evidence into alerts and cases, and presents everything through an investigation dashboard.

Architecture: a **modular monolith** — FastAPI backend + background worker + PostgreSQL warehouse + React/TypeScript dashboard, run **natively** (local PostgreSQL, `uv`, `npm`). Docker Compose is optional and only for containerised verification; never claim Docker-based results without running Docker. Read [PROJECT_OVERVIEW.md](PROJECT_OVERVIEW.md) first.

## Documentation map

| Topic | File |
|---|---|
| Vision, scope, requirements | [PROJECT_OVERVIEW.md](PROJECT_OVERVIEW.md) |
| Components, layering, data flow | [ARCHITECTURE.md](ARCHITECTURE.md) |
| Approved dependencies | [TECH_STACK.md](TECH_STACK.md) |
| Warehouse schema | [DATABASE_DESIGN.md](DATABASE_DESIGN.md) |
| Adapters, validation, dedup | [DATA_INGESTION.md](DATA_INGESTION.md) |
| Canonical fields | [DATA_DICTIONARY.md](DATA_DICTIONARY.md) |
| Supervised classification | [ML_CLASSIFICATION.md](ML_CLASSIFICATION.md) |
| Anomaly mining | [ANOMALY_DETECTION.md](ANOMALY_DETECTION.md) |
| Threat intel and ATT&CK | [THREAT_INTELLIGENCE.md](THREAT_INTELLIGENCE.md) |
| Correlation, alerts, risk scoring | [ATTACK_CORRELATION.md](ATTACK_CORRELATION.md) |
| REST API (`/api/v1`) | [API_SPECIFICATION.md](API_SPECIFICATION.md) |
| Dashboard | [FRONTEND_SPECIFICATION.md](FRONTEND_SPECIFICATION.md) |
| Security controls | [SECURITY_REQUIREMENTS.md](SECURITY_REQUIREMENTS.md) |
| Tests and commands | [TESTING_STRATEGY.md](TESTING_STRATEGY.md) |
| Phases | [IMPLEMENTATION_ROADMAP.md](IMPLEMENTATION_ROADMAP.md) |
| Definition of done per phase | [ACCEPTANCE_CRITERIA.md](ACCEPTANCE_CRITERIA.md) |
| Coding, migration, review rules | [DEVELOPMENT_RULES.md](DEVELOPMENT_RULES.md) |
| Running it | [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md) |
| Diagnosing problems | [TROUBLESHOOTING.md](TROUBLESHOOTING.md) |
| Decisions (ADRs) | [docs/decisions/README.md](docs/decisions/README.md) |

## Mandatory workflow

1. **Inspect before modifying.** Read the existing code, migrations, and tests in the area you will touch. Check `git status` and recent history. Do not assume a file or function exists — verify it.
2. **Read the specs first.** Before implementing anything, read the specification file(s) for that area plus the relevant phase in [IMPLEMENTATION_ROADMAP.md](IMPLEMENTATION_ROADMAP.md) and [ACCEPTANCE_CRITERIA.md](ACCEPTANCE_CRITERIA.md).
3. **Plan before significant changes.** For a new module, migration, API group, or ML pipeline, state the plan (files, schema changes, tests) before writing code.
4. **One phase at a time; one coherent milestone at a time.** Do not start Phase N+1 work while Phase N acceptance criteria are unmet, unless the user explicitly asks.
5. **Run the relevant tests** (commands in [TESTING_STRATEGY.md](TESTING_STRATEGY.md)). Fix failures before declaring a milestone complete.
6. **Report actual results** using the milestone report format below.

## Non-negotiable rules

- **No fabrication.** Never invent data, metrics, accuracy figures, test results, indicators, dataset columns, API responses, or integrations. Never claim a test passed unless you ran it and saw it pass. If something was not run, say "not run" and why.
- **No placeholders for required functionality.** Do not replace a required feature with a stub, `TODO`, `pass`, mocked return value, or hard-coded sample output. If something cannot be finished, stop and report it as incomplete.
- **Preserve existing functionality.** Do not delete or weaken existing behaviour, tests, or data to make something pass. Never skip, xfail, or loosen a test without explaining why in the report.
- **Ground truth is immutable.** Dataset labels and analyst feedback are never overwritten by model predictions (see [DATABASE_DESIGN.md](DATABASE_DESIGN.md)).
- **Observed facts ≠ predictions ≠ analyst conclusions.** Keep them in separate fields/tables and label them distinctly in API and UI.
- **Anomalies are not attacks; anomaly scores are not probabilities; alerts are hypotheses, not confirmed incidents.**
- **Dashboard honesty.** Every number shown in the UI comes from a real API response. Empty data → honest empty state.
- **Do not change the stack** ([TECH_STACK.md](TECH_STACK.md)) or add infrastructure (Kafka, Spark, Kubernetes, vector DBs, microservices) without an accepted ADR.

## Architecture boundaries (summary)

Layering in the backend is `api → services → (repositories | domain modules)`. Routers contain no SQL or business logic. Domain modules (`ingestion`, `ml`, `ti`, `correlation`) never import from `api`. The frontend talks to the backend only via `frontend/src/api/`. Full rules: [ARCHITECTURE.md](ARCHITECTURE.md#5-layering-and-module-boundaries) and [DEVELOPMENT_RULES.md](DEVELOPMENT_RULES.md).

## Database rules

- All schema changes go through **Alembic migrations** in `backend/migrations/versions/`. Never edit the schema by hand or with `create_all()` outside tests.
- Never edit a migration that has been merged/applied; add a new one.
- Every migration must upgrade on an empty database and on the previous head; provide `downgrade()` unless destructive (then document it).
- Ingestion is idempotent; re-importing the same file must not create duplicate events.

## ML rules

- Every training run records: random seed, dataset snapshot (batch IDs, row counts, hash), feature-set version, label-mapping version, config, library versions, and code version.
- Use leakage-aware splits; never put duplicate or near-duplicate records in both train and test. Fit preprocessing on training data only.
- Report per-class precision/recall, macro-F1, weighted-F1, and a confusion matrix. Never report accuracy alone.
- Model training/scoring runs as background jobs, never synchronously in a request handler.
- Load model artifacts only from the configured artifact directory, verified by the SHA-256 recorded in the model registry. Never load user-supplied model files.

## Security rules

Full list: [SECURITY_REQUIREMENTS.md](SECURITY_REQUIREMENTS.md). In short: no secrets in code or git; parameterised SQL only; RBAC on every endpoint except health and login; validate and size-limit uploads; never execute, render as HTML, or fetch content from logs or indicators (no visiting URLs from indicators); use public or synthetic data during development; audit-log every state-changing action.

## Documentation updates

When behaviour, schema, API contracts, configuration, or commands change, update the corresponding spec file in the same change. Significant technical choices get an ADR in [docs/decisions/](docs/decisions/README.md).

## Milestone report format

At the end of each milestone, report:

```text
## Milestone: <phase.number> <name>
Status: complete | partially complete | blocked
Changes: <files/modules added or changed>
Migrations: <revision ids, or "none">
Commands run: <exact commands>
Results: <actual output summary: passed/failed counts, metrics with dataset + split named>
Acceptance criteria: <AC ids met / not met>
Not done / limitations: <honest list>
Documentation updated: <files>
Next step: <proposal>
```
