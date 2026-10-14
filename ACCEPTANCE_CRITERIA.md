# Acceptance Criteria

Measurable definition of done for each phase of the [roadmap](IMPLEMENTATION_ROADMAP.md). A criterion is **met** only when the stated evidence exists (command output, test names, API responses) and was produced in this environment. Criteria involving downloaded public datasets may be reported as **"not run — dataset not present"**, which leaves the phase *partially complete*, never silently complete.

Unacceptable criteria (never used): "zero bugs", "perfect detection", "100 % accuracy", "production-ready security", any metric target on a public dataset that has not been measured.

## Phase 1 — Repository setup and foundation

| ID | Criterion | Evidence |
|---|---|---|
| AC-1.1 | Repository layout matches [ARCHITECTURE.md §4](ARCHITECTURE.md#4-repository-layout-target); `.gitignore` excludes `.env`, `data/external/`, `artifacts/`, upload dir, virtualenvs, `node_modules`. | Tree listing; `git check-ignore` output. |
| AC-1.2 | Without Docker, following [DEPLOYMENT_GUIDE.md §4–§7](DEPLOYMENT_GUIDE.md#4-postgresql-native): native PostgreSQL, API, worker, and Vite dev server start; `/api/v1/health/ready` returns 200 through the dev proxy; a diagnostic job enqueued from the CLI is completed by the running worker. | Command log. |
| AC-1.2D | *(Optional — containerised verification, required only when Docker is available.)* `docker compose up -d --build` starts `postgres`, `backend`, `worker`, `frontend`; all report healthy within 120 s; the backend test suite passes against `postgres:17` in the container. | `docker compose ps` and test output. Reported as "not run" while Docker is unavailable. |
| AC-1.3 | `GET /api/v1/health` → 200; `GET /api/v1/health/ready` → 200 with DB up and migrations at head, 503 when DB is down or migrations are behind. | Integration tests. |
| AC-1.4 | `alembic upgrade head` on an empty DB creates `app_user`, `auth_session`, `audit_log`, `job`, `dim_date`; migration test suite passes. | Test output. |
| AC-1.5 | All configuration via `CTI_*` env vars documented in `.env.example` and [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md#3-environment-variables); production mode refuses placeholder secrets. | Unit test. |
| AC-1.6 | `cti create-admin`, login/logout/me, CSRF, roles work; route-enumeration authorization test passes. | Tests. |
| AC-1.7 | Worker claims and executes a `diagnostic` job; status visible via `GET /api/v1/jobs/{job_id}`; two workers never run the same job. | Integration test. |
| AC-1.8 | Structured JSON logs include `request_id`; secret redaction tested. | Unit test. |
| AC-1.9 | Frontend login page, app shell, and all routes render with honest empty/"not yet available" states; lint, typecheck, test, build pass. | Command output. |
| AC-1.10 | All backend/frontend lint, type-check, and test commands in [TESTING_STRATEGY.md §2](TESTING_STRATEGY.md#2-layout-and-commands) run successfully. | Command output. |

## Phase 2 — Database schema, ingestion, normalisation, data quality

| ID | Criterion | Evidence |
|---|---|---|
| AC-2.1 | Migrations create raw, dimension, fact (monthly partitioned), ground-truth, and DQ tables per [DATABASE_DESIGN.md](DATABASE_DESIGN.md); `cti seed-reference` loads categories, sources, rules idempotently. | Migration tests; seed run twice without duplicates. |
| AC-2.2 | All MVP adapters in [DATA_INGESTION.md §4](DATA_INGESTION.md#4-source-adapters) implemented, each with fixture tests covering mapping, variants, and every applicable rejection code. | Test list and output. |
| AC-2.3 | API upload enforces 413/415; API and CLI ingestion of the same file produce identical counters and fingerprints. | Tests. |
| AC-2.4 | Re-uploading a file yields `duplicate`; overlapping records are counted as duplicates; no duplicate events exist (`COUNT(*) = COUNT(DISTINCT (source_id, event_fingerprint, event_time))`). | Tests. |
| AC-2.5 | For every batch, `records_total = loaded + rejected + duplicate`; DQ results stored for each check in [DATA_INGESTION.md §10](DATA_INGESTION.md#10-data-quality-checks-per-batch). | Tests. |
| AC-2.6 | Event detail returns full provenance (file hash, record number, adapter version, timezone assumption, time quality). | API test. |
| AC-2.7 | `/events` and `/analytics/*` endpoints implement documented filters and cursor pagination; invalid filters → 422. | API tests. |
| AC-2.8 | A compatible public dataset file (UNSW-NB15 or CIC-IDS2017) imported via `cti ingest`, with measured duration/throughput and DQ results reported. | Run log — or "not run — dataset not present". |
| AC-2.9 | `cti generate-synthetic` produces deterministic scenario files plus `expected.json`; same seed → byte-identical output. | Test. |
| AC-2.10 | Asset inventory import creates SCD Type 2 versions and links events to assets by time. | Tests. |
| AC-2.11 | Chunk failure leaves a resumable `failed` batch; retry completes without duplicates. | Integration test. |

## Phase 3 — Supervised classification

| ID | Criterion | Evidence |
|---|---|---|
| AC-3.1 | Versioned label mappings for CIC-IDS2017 and UNSW-NB15; unmapped/ambiguous labels reported, never guessed. | Tests; report. |
| AC-3.2 | Feature sets `flow_v1` and dataset-native sets implemented; denylisted features cause training failure. | Tests. |
| AC-3.3 | Split strategies `group_stratified`, `temporal`, `predefined`; no group/event in two splits; leakage checks in [ML_CLASSIFICATION.md §6.4](ML_CLASSIFICATION.md#64-automated-leakage-checks-training-fails-or-warns) tested. | Tests. |
| AC-3.4 | Training job trains both Dummy baselines, Logistic Regression, and Random Forest; stores per-class precision/recall/F1/support, macro-F1, weighted-F1, confusion matrix with class order, bootstrap CI, permutation importance, data report. | API response for a run. |
| AC-3.5 | Artifact + manifest written; reload gives identical predictions; tampered hash / outside-dir path / version mismatch refused. | Tests. |
| AC-3.6 | Promotion gate enforced; exactly one active model per name. | Tests. |
| AC-3.7 | Scoring job writes `classification_result`; incompatible events skipped with counted reasons. | Tests. |
| AC-3.8 | Same snapshot + config + seed → identical metrics and predictions. | Test. |
| AC-3.9 | Training on an imported public dataset executed; actual metrics reported with dataset, snapshot hash, and split strategy. | Run report — or "not run — dataset not present". |
| AC-3.10 | Training/scoring never run inside request handlers (endpoints return 202). | API tests. |

## Phase 4 — Anomaly mining

| ID | Criterion | Evidence |
|---|---|---|
| AC-4.1 | `window_v1` features for `host`, `account`, `src_ip` equal hand-computed values on fixtures. | Tests. |
| AC-4.2 | `robust_zscore` and `isolation_forest` implemented; threshold = configured percentile of reference scores, stored on model and results. | Tests. |
| AC-4.3 | `anomaly_result` rows include feature snapshot, percentile, threshold, top deviations; `assumed` timestamps excluded. | Tests. |
| AC-4.4 | The planted anomalous entity-window in the synthetic scenario is flagged by both methods. | Test. |
| AC-4.5 | Anomaly endpoints return baseline comparison and history; no response or UI text calls scores probabilities. | API + text tests. |
| AC-4.6 | Proxy evaluation report produced when labels exist and is labelled "proxy". | Test. |

## Phase 5 — Threat intelligence and correlation

| ID | Criterion | Evidence |
|---|---|---|
| AC-5.1 | Manual, CSV, and STIX 2.1 indicator import with normalisation and versioning; unsupported patterns reported. | Tests. |
| AC-5.2 | Exact matching for all matchable types; state at match from event time; idempotent re-runs. | Tests. |
| AC-5.3 | ATT&CK bundle import; category→technique mappings validated against imported version (missing/revoked IDs reported). | Tests with fixture bundle. |
| AC-5.4 | Full test suite passes with **zero** feeds configured and no credentials. | Test run. |
| AC-5.5 | Rule DSL validation; five default rules fire on planted scenarios and not on near-miss scenarios. | Tests. |
| AC-5.6 | Dedup appends evidence to open alerts; risk score and breakdown equal hand-computed values. | Tests. |
| AC-5.7 | Alert → case → notes → close with disposition → feedback works with timeline and audit rows. | Tests. |
| AC-5.8 | No outbound network calls during import, matching, or correlation (socket-blocking test). TAXII, if implemented, tested against a local stub; otherwise recorded as deferred to Phase 8. | Tests / report. |

## Phase 6 — API and dashboard integration

| ID | Criterion | Evidence |
|---|---|---|
| AC-6.1 | All pages in [FRONTEND_SPECIFICATION.md §5](FRONTEND_SPECIFICATION.md#5-pages) implemented against real endpoints (no mocks outside tests). | Code review checklist; grep for test-only mocks outside `src/test`. |
| AC-6.2 | `/dashboard/overview` implemented; E2E asserts its values equal direct DB counts. | E2E test. |
| AC-6.3 | Every page has loading, empty, and error tests; empty-state tests assert no numeric statistics are rendered. | Frontend tests. |
| AC-6.4 | Category tags and score labels ("uncalibrated", "percentile", "rule-based") present where required. | Frontend tests. |
| AC-6.5 | Untrusted strings rendered as text; URLs/domains defanged and non-clickable. | Frontend tests. |
| AC-6.6 | Role-based visibility of controls; backend still rejects forbidden actions. | Frontend + API tests. |
| AC-6.7 | Frontend lint, typecheck, tests, and production build pass. | Command output. |

## Phase 7 — Security, testing, deployment, documentation

| ID | Criterion | Evidence |
|---|---|---|
| AC-7.1 | Rate limits from [API_SPECIFICATION.md §8](API_SPECIFICATION.md#8-rate-limiting) enforced (429 + `Retry-After`). | Tests. |
| AC-7.2 | Security headers, CORS restriction, production-mode checks (no Swagger, no placeholder secrets; non-root containers in the optional Docker images). | Tests; Dockerfile review. |
| AC-7.3 | Authorization and security suites ([TESTING_STRATEGY.md §10–11](TESTING_STRATEGY.md#10-authorization-tests)) pass. | Test output. |
| AC-7.4 | `pip-audit` and `npm audit --omit=dev` executed; high/critical findings fixed or justified in release notes. | Command output. |
| AC-7.5 | From a fresh clone, following the native path in [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md) verbatim, the stack starts and the E2E suite passes. If Docker is available, repeat with Docker Compose (AC-1.2D). | Command log. |
| AC-7.6 | NFR-03/NFR-04 measured and reported as measured values (no assumed numbers). | Benchmark log. |
| AC-7.7 | Documentation matches implementation; Markdown link check passes; ADRs exist for decisions taken. | Link-check output; review. |
| AC-7.8 | `cti retention apply --dry-run` reports counts; `--execute` deletes per policy and is audited. | Tests. |
| AC-7.9 | MVP release checklist below is fully met. | Checklist with evidence links. |

## Phase 8 — Temporal pattern mining, incremental ingestion, concept drift

| ID | Criterion | Evidence |
|---|---|---|
| AC-8.1 | Incremental processing: watermarks for matching, scoring, and correlation; a second run processes only new events (tested). Inbox-folder ingestion (`cti watch`) imports new files once. | Tests. |
| AC-8.2 | Drift reports (PSI per feature, flagged-rate change, prediction distribution shift) generated on schedule/command; warnings shown on Models page; no automatic retraining. | Tests. |
| AC-8.3 | Sequential pattern mining recovers a planted sequence from synthetic data and outputs candidate rules requiring human enablement. | Test. |
| AC-8.4 | TAXII 2.1 polling (if not delivered in Phase 5) works against a local stub with cursor, pagination, retry, 429 handling. | Tests. |

## MVP release checklist (end of Phase 7)

| MVP capability | Criteria |
|---|---|
| Starts locally with documented commands (Docker optional) | AC-1.2, AC-7.5 |
| Initialises the database through migrations | AC-1.4, AC-2.1 |
| Imports a compatible public security dataset | AC-2.8 |
| Validates, normalises, and preserves events | AC-2.2–AC-2.6 |
| Queries historical data | AC-2.7 |
| Trains and evaluates a classifier | AC-3.3, AC-3.4, AC-3.9 |
| Scores anomalies | AC-4.2–AC-4.4 |
| Persists and reloads model artifacts | AC-3.5 |
| Matches configured threat indicators | AC-5.1, AC-5.2 |
| Correlates related events with supporting evidence | AC-5.5, AC-5.6 |
| Displays real API-backed analytics | AC-6.1–AC-6.3 |
| Handles invalid inputs and failures safely | AC-2.3, AC-2.11, AC-7.1–AC-7.3 |
| Passes the required tests | AC-1.10, AC-6.7, AC-7.3, AC-7.5 |
