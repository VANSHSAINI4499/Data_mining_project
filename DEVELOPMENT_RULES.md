# Development Rules

Practical, enforceable rules. Where a tool can enforce a rule (ruff, mypy, eslint, tests), it must. AI-assistant workflow rules are in [CLAUDE.md](CLAUDE.md).

## 1. Working agreement

1. Inspect before modifying; plan before significant changes; one milestone at a time ([IMPLEMENTATION_ROADMAP.md](IMPLEMENTATION_ROADMAP.md)).
2. Every change keeps the build green: lint, types, tests ([TESTING_STRATEGY.md](TESTING_STRATEGY.md#2-layout-and-commands)).
3. No placeholders for required functionality; no fabricated data, metrics, or results.
4. Preserve existing behaviour unless the change intentionally alters it and documents why.

## 2. Coding conventions

**Python (backend)**

- Python 3.12, type hints everywhere; `mypy --strict` for new modules (`app/` gradually strict; no new `Any` without a comment).
- `ruff` for lint + format (line length 100); rules include `E,F,I,B,UP,S` (bandit-style security), `SIM`, `PL` subset.
- Pydantic v2 models for all API I/O and canonical events; SQLAlchemy 2.0 typed ORM (`Mapped[...]`).
- Pure functions for parsing, normalisation, features, scoring; side effects at the edges (services, repositories, jobs).
- No global mutable state; dependencies injected (FastAPI `Depends`, function arguments). Time via injectable `now()` provider.
- Docstrings for public functions in domain modules explaining *why*, not restating code.

**TypeScript (frontend)**

- `strict: true`, no `any` (eslint error), no non-null assertions without comment.
- Function components + hooks; data fetching only via hooks in `src/hooks/` using `src/api/`.
- Tailwind utilities; shared tokens in Tailwind config; no inline style objects except dynamic chart sizes.
- No `dangerouslySetInnerHTML`, no `eval`/`new Function` (eslint rules).

## 3. Architecture boundaries

Enforced by review and an import-linter-style test (`tests/unit/test_architecture.py` checks imports with `ast`):

| Module | May import | Must not import |
|---|---|---|
| `app.api` | `services`, `schemas`, `core` | `repositories`, `models`, SQLAlchemy session APIs |
| `app.services` | everything below | `app.api`, FastAPI request objects |
| `app.repositories` | `models`, `core.db` | `services`, `api` |
| `app.ingestion`, `app.ti`, `app.ml`, `app.correlation`, `app.enrichment` | `core` (config/logging/errors), each other's pure helpers, pandas/NumPy/sklearn | `api`, `services`, FastAPI |
| `app.jobs` | `services`, `core` | `api` |
| `frontend/src/pages`, `features` | `hooks`, `components`, `lib` | `api/client` directly (go through hooks) |

Transactions are opened only in services. ML code receives DataFrames and returns results; it never opens DB sessions.

## 4. Naming conventions

| Thing | Convention | Example |
|---|---|---|
| Python modules/functions/variables | `snake_case` | `build_flow_features` |
| Python classes | `PascalCase` | `CanonicalEvent` |
| Constants | `UPPER_SNAKE` | `MAX_RECORD_BYTES` |
| DB tables | singular `snake_case`, layer prefix (`dim_`, `fact_`, `ti_`, `ml_`) | `fact_security_event` |
| DB constraints/indexes | `pk_`, `fk_`, `uq_`, `ix_`, `ck_` + table + columns | `ix_fact_security_event_dst_ip_event_time` |
| Alembic revisions | `YYYYMMDD_HHMM_<description>.py` | `20261101_0930_create_ti_tables.py` |
| API paths | plural kebab-case nouns | `/threat-intel/match-runs` |
| JSON fields | `snake_case` | `predicted_score` |
| Env vars | `CTI_` prefix | `CTI_MAX_UPLOAD_MB` |
| Adapters | `snake_case` name + semver | `zeek_conn@1.0` |
| Models (registry) | `snake_case` name + integer version | `attack_classifier` v3 |
| React components | `PascalCase.tsx` | `RiskBreakdownTable.tsx` |
| Hooks | `useX` | `useAlerts` |
| Tests | `test_<unit>_<behaviour>` / `<Component>.test.tsx` | `test_fingerprint_stable_across_runs` |

Terminology is fixed by [DATA_DICTIONARY.md](DATA_DICTIONARY.md): "event", "ground truth", "prediction/model output", "anomaly (unusual behaviour)", "indicator match", "alert (hypothesis)", "case", "disposition", "feedback".

## 5. Dependency management

- Follow [TECH_STACK.md](TECH_STACK.md#9-conditions-for-introducing-new-technology); runtime additions need an ADR; dev-only tools need a one-line justification.
- `uv add` / `npm install --save-exact` then commit lockfiles in the same change.
- No vendored copies of third-party code. No dependencies fetched at runtime.

## 6. Error handling

- Raise typed domain errors (`NotFoundError`, `ConflictError`, `ValidationFailedError`, `PermissionDeniedError`, `IntegrityError` for artifacts) from services/domain code; the API layer maps them to problem responses.
- Never swallow exceptions (`except Exception: pass` is forbidden). Catch narrowly; if catching broadly at a boundary (worker loop), log with context and record failure.
- Record-level ingestion errors are data (rejections), not exceptions that abort the batch.
- Error messages to clients are specific but never leak secrets, SQL, stack traces, or file system paths.
- Frontend: errors are shown, not hidden; no automatic fallback to fake data.

## 7. Logging

- Structured JSON logs to stdout: `timestamp`, `level`, `logger`, `message`, `request_id`, `job_id`, `user_id` (when present), plus event-specific fields.
- Levels: `DEBUG` (dev only), `INFO` (lifecycle: job start/end, batch counters), `WARNING` (recoverable anomalies: DQ warnings, retries), `ERROR` (failed jobs/requests).
- Never log secrets, session tokens, passwords, raw payloads, or full untrusted strings (truncate to 200 chars and escape control characters).
- Audit trail is the `audit_log` table, not application logs.

## 8. Configuration

- All runtime configuration via `CTI_*` environment variables parsed by one `Settings` class; documented in [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md#3-environment-variables) and `.env.example` in the same change that adds them.
- Domain configuration (label mappings, feature sets, rules, ML configs, dataset column specs, ATT&CK mappings) lives in versioned TOML under `config/`; changing semantics bumps the file's `version`.
- Safe defaults for development; production mode validates stricter requirements.

## 9. Database migration policy

Defined in [DATABASE_DESIGN.md §11](DATABASE_DESIGN.md#11-migration-rules). Summary: Alembic only; never edit applied revisions; upgrade from empty and from previous head are tested; separate data migrations; expand-then-contract for breaking changes; dictionary updated in the same change.

## 10. API contract changes

- Additive changes (new endpoint, new optional field) are allowed in `/api/v1`; update [API_SPECIFICATION.md](API_SPECIFICATION.md) and `frontend/src/api/types.ts` in the same change.
- Breaking changes require a new version prefix or a documented deprecation period; never silently change a field's meaning (e.g., redefining a score).
- Contract tests compare FastAPI's OpenAPI output with documented endpoints (presence of paths and methods).

## 11. ML artifact handling

- Artifacts only in `CTI_ARTIFACT_DIR`, written once, hashed, registered in a transaction ([ML_CLASSIFICATION.md §10](ML_CLASSIFICATION.md#10-model-persistence-and-versioning)).
- Never commit artifacts, datasets, or generated reports with real data; `artifacts/` and `data/external/` are git-ignored.
- Every reported metric names the training run ID, dataset/snapshot hash, split strategy, and model version.
- Notebooks (if any, in `notebooks/`, git-ignored outputs) are exploration only; production logic lives in `app/ml`.

## 12. Documentation updates

A change that alters behaviour, schema, API, configuration, commands, or limitations updates the relevant spec file(s) in the **same change**. Significant decisions get an ADR ([docs/decisions/README.md](docs/decisions/README.md)). Diagrams follow [docs/diagrams/README.md](docs/diagrams/README.md).

## 13. Git and repository hygiene

- Branch per milestone (`phase-2/ingestion-framework`); small, focused commits with imperative messages (`Add zeek_conn adapter with rejection tests`).
- Never commit: `.env`, secrets, datasets, uploads, artifacts, `node_modules`, virtualenvs, large binaries (> 1 MB requires justification).
- `main` must always pass the full default test suite.
- No force-push to shared branches; no rewriting published history.
- Generated files (OpenAPI dumps, coverage) are not committed unless a doc explicitly requires them.

## 14. Code review checklist

- [ ] The relevant spec was read and the change matches it (or the spec was updated with rationale).
- [ ] Architecture boundaries respected; no SQL in routers; transactions in services.
- [ ] Inputs validated; untrusted strings treated as inert data; no execution/fetching of log content.
- [ ] Queries parameterised; dynamic identifiers from allowlists.
- [ ] Authorization declared on new routes; audit entries for state changes.
- [ ] Migrations reviewed (constraints, indexes, downgrade, tested on empty + previous head).
- [ ] Facts, predictions, hypotheses, and analyst conclusions kept separate; ground truth untouched.
- [ ] ML changes: no leakage, seeds recorded, metrics per class, artifacts hashed.
- [ ] Errors handled per §6; logs per §7; no secrets logged.
- [ ] Tests added/updated and **actually run**; results quoted.
- [ ] Frontend: loading/empty/error states; numbers only from API; correct score labels.
- [ ] Documentation and `.env.example` updated; ADR added if needed.
- [ ] No new dependency without required justification/ADR.
