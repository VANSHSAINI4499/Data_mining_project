# Testing Strategy

## 1. Principles

- **Never report tests as passing unless they were executed and passed in this environment.** Reports quote the actual command and the pass/fail/skip counts. "Not run" is an acceptable, honest status; "should pass" is not.
- Tests run against **real PostgreSQL** (partitioning, `inet`, `jsonb`, `SKIP LOCKED` are used); SQLite is not a substitute.
- Fixtures are synthetic or handcrafted; no real organisational data, no copied dataset rows ([SECURITY_REQUIREMENTS.md](SECURITY_REQUIREMENTS.md#10-privacy)).
- Tests are deterministic: fixed seeds, frozen clocks where time matters, no network access (outbound HTTP is blocked in tests; TAXII tests use a local stub).
- Skips must carry a reason (`pytest.mark.skipif(..., reason=...)`) and are listed in milestone reports.
- A bug fix comes with a test that fails before the fix.

## 2. Layout and commands

```text
backend/tests/
  unit/           no DB, no filesystem beyond tmp_path         marker: unit
  integration/    PostgreSQL via CTI_TEST_DATABASE_URL          marker: integration
  e2e/            against a running stack (native or Compose)   marker: e2e
  dataset/        optional, needs downloaded public datasets    marker: dataset
  fixtures/       ingestion/, ti/, ml/ small files
  conftest.py
frontend/src/**/*.test.tsx, frontend/src/test/ (setup, MSW handlers)
```

`pyproject.toml` sets `addopts = -m "not e2e and not dataset"` so the default run is unit + integration.

| Purpose | Command (from repo root) |
|---|---|
| Backend lint/format/type | `cd backend && uv run ruff check . && uv run ruff format --check . && uv run mypy app` |
| Backend unit | `cd backend && uv run pytest -m unit` |
| Backend unit + integration | `cd backend && uv run pytest` (requires `CTI_TEST_DATABASE_URL`) |
| Coverage | `cd backend && uv run pytest --cov=app --cov-report=term-missing` |
| Migration tests | `cd backend && uv run pytest tests/integration/test_migrations.py` |
| E2E (API-level) | start the stack natively ([DEPLOYMENT_GUIDE.md §5–§6](DEPLOYMENT_GUIDE.md#5-backend-and-worker)) then `cd backend && uv run pytest -m e2e` |
| Optional dataset tests | `cd backend && CTI_DATASET_DIR=../data/external uv run pytest -m dataset` |
| Frontend lint/type | `cd frontend && npm run lint && npm run typecheck` |
| Frontend tests | `cd frontend && npm run test -- --run` |
| Frontend build | `cd frontend && npm run build` |
| *(Optional)* Everything in Docker | `docker compose run --rm backend uv run pytest` and `docker compose run --rm frontend npm run test -- --run` — counts as passed only when actually executed |
| Dependency audit (Phase 7) | `cd backend && uv run pip-audit` ; `cd frontend && npm audit --omit=dev` |

The test database (`cti_test`) is created manually for native PostgreSQL ([DEPLOYMENT_GUIDE.md §4](DEPLOYMENT_GUIDE.md#4-postgresql-native)) or by the optional Compose init script. Its name must contain `test` and differ from `CTI_DATABASE_URL`; the fixtures refuse to run otherwise, because they drop and recreate the `public` schema. If `CTI_TEST_DATABASE_URL` is unset, integration tests are skipped with a reason; if it is set but unreachable, they error. The session fixture runs `alembic upgrade head` once; each test runs inside a transaction/SAVEPOINT rolled back at teardown. Tests needing committed data across processes (worker tests) use a truncation fixture instead.

## 3. Fixtures and test data

| Fixture | Content | Location |
|---|---|---|
| Synthetic scenario generator | `cti generate-synthetic --scenario <name> --seed <n> --out <dir>` emits canonical JSONL/CSV with **planted, known** patterns: SSH brute force followed by success, port scan then exploit-like flows, an account with anomalous login volume, flows to documentation IPs that appear in a synthetic indicator list, plus benign background. Ground-truth labels and an `expected.json` (which alerts/matches/flags should appear) are generated alongside. Deterministic per seed. | `backend/app/devtools/synthetic.py`; outputs in `data/samples/` (committed small versions) |
| Adapter fixtures | 5–50 handcrafted rows per adapter/variant, **synthetic values with realistic header structure** (e.g., CIC-IDS2017 header quirks: leading spaces, duplicate column, `Infinity`), plus malformed rows for every rejection code. | `backend/tests/fixtures/ingestion/<adapter>/` |
| TI fixtures | CSV and STIX 2.1 bundles with supported and unsupported patterns, defanged values, expired/revoked indicators; documentation values only. | `backend/tests/fixtures/ti/` |
| ATT&CK fixture | Minimal STIX bundle with a handful of `attack-pattern` objects in the official structure (synthetic descriptions). | `backend/tests/fixtures/attack/` |
| ML fixtures | Small DataFrames with known separability, deliberate duplicates and label conflicts, a deliberately leaking column. | built in tests (`tests/unit/ml/conftest.py`) |
| Factories | Functions creating DB rows (`make_event`, `make_batch`, `make_model`…). | `backend/tests/factories.py` |
| Frontend | MSW handlers returning schema-valid payloads **including empty and error payloads**. Test-only. | `frontend/src/test/` |

Public datasets are never committed; `dataset`-marked tests run only if files exist and are skipped with a reason otherwise.

## 4. Unit tests

Pure functions and classes: normalisers (timestamps, IPs, protocols), fingerprinting stability, label normalisation and mapping, feature builders (hand-computed expected values), window features, robust z, risk-score formula (table-driven), rule DSL validation, indicator normalisation (re-fanging, IDNA, hash checks), STIX pattern tokenizer, pagination cursor encode/decode, config validation, redaction filter.

## 5. Migration tests

- Migration tests run on a scratch database `<test database>_migrations` that the test creates and drops, so the test role needs `CREATEDB` (the Docker `POSTGRES_USER` is a superuser; for a native cluster grant it explicitly).
- Upgrade empty DB → `head`; downgrade `head` → `base` → upgrade again (where downgrades exist).
- Upgrade from each previous revision with representative rows present (data survives, constraints valid).
- Alembic model/DB drift check: autogenerate against `head` produces no unexpected operations (known exceptions like partitions are allow-listed in the test).
- `ensure_event_partitions` creates monthly partitions; default partition stays empty for in-range data.
- Seeded reference data (`dim_date`, `dim_attack_category`) exists after upgrade.

## 6. Database and API integration tests

- **Repositories:** constraints (unique fingerprint, one active model per name, one open alert per dedup key), cascade/FK behaviour, partition pruning queries return correct rows, append-only tables reject updates where enforced by privileges (production-role test).
- **API:** for every endpoint — success path, validation errors (422 problem shape), not found, conflict cases, pagination (cursor continuity, limit bounds), filters (each filter narrows results correctly), response schema matches Pydantic model, `X-Request-ID` present, 202 + job for async endpoints.
- **Jobs:** worker claims with `SKIP LOCKED` (two workers don't run the same job), failure recorded, retry/back-off for transient errors, heartbeat timeout.
- **Health:** `/health/ready` returns 503 when DB unreachable or migrations behind.

## 7. ML pipeline tests

- Pipeline fits only on training data (spy/assert the fitted scaler's statistics equal training-split statistics).
- **Leakage checks:** denylisted feature → training fails; group split never puts the same `feature_hash` group or `event_id` in two splits (property test over random seeds); a deliberately leaking column triggers the single-feature warning; suspiciously high score warning fires.
- Duplicate and label-conflict statistics are correct on a fixture with known counts.
- Rare-class merge/exclude policies behave as configured and are reported.
- Metrics: per-class P/R/F1, macro/weighted F1, confusion matrix match `sklearn.metrics` on a fixed fixture; class order recorded.
- Baselines are always trained and stored; promotion gate rejects a model that does not beat `DummyClassifier(stratified)`.
- **Reproducibility:** two runs with identical snapshot/config/seed produce identical metrics and test-split predictions.
- Persistence: save → reload → identical predictions; tampered artifact (hash mismatch) fails to load; path outside artifact dir rejected; version mismatch rejected.
- Inference skips incompatible events with counted reasons.
- Anomaly: window features equal hand-computed values; robust z with MAD=0 handled; threshold = configured percentile of reference scores; scores higher for planted anomalies than for background in the synthetic scenario; events with `time_quality = 'assumed'` excluded.

## 8. Ingestion tests

Per adapter: variant detection, header normalisation, field mapping, every rejection code, non-finite handling, timezone handling (configured vs. missing), label mapping (mapped/unmapped/ambiguous), fingerprint stability, **idempotent re-import** (same file twice → `duplicate`; same records in a new file → counted duplicates, no new events), counter reconciliation, chunk failure + resume, rejection-ratio cut-off, upload size limit (413), extension allowlist (415), binary content rejection.

## 9. Indicator matching and correlation tests

- Matching: each indicator type against each matchable field; normalised equality (case, trailing dot, defanged inputs); expired/revoked excluded by default and included with `include_expired`; state at match computed from event time; re-run creates no duplicates; unsupported STIX patterns not matched.
- Correlation: each default rule fires on its planted synthetic scenario and **does not** fire on near-miss scenarios (9 failures instead of 10; success before failures; events outside window); dedup appends evidence to the open alert; dismissed alerts are not reopened; risk score and breakdown equal hand-computed values; rule versioning preserves the version on existing alerts; invalid DSL rejected (unknown field, operator, window).

## 10. Authorization tests

- A parametrised test enumerates **all registered routes** and asserts each declares a minimum role (except health and login).
- For each route: unauthenticated → 401; insufficient role → 403 (audited for state-changing routes); sufficient role → not 401/403.
- CSRF: state-changing request without/with wrong `X-CSRF-Token` → 403.
- Session expiry, logout revocation, lockout after failures, last-admin protection.

## 11. Security tests

Malicious content in every free-text field (`<script>`, `javascript:` URLs, `=cmd|...` formula strings, very long strings, NUL bytes, Unicode bidi characters) is stored inertly and returned as JSON strings; frontend tests assert it renders as text. SQL-injection probes in all filter parameters return 422 or empty results, never errors revealing SQL. Upload path traversal attempts in filenames have no effect. Secret redaction in logs. No outbound network calls during ingestion/matching (socket-blocking fixture). Artifact integrity checks. Dependency audit commands (Phase 7).

## 12. End-to-end tests

API-level E2E against a running stack (native by default; Docker Compose when available) (`-m e2e`), using the synthetic scenario:

1. `/health/ready` is ready.
2. Create admin (CLI) and log in; create source; upload synthetic files; wait for jobs.
3. Assert batch counters and DQ results.
4. Train classifier on the synthetic labelled data; assert run succeeded and metrics present (no threshold on quality beyond beating the dummy baseline).
5. Promote; score; assert classification results exist.
6. Train/score anomaly model; assert planted anomalous account window is flagged.
7. Import synthetic indicators; match; assert expected matches.
8. Correlate; assert expected alerts per `expected.json` with evidence and risk breakdown.
9. Escalate to case, add note, close with disposition, submit feedback; assert audit records.
10. `GET /dashboard/overview` values equal counts queried directly from the DB.

Browser-level E2E (Playwright) is not in the MVP stack (ADR required).

## 13. Frontend tests

Vitest + React Testing Library + MSW:

- API client: CSRF header added on mutations, problem+json parsed, 401 redirect.
- Every page: loading, **empty** (asserts no numeric stats rendered), error (shows `request_id`), and populated states.
- Displayed numbers equal the mocked response values (no client-side invention); labels for scores ("uncalibrated", "percentile", "rule-based") present.
- Untrusted strings render as text; defanging applied; no anchor elements for indicator URLs.
- Role-based control visibility.
- Forms: validation messages, disabled submit while pending, job progress polling stops at terminal states.
- `npm run build` succeeds with `strict` TypeScript.

## 14. Reproducibility rules

- Seeds fixed in tests and recorded in failure messages.
- `freezegun`-style clock control is **not** added as a dependency; code takes an injectable `now()` provider instead.
- Floating-point comparisons use explicit tolerances (`pytest.approx`) except where exact reproducibility is the requirement under test.
- Lockfiles define the test environment; CI-equivalent commands above use `uv sync --frozen` and `npm ci`.

## 15. Failure handling

1. Read the full failure output; reproduce with the narrowest command (`pytest path::test -x -vv`).
2. Fix the cause in code or, if the test is wrong, fix the test **and explain why** in the report.
3. Never delete, skip, xfail, or loosen assertions to make the suite green without explicit justification recorded in the milestone report.
4. Flaky tests are bugs: quarantine only with an issue/ADR note and a deadline, and report them.
5. A milestone with failing required tests is reported as **not complete**.

## 16. Coverage expectations

Coverage is a signal, not a goal: target ≥ 80 % line coverage for `app/ingestion`, `app/ml`, `app/ti`, `app/correlation`, `app/core/security*`; report actual numbers from `pytest --cov`, never estimated numbers.
