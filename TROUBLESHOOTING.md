# Troubleshooting

How to diagnose common problems **without hiding errors or deleting useful data**. Commands assume the native setup in [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md), run from the repository root (`uv run --project backend …`). For the optional Docker setup, prefix backend commands with `docker compose exec backend`.

## 0. General approach

1. Read the full error: API problem response (`title`, `detail`, `request_id`), job `error`, container logs.
2. Correlate by ID: search the API/worker console output (JSON lines) for the `request_id` or `job_id` (Docker: `docker compose logs backend worker | grep <id>`).
3. Check readiness: `curl -s http://localhost:8000/api/v1/health/ready`.
4. Reproduce with the narrowest command (single test, single file, single job).
5. Fix the cause. Do **not**: delete volumes, drop tables, edit applied migrations, disable tests, catch-and-ignore exceptions, or replace real data with samples to make a symptom disappear. If a destructive step is truly needed, back up first (`pg_dump`) and record why.

## 1. Dependency conflicts

| Symptom | Diagnosis | Fix |
|---|---|---|
| `uv sync` fails to resolve | `uv tree`, read the conflicting constraint | Adjust the one dependency deliberately; commit `uv.lock`; never delete the lockfile to "start fresh" without review. |
| `npm ci` fails: lockfile mismatch | `package.json` changed without lockfile | Run `npm install` intentionally, review the diff, commit both. |
| Behaviour changed after upgrade | Compare lockfile diff | Pin back or adapt; scikit-learn upgrades may change model outputs (retrain and record). |

## 2. Python environments

- `ModuleNotFoundError: app` → run commands from `backend/` via `uv run`, or the package isn't installed (`uv sync`).
- Wrong interpreter → `uv run python --version` must show 3.12.x; `uv python pin 3.12` if needed.
- `cti: command not found` → use `uv run cti …` natively; in Docker the image installs the entry point (rebuild with `docker compose build backend`).
- Windows: native paths with spaces must be quoted; line-ending issues in shell scripts → ensure `.gitattributes` sets `*.sh text eol=lf`.

## 3. Node.js versions

- `npm` errors about engines or unexpected syntax → `node --version` must match `frontend/.nvmrc` (24 LTS). Use `nvm use` (or `fnm`).
- Vite fails to start in Docker on Windows file mounts (no hot reload) → enable polling (`CHOKIDAR_USEPOLLING=true`) in the dev profile only.

## 4. Database connections

| Symptom | Check | Fix |
|---|---|---|
| `connection refused` | `pg_ctl -D .local/pgdata status`, `.local/pg.log` (Docker: `docker compose ps postgres`) | Start it: `pg_ctl -D .local/pgdata start`. |
| Works in Docker, fails natively | `CTI_DATABASE_URL` host is `postgres` (container name) | Use `localhost` for native runs. |
| `password authentication failed` | `.env` changed after volume creation | Postgres keeps the original password in the volume; set the password with `ALTER USER` via `psql` rather than deleting the volume. |
| Port 5432 in use | Another local PostgreSQL | Change the published port mapping or stop the other instance. |
| `/health/ready` 503 `database` | Readiness output | Fix connectivity first; the API intentionally stays not-ready. |

## 5. Migrations

- `/health/ready` 503 `migrations_behind` → `alembic upgrade head`.
- `Can't locate revision` → your DB was migrated by a branch whose revision isn't present. Check `alembic current` and `alembic history`; return to the branch or add a merge revision. Never edit `alembic_version` by hand without a backup and a recorded reason.
- Multiple heads → `alembic heads`; create a merge revision (`alembic merge -m "merge heads" <rev1> <rev2>`).
- Migration fails half-way → PostgreSQL DDL is transactional; the revision rolled back. Fix the migration (if unapplied anywhere) or add a new corrective revision.
- Autogenerate wants to drop partitions/functions → expected; partitions and functions are hand-managed and allow-listed ([DATABASE_DESIGN.md §11](DATABASE_DESIGN.md#11-migration-rules)).
- Rows in the default partition (DQ check `default_partition_empty` fails) → event times outside created partitions; run ingestion's partition creation for that range and move rows with a documented maintenance command, not by deleting them.

## 6. File uploads

| Symptom | Meaning | Fix |
|---|---|---|
| 413 | Over `CTI_MAX_UPLOAD_MB` | Use `cti ingest` for large files. |
| 415 | Extension not allowed or binary content | Decompress archives; ensure the file is text CSV/JSON/JSONL/TSV/log. |
| 403 `csrf-failed` | Missing CSRF header | Re-login in the UI; API clients must send `X-CSRF-Token`. |
| Batch `duplicate` | Same file already ingested | Expected idempotency; see `duplicate_of`. |
| CLI `path outside import root` | Path not under `CTI_IMPORT_ROOT` | Move the file under `./data/` (mounted at `/data`). |

## 7. Dataset schema mismatches

- `UNSUPPORTED_VARIANT` → the batch error lists missing columns. Compare with the adapter's documented variants ([DATA_INGESTION.md §4](DATA_INGESTION.md#4-source-adapters)); you may have a different distribution of the dataset. Do not rename columns by hand silently — add/extend a variant in the adapter with tests.
- `TIMEZONE_NOT_CONFIGURED` → set the source's `default_timezone` (only you can decide the correct value; record your source for it).
- High rejection ratio / `ADAPTER_MISMATCH_SUSPECTED` → inspect `GET /api/v1/ingestion/batches/{id}/rejections`; most common: wrong adapter, wrong delimiter, header-less file (UNSW-NB15 raw files need the column spec).
- `ENCODING_ERROR` → check the adapter's fallback encodings; add the correct encoding to the adapter config with a test rather than ignoring errors.
- Many `unmapped` labels → extend `config/label_mappings/<dataset>.toml` (new version) after checking the dataset documentation; never map by guess.
- Non-finite values warnings (CIC-IDS2017 rate columns) → expected; they are stored as NULL and reported.

## 8. Missing ML features

- Training fails "feature X missing" → the feature set requires attributes absent from the selected batches (e.g., a native feature set on a different source). Choose `flow_v1` or the matching native set.
- "denylisted feature present" → a config tries to use identifiers/labels; remove it. This check is intentional.
- Scoring skipped many events (`incompatible_source`, `too_many_missing_features`) → the active model's feature set doesn't fit those events; train a model for that source.
- Anomaly windows `insufficient_history` → fewer than `min_baseline_windows`; import more history or lower the setting knowingly (recorded in config).
- Leakage warning "single feature reaches macro-F1 ≥ 0.98" → investigate the feature (often a dataset artefact such as port or TTL); acknowledge only with a written note.

## 9. Model persistence

| Error | Cause | Fix |
|---|---|---|
| `ARTIFACT_INTEGRITY_FAILED` | File hash differs from registry | The artifact changed or is corrupted. Do not bypass; retrain or restore the original file from backup. |
| `ARTIFACT_VERSION_MISMATCH` | scikit-learn major.minor differs from manifest | Use the matching environment or retrain under the current versions. |
| Artifact not found | Volume removed or path changed | Check `CTI_ARTIFACT_DIR` and the `artifacts` volume; the registry row remains for lineage. |
| Orphan files in artifact dir | Training crashed before registration | `cti artifacts gc --dry-run`, then run without `--dry-run`. |

## 10. Docker

- Service unhealthy → `docker compose ps`, `docker compose logs <service>`; check health check command output.
- Code changes not visible → rebuild: `docker compose up -d --build backend worker`.
- Disk full → `docker system df`; prune **unused images/build cache** (`docker builder prune`), not volumes holding data.
- Permission denied on volumes (Linux) → containers run as non-root; ensure host bind-mount ownership matches the container UID or use named volumes.
- Windows/WSL2 slow file I/O → keep the repo inside the WSL2 filesystem.

## 11. Frontend–API connection

| Symptom | Check | Fix |
|---|---|---|
| Network error / 404 on `/api` | Vite proxy target | `CTI_BACKEND_PROXY_TARGET` = `http://backend:8000` (compose) or `http://localhost:8000` (native). |
| CORS error | `CTI_CORS_ORIGINS` | Include the exact origin (scheme, host, port). |
| Logged out after page reload | Is the `cti_session` cookie present in the browser? | After reload the app calls `GET /auth/me` to restore the user and rotate the CSRF token. If the cookie is missing, check its `Path` and `Secure` settings (`Secure` cookies are not sent over plain HTTP in development). |
| Mutations fail with 403 `csrf-failed` after reload | `GET /auth/me` ran before the mutation? | Ensure the API client stores the CSRF token returned by `/auth/me`. |
| Empty dashboard | Real empty data or failing requests | Check the browser network tab; empty states must reflect real empty responses. Do not add sample data to the UI. |

## 12. Test failures

- Integration tests are skipped or fail to connect → check `CTI_TEST_DATABASE_URL`, that PostgreSQL is running (`pg_ctl -D .local/pgdata status`), and that `cti_test` exists.
- `UnsafeTestDatabaseError` → `CTI_TEST_DATABASE_URL` names a database without `test` in its name, or the same database as `CTI_DATABASE_URL`. The guard prevents the suite from dropping real data; fix the URL, never the guard.
- Tests pass alone, fail together → shared state; check transaction rollback fixtures and worker tests using truncation.
- Non-deterministic ML test → missing seed or dependency on dict/set ordering; fix the source of nondeterminism, don't widen tolerances blindly.
- Socket-blocking fixture fails a test → code attempted an outbound network call; that is a bug for ingestion/matching paths.
- Frontend test fails on "fake numbers" assertion → a component renders a value not from the mocked response; fix the component.
- Report failing tests honestly in the milestone report; do not mark the milestone complete ([TESTING_STRATEGY.md §15](TESTING_STRATEGY.md#15-failure-handling)).
