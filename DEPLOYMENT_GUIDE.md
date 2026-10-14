# Deployment Guide

Local setup (native, primary) and optional Docker Compose deployment.

> **Status:** Phase 1 is implemented. The **native path (§4–§7) is the supported development setup** and was verified on Windows 11 with PostgreSQL 18.6 (Scoop), Python 3.12.5, and Node.js 22.23. **Docker is optional**: the Docker Compose files (§11) are kept for later containerised verification but **have never been run**. Commands for later phases are marked with their phase and do not exist yet.

Nothing here assumes Docker, external credentials, or downloaded datasets.

## 1. Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Git | any recent | |
| Python | 3.12.x | Backend. |
| uv | recent stable | `pip install --user uv` works. Fallback: `pip install -e backend --group dev` (pip ≥ 25.1). |
| Node.js | ≥ 22.22 (24 LTS preferred, see `frontend/.nvmrc`) | Frontend. |
| PostgreSQL | ≥ 17 (17 is the reference; 18.6 verified) | Native install. On Windows without admin rights: Scoop (§4). |
| *(optional)* Docker with Compose v2 | recent stable | Only for containerised verification (§11). |

Ports: `5173` (frontend), `8000` (backend), `5432` (PostgreSQL, bound to localhost).

All commands below are run from the **repository root** unless stated otherwise. `uv run --project backend …` runs a backend command from there.

## 2. Get the code

```bash
git clone <repository-url> CTI-Warehouse
cd CTI-Warehouse
cp .env.example .env
```

Edit `.env` and replace every `change-me` value (§9).

## 3. Environment variables

Implemented now (every one is listed in `.env.example`; a unit test enforces this):

| Variable | Default | Description |
|---|---|---|
| `CTI_ENV` | `development` | `development`, `test`, or `production` (production refuses placeholder secrets). |
| `CTI_LOG_LEVEL` | `INFO` | Log level. |
| `CTI_DATABASE_URL` | `postgresql+psycopg://cti:change-me@localhost:5432/cti` | Application database. |
| `CTI_TEST_DATABASE_URL` | `postgresql+psycopg://cti:change-me@localhost:5432/cti_test` | Test database. Its name **must contain `test`** and differ from `CTI_DATABASE_URL`; the test suite refuses otherwise because it drops and recreates the schema. |
| `CTI_SECRET_KEY` | `change-me` | ≥ 32 random bytes; HMAC key for session/CSRF token hashing. Generate: `python -c "import secrets; print(secrets.token_urlsafe(48))"`. |
| `CTI_SESSION_TTL_MINUTES` / `CTI_SESSION_IDLE_MINUTES` | `480` / `60` | Session lifetimes. |
| `CTI_CORS_ORIGINS` | `http://localhost:5173` | Comma-separated allowed origins. |
| `CTI_UPLOAD_DIR` / `CTI_ARTIFACT_DIR` | `.local/uploads` / `.local/artifacts` | Writable directories; relative paths resolve against the repository root. |
| `CTI_MAX_CONCURRENT_JOBS` | `2` | Job slots per worker process. |
| `CTI_JOB_HEARTBEAT_SECONDS` | `15` | How often a running job refreshes its heartbeat (and notices cancellation). |
| `CTI_JOB_TIMEOUT_SECONDS` | `600` | A running job without a heartbeat for this long is failed with `worker_timeout`. |
| `CTI_WORKER_POLL_SECONDS` | `2` | Idle polling interval of the worker. |
| `VITE_API_BASE_URL` | `/api/v1` | Frontend API base (public; never a secret). |
| `CTI_BACKEND_PROXY_TARGET` | `http://localhost:8000` | Vite dev-server proxy target for `/api`. |
| `POSTGRES_USER` / `POSTGRES_PASSWORD` / `POSTGRES_DB` | `cti` / `change-me` / `cti` | Used only by the optional Docker Compose stack. |

Planned (added to `.env.example` when their phase is implemented):

| Variable | Default | Phase |
|---|---|---|
| `CTI_MAX_UPLOAD_MB`, `CTI_IMPORT_ROOT` (`./data`), `CTI_MAX_REJECT_RATIO` (`0.2`) | `50`, `./data`, `0.2` | 2 |
| `CTI_MAX_QUERY_DAYS` / `CTI_MAX_AGG_DAYS` | `400` / `400` | 2 |
| `CTI_SITE_TIMEZONE` | `UTC` | 4 |
| `CTI_ALERT_MAX_EVIDENCE`, `CTI_TI_*` ([THREAT_INTELLIGENCE.md §11](THREAT_INTELLIGENCE.md#11-configuration)) | — | 5 |
| `CTI_RETENTION_*` ([DATABASE_DESIGN.md §9](DATABASE_DESIGN.md#9-retention)) | — | 7 |
| `CTI_DATASET_DIR` | unset | enables `dataset`-marked tests |

## 4. PostgreSQL (native)

Any native PostgreSQL ≥ 17 works. On Windows without admin rights, Scoop installs a user-level copy:

```bash
scoop install postgresql
initdb -D .local/pgdata -U postgres --auth=scram-sha-256 --pwprompt -E UTF8 --locale=C
pg_ctl -D .local/pgdata -l .local/pg.log -o "-p 5432 -c listen_addresses=localhost" start
psql -h localhost -U postgres -c "CREATE ROLE cti LOGIN CREATEDB PASSWORD '<app password>'"
psql -h localhost -U postgres -c "CREATE DATABASE cti OWNER cti"
psql -h localhost -U postgres -c "CREATE DATABASE cti_test OWNER cti"
```

- `.local/` is git-ignored. Put the matching URLs in `.env`.
- `CREATEDB` is needed because migration tests create and drop a scratch database `cti_test_migrations`.
- The cluster does not start automatically: `pg_ctl -D .local/pgdata start` / `stop` / `status`.

## 5. Backend and worker

```bash
uv sync --project backend
uv run --project backend alembic -c backend/alembic.ini upgrade head
uv run --project backend cti create-admin --username admin          # prompts for a password
uv run --project backend uvicorn app.main:app --reload --port 8000   # terminal 1
uv run --project backend cti worker --heartbeat-file .local/worker.beat   # terminal 2
```

Migrations never run automatically; `/api/v1/health/ready` returns 503 until the database is at head. Other Alembic commands: `current`, `history --verbose`, `check` (detects model/schema drift), `downgrade -1` (development only).

## 6. Frontend

```bash
cd frontend
npm ci
npm run dev        # http://localhost:5173, proxies /api to CTI_BACKEND_PROXY_TARGET
```

## 7. Health checks and a first job

```bash
curl -s http://localhost:8000/api/v1/health         # {"status":"ok",...}
curl -s http://localhost:8000/api/v1/health/ready   # 200 ready, or 503 with failing checks
uv run --project backend cti diagnostic-job --steps 3   # prints {"job_id": ...}; the worker runs it
```

Readiness checks: database reachable, Alembic revision at head, upload and artifact directories writable. `GET /api/v1/jobs/{job_id}` (signed in) shows the job's status and progress.

## 8. Running tests

```bash
cd backend && uv run pytest          # unit + integration against CTI_TEST_DATABASE_URL
cd frontend && npm run test -- --run
```

If `CTI_TEST_DATABASE_URL` is unset, integration tests are **skipped** with a reason and unit tests still run. If it is set but the database is unreachable, integration tests **error** (deliberately not skipped, so a broken database is never mistaken for a pass). Full command list: [TESTING_STRATEGY.md §2](TESTING_STRATEGY.md#2-layout-and-commands).

## 9. Secret handling

- Generate strong values for the database password and `CTI_SECRET_KEY`; keep them only in `.env` (git-ignored) or a secret manager.
- `CTI_ENV=production` refuses to start with placeholder secrets.
- Rotating `CTI_SECRET_KEY` invalidates all sessions (users sign in again).
- Feed credentials (Phase 5) go in env vars referenced by name from the feed configuration; never in the database or UI.
- Never paste secrets into issues, logs, or chat transcripts.

## 10. Shutdown and reset

```bash
# stop the API, worker, and Vite with Ctrl+C, then:
pg_ctl -D .local/pgdata stop
```

Before any destructive reset, back up: `pg_dump -h localhost -U cti cti > backup.sql`. To reset only the test database: `dropdb -h localhost -U cti cti_test && createdb -h localhost -U cti cti_test` (the test suite also rebuilds its schema on every run).

## 11. Optional: Docker Compose (containerised verification)

> **Not yet verified.** These files were written in Phase 1 but have never been built or run. Do not treat any Docker result as passing until it has actually been executed.

```bash
docker compose up -d --build        # postgres:17, backend, worker, frontend
docker compose ps                   # all services should become "healthy"
docker compose exec backend alembic upgrade head
docker compose exec backend cti create-admin --username admin
docker compose run --rm backend uv run pytest     # tests against postgres:17 (cti_test)
docker compose down                 # keep volumes; `down -v` DELETES the database volume
```

| Service | Build | Command | Health check |
|---|---|---|---|
| `postgres` | `postgres:17` | default (init script creates `cti_test`) | `pg_isready` |
| `backend` | `./backend` | `uvicorn app.main:app --host 0.0.0.0 --port 8000` | `GET /api/v1/health` |
| `worker` | same image | `cti worker --heartbeat-file /tmp/cti-worker.beat` | `cti worker-healthcheck` |
| `frontend` | `./frontend` | `npm run dev -- --host 0.0.0.0` | HTTP 200 on `/` |

Compose builds its own database URLs from `POSTGRES_*` (host `postgres`), so the native `CTI_DATABASE_URL` in `.env` is not used inside containers. Stop a native PostgreSQL on port 5432 first, or change the published port.

## 12. Data import, ML, and threat intelligence (Phases 2–5, not yet implemented)

Target commands, run from the repository root:

```bash
uv run --project backend cti seed-reference
uv run --project backend cti generate-synthetic --scenario full --seed 42 --out data/samples/generated
uv run --project backend cti ingest --source synthetic --adapter canonical_jsonl data/samples/generated/events.jsonl
uv run --project backend cti ingest --source unsw-nb15 --adapter unsw_nb15 --variant partition \
  --assume-event-date 2015-01-22 data/external/unsw-nb15/UNSW_NB15_training-set.csv
uv run --project backend cti train classifier --config config/ml/classifier_default.toml --batch-id <uuid>
uv run --project backend cti train anomaly --config config/ml/anomaly_account_1h.toml
uv run --project backend cti ti-import --feed local-csv --format csv data/samples/generated/synthetic_indicators.csv
uv run --project backend cti correlate --from <ts> --to <ts>
```

Public datasets are downloaded manually (UNSW-NB15: <https://research.unsw.edu.au/projects/unsw-nb15-dataset>; CIC-IDS2017: <https://www.unb.ca/cic/datasets/ids-2017.html>) into `data/external/<dataset>/` (git-ignored), respecting their licence and citation terms. An assumed event date is a recorded assumption; such events are classification-only ([DATA_INGESTION.md §4](DATA_INGESTION.md#4-source-adapters)). Equivalent API endpoints return `202` with a job ID ([API_SPECIFICATION.md](API_SPECIFICATION.md#59-classification)).

## 13. Known operational limitations

- Single API process and single worker by default; no high availability.
- No TLS termination — intended for localhost or a trusted network only.
- Frontend runs via the Vite dev server; serving a production build is an open decision (OD-2).
- The native PostgreSQL cluster is started and stopped manually.
- Large dataset imports are CPU/disk bound; throughput will be measured in Phase 7, not assumed.
- Model artifacts are tied to library versions; upgrading scikit-learn may require retraining.

## 14. CLI reference (`cti`)

| Command | Purpose | Phase |
|---|---|---|
| `cti create-admin --username U [--password-stdin]` | Create first/additional admin. | 1 |
| `cti worker [--heartbeat-file F] [--once]` | Run the job worker (`--once`: run at most one job, then exit). | 1 |
| `cti worker-healthcheck --heartbeat-file F [--max-age-seconds N]` | Exit 0 if the worker heartbeat is fresh. | 1 |
| `cti diagnostic-job [--steps N] [--sleep-seconds S] [--fail] [--transient-failures N]` | Enqueue a `diagnostic` job that exercises the queue (success, failure, retry, progress). | 1 |
| `cti seed-reference` | Seed attack categories, default sources (`synthetic`, `cicids2017`, `unsw-nb15`), a local file feed (`local-csv`), default correlation rules, mappings (idempotent). | 2 |
| `cti ingest --source S --adapter A [--variant V] [--assume-event-date D] [--timezone TZ] PATH` | Import a file. | 2 |
| `cti assets-import PATH` | Import asset inventory. | 2 |
| `cti generate-synthetic --scenario N --seed S --out DIR` | Generate synthetic data + expected outcomes. | 2 |
| `cti train classifier\|anomaly --config FILE [...]` | Train models. | 3/4 |
| `cti score classifier\|anomaly [scope]` | Score events/windows. | 3/4 |
| `cti models list\|promote\|archive\|reject` | Registry operations. | 3 |
| `cti artifacts gc [--dry-run]` | Remove orphan artifact files. | 3 |
| `cti attack-import PATH` | Load ATT&CK STIX bundle. | 5 |
| `cti ti-import --feed F --format csv\|stix PATH` | Import indicators. | 5 |
| `cti match-indicators [scope]` | Indicator matching. | 5 |
| `cti correlate --from T --to T [--rule K]` | Correlation run. | 5 |
| `cti retention apply --dry-run\|--execute` | Apply retention policy (audited). | 7 |
| `cti watch` | Inbox-folder incremental ingestion. | 8 |
