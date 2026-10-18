# Release notes — MVP (end of Phase 7)

Date: 2026-10-15. Everything below was run on the development machine (Windows 11, native PostgreSQL 18.6). Docker was **not** run.

## Verification evidence

| Check | Command | Result |
|---|---|---|
| Fresh-clone walkthrough (AC-7.5, native path) | `git clone` → `.env` from `.env.example` (new databases `cti_fresh`, `cti_fresh_test`) → `uv sync`, `alembic upgrade head`, `cti seed-reference`, `cti create-admin`, `uvicorn`, `/health` + `/health/ready`, `cti diagnostic-job` + `cti worker --once`, `cti generate-synthetic`, `cti ingest`, `cti ti-import`, `cti match-indicators`, `cti correlate` | All succeeded (ready = 200; 1,582 events loaded; 34 indicator matches; 4 alerts — no classifier was trained in the clone, so the classification-based rules had no evidence). |
| Backend suite in the fresh clone | `uv run pytest` | 478 passed |
| Frontend in the fresh clone | `npm ci`, `npx vitest run`, `npm run build` | 63 passed; build succeeded |
| Python dependency audit (AC-7.4) | `uvx pip-audit --disable-pip --no-deps -r <uv export of uv.lock>` (147 packages) | No known vulnerabilities |
| JavaScript dependency audit (AC-7.4) | `npm audit --omit=dev` and `npm audit` | 0 vulnerabilities |
| Performance (AC-7.6) | see [PERFORMANCE.md](PERFORMANCE.md) | NFR-04 met; NFR-03 **not met** (899 rows/s vs 2,000 target) |
| Docker Compose (AC-1.2D) | — | **Not run** (Docker not available) |

## MVP release checklist

| MVP capability | Status |
|---|---|
| Starts locally with documented commands (Docker optional) | Met natively (walkthrough above). Docker path not run. |
| Initialises the database through migrations | Met. |
| Imports a compatible public security dataset | **Not verified**: adapters for CIC-IDS2017 and UNSW-NB15 exist and are tested on fixtures, but no public dataset was available (AC-2.8). |
| Validates, normalises, and preserves events | Met. |
| Queries historical data | Met. |
| Trains and evaluates a classifier | Met on synthetic data; AC-3.9 (public dataset) not run. |
| Scores anomalies | Met; AC-4.4 partly (Isolation Forest does not flag the planted anomaly on the small synthetic sample; robust z-score does). |
| Persists and reloads model artifacts | Met. |
| Matches configured threat indicators | Met. |
| Correlates related events with supporting evidence | Met; AC-5.5 partly (4 of 5 default rules fire on planted scenarios). |
| Displays real API-backed analytics | Met. |
| Handles invalid inputs and failures safely | Met (rate limits, headers, upload limits, authorization suite). |
| Passes the required tests | Met for native runs. |

**The MVP checklist is therefore not fully met (AC-7.9):** the public-dataset items require downloading UNSW-NB15 or CIC-IDS2017, and the Docker verification requires Docker.

## Known limitations

- Ingestion throughput: NFR-03 met at the median of three runs on 2026-10-18 (2,137 rows/s; one run 1,952 rows/s) on the synthetic file — see PERFORMANCE.md. Not measured on UNSW-NB15.
- Database role separation: implemented (`cti db grant-app-role`, DEPLOYMENT_GUIDE.md §4.1), but the end-to-end test with a real DML-only role was **not run** here because the development role lacks `CREATEROLE`; development still uses one role by default.
- Scheduling: `cti worker` queues incremental processing (matching, scoring incl. web payloads, correlation) every `CTI_SCHEDULE_PROCESSING_SECONDS` when there is work.
- Production frontend serving / TLS (open decision OD-2) is not decided; the frontend runs on the Vite dev server.
- TAXII polling is not implemented (Phase 8).
- Frontend gaps against the specification are listed in [FRONTEND_SPECIFICATION.md §11](../FRONTEND_SPECIFICATION.md#11-implementation-status-phase-6).
- Rate limits are per API process (in memory).
