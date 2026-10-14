# Technology Stack

This is the **approved default stack**. Adding, removing, or replacing a runtime dependency or infrastructure component requires the process in §9. Architecture context: [ARCHITECTURE.md](ARCHITECTURE.md).

## 1. Runtime baselines

| Component | Baseline | Notes |
|---|---|---|
| Python | 3.12.x | 3.13 allowed after all tests pass on it and an ADR records the switch. |
| Node.js | 24 LTS (Docker image, `.nvmrc`); ≥ 22.22 supported | `package.json` `engines` is `>=22.22` because React Router 8 requires it. Phase 1 was verified locally on Node 22.23. |
| PostgreSQL | 17 | Docker image `postgres:17`. Features used (declarative partitioning, `jsonb`, `inet`, `SKIP LOCKED`) exist in all supported versions ≥ 13; 17 is the reference. Phase 1 tests were run natively on PostgreSQL 18.6 (Scoop install) because Docker was unavailable; see [ADR-0009](docs/decisions/0009-phase-1-version-baseline.md). |
| Docker Engine / Desktop *(optional)* | with Compose v2 (`docker compose`) | Not required for development or tests; used only for containerised verification. |

Exact versions are fixed in `backend/uv.lock` and `frontend/package-lock.json` (locked in Phase 1, 2026-10-14). The "Line" columns below give the major lines actually locked; see [ADR-0009](docs/decisions/0009-phase-1-version-baseline.md) for where they differ from the original plan.

## 2. Frontend

| Library | Line | Why |
|---|---|---|
| React | 19 | Component model for the investigation dashboard. |
| TypeScript | 6.x, `strict: true` | Type-safe API contracts and components. |
| Vite | 8 | Fast dev server and production build; proxies `/api` in development. |
| Tailwind CSS | 4 | Utility styling with a small design-token set; no component framework lock-in. |
| Recharts | current major (installed in Phase 6) | Declarative charts (time series, bar, stacked bar, heatmap-like grids for confusion matrices). Not installed until a page needs it. |
| TanStack Query | v5 | Server-state caching, polling of job status, request de-duplication. |
| React Router | 8 (declarative mode: `BrowserRouter`/`Routes`) | Client-side routes listed in [FRONTEND_SPECIFICATION.md](FRONTEND_SPECIFICATION.md). Framework/SSR mode is **not** used. |

Supporting (approved, dev only): ESLint + `typescript-eslint` + `eslint-plugin-react-hooks` + `globals`, Prettier, `@types/node` (typing `vite.config.ts`), `@tanstack/react-query-devtools` (not yet installed).

## 3. Backend

| Library | Line | Why |
|---|---|---|
| FastAPI | 0.143 | Typed HTTP API with OpenAPI generation, dependency injection for auth/DB. |
| Pydantic | v2 | Request/response validation, canonical event models. |
| pydantic-settings | v2 | Environment-based configuration (`CTI_*` variables). |
| SQLAlchemy | 2.1 (typed ORM + Core) | Database access with parameterised queries; Core for bulk inserts and aggregates. |
| Alembic | current | Versioned schema migrations. |
| psycopg | 3.x (`psycopg[binary]`) | PostgreSQL driver for SQLAlchemy. |
| uvicorn | current | ASGI server. |
| python-multipart | current | Required by FastAPI for file uploads. |
| argon2-cffi | current | Password hashing. |
| httpx | current | FastAPI `TestClient` and optional TAXII/HTTP feed retrieval. |

The CLI uses the standard library `argparse`; configuration files use TOML read with the standard library `tomllib`. No YAML dependency.

## 4. Data and ML

| Library | Line | Why |
|---|---|---|
| PostgreSQL | 17 | Warehouse storage, partitioning, job queue. |
| pandas | ≥ 2.2 | Dataset loading in adapters, feature frames. |
| NumPy | ≥ 2.0 | Numerical arrays. |
| scikit-learn | ≥ 1.5 | `Pipeline`, `ColumnTransformer`, `RandomForestClassifier`, `LogisticRegression`, `DummyClassifier`, `IsolationForest`, `StratifiedGroupKFold`, metrics. |
| joblib | (bundled dependency of scikit-learn) | Model artifact persistence. Pickle-based: load only trusted artifacts ([SECURITY_REQUIREMENTS.md](SECURITY_REQUIREMENTS.md#9-ml-artifact-safety)). |

`skops` (a non-pickle persistence format for scikit-learn) is a **candidate alternative** — see open decisions in [docs/decisions/README.md](docs/decisions/README.md#open-decisions).

### Optional (behind extras, never required to run the MVP)

| Library | Extra | Use |
|---|---|---|
| `taxii2-client` | `[taxii]` | TAXII 2.1 collection polling ([THREAT_INTELLIGENCE.md](THREAT_INTELLIGENCE.md#8-stixtaxii-integration)). |

## 5. Optional processing

| Component | Status | Introduce only when |
|---|---|---|
| Redis | **Optional, not in MVP** | Celery is adopted, or a measured need for caching/rate-limit storage across multiple API processes exists. |
| Celery | **Optional, not in MVP** | The PostgreSQL job queue ([ARCHITECTURE.md](ARCHITECTURE.md#7-background-jobs)) is shown (measurements, not opinion) to be insufficient — e.g., scheduling, priorities, or throughput needs. Must keep the `enqueue()` interface. |

## 6. Infrastructure and testing

| Tool | Why |
|---|---|
| Docker, Docker Compose v2 *(optional)* | Containerised verification: `postgres`, `backend`, `worker`, `frontend`. The native setup is the primary path. |
| pytest, pytest-cov | Backend unit/integration tests and coverage. |
| ruff | Python lint + format. |
| mypy | Python static typing (`app/` strict on new modules). |
| Vitest | Frontend unit/component tests. |
| React Testing Library (+ `@testing-library/user-event`, `jsdom`) | Component behaviour tests. |
| MSW (Mock Service Worker) 3 | **Approved for frontend tests only** — mocks HTTP at the network layer. Never used in the running app. |

Browser E2E (Playwright) is **not** in the default stack; MVP E2E is API-level ([TESTING_STRATEGY.md](TESTING_STRATEGY.md#12-end-to-end-tests)). Adding Playwright requires an ADR.

## 7. Version management practices

- **Python:** `uv` manages the virtual environment and lockfile (`backend/pyproject.toml` + `backend/uv.lock`). Commit the lockfile. Use `uv sync` to install, `uv add <pkg>` to add (with ADR when required). Development dependencies are a PEP 735 dependency group (`[dependency-groups] dev`); the pip fallback is `pip install -e . --group dev` (pip ≥ 25.1).
- **Node:** `npm` with committed `package-lock.json`; use `npm ci` in Docker and CI.
- **Docker images:** pin major (and preferably minor) tags, e.g., `postgres:17`, `python:3.12-slim`, `node:24-alpine`. Never use `latest`.
- **Upgrades:** one dependency family per change; run the full test suite; note behaviour changes (especially scikit-learn, which can change model outputs and artifact compatibility) in the change description.
- **Model artifacts** record the exact scikit-learn, NumPy, pandas, and Python versions; loading under different versions logs a warning and is blocked for promotion ([ML_CLASSIFICATION.md](ML_CLASSIFICATION.md#10-model-persistence-and-versioning)).
- **Vulnerability checks:** `uv run pip-audit` (dev dependency) and `npm audit --omit=dev` in Phase 7 ([SECURITY_REQUIREMENTS.md](SECURITY_REQUIREMENTS.md#11-dependency-management)).

## 8. Alternatives considered

| Choice | Alternatives | Reason for default |
|---|---|---|
| PostgreSQL | DuckDB, ClickHouse, SQLite | Transactions, concurrency, partitioning, `inet`, mature migrations; one store for warehouse + app data. DuckDB may be revisited for offline analytics. |
| FastAPI | Django + DRF, Flask | Typed schemas, OpenAPI, async-capable, light. |
| PostgreSQL job table | Celery + Redis, RQ, Dramatiq | No extra infrastructure for the MVP. |
| scikit-learn | XGBoost, LightGBM, PyTorch | Sufficient for tabular baselines; interpretable; no GPU. Gradient boosting may be added later via ADR. |
| Recharts | ECharts, Nivo, D3 | React-native API, adequate chart set. |
| uv | pip-tools, Poetry | Fast, lockfile-based, standards-compliant `pyproject.toml`. |

## 9. Conditions for introducing new technology

A new runtime dependency or infrastructure component requires:

1. A concrete requirement from a spec file that the current stack cannot meet (with evidence: measurements, failing scenario, or missing capability).
2. An ADR in [docs/decisions/](docs/decisions/README.md) stating alternatives, licence, maintenance status, security impact, and removal cost.
3. Lockfile update, tests, and documentation updates in the same change.

**Not permitted in the MVP without an accepted ADR:** Kafka or other message brokers, Spark/Flink/Dask clusters, Kubernetes/Helm, vector databases, Elasticsearch/OpenSearch, graph databases, microservices, deep-learning frameworks, LLM APIs, UI component frameworks that replace Tailwind, GraphQL.

Development-only tools (linters, test helpers) still need a one-line justification in the change description but not an ADR.
