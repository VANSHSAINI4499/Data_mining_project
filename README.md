# CTI Warehouse

**A Cyber Threat Intelligence data warehouse for attack-pattern classification, anomaly mining, and threat correlation.**

> **Status:** Phase 1 (foundation) of the [roadmap](IMPLEMENTATION_ROADMAP.md) is implemented: authentication and roles, the background job queue, health checks, migrations, and the dashboard shell. No security data features exist yet — ingestion arrives in Phase 2. It runs natively without Docker; the optional Docker Compose files have not yet been run.

## What it does

1. **Ingests and preserves** security events from CSV/JSON/JSONL files, Zeek and Suricata logs, authentication and endpoint events, and public datasets such as CIC-IDS2017 and UNSW-NB15 — keeping the raw record, provenance, and ingestion status.
2. **Normalises** them into a canonical event model stored in a PostgreSQL dimensional warehouse.
3. **Classifies** events into known attack categories with a supervised model (Random Forest, with baselines), evaluated with per-class metrics.
4. **Mines anomalies** in host, account, and network behaviour with Isolation Forest and statistical baselines.
5. **Enriches** events with optional threat-intelligence indicators and MITRE ATT&CK references.
6. **Correlates** related evidence into explainable, risk-scored alerts that analysts can promote to cases.
7. **Presents** results in an investigation dashboard backed entirely by real API data.

## Stack

React · TypeScript · Vite · Tailwind CSS · Recharts · TanStack Query · React Router — Python · FastAPI · Pydantic · SQLAlchemy · Alembic — PostgreSQL · pandas · NumPy · scikit-learn — Docker Compose · pytest · Vitest. Details and rationale: [TECH_STACK.md](TECH_STACK.md).

## Quick start (native, no Docker required)

```bash
cp .env.example .env                 # then set real secrets and database URLs
# PostgreSQL >= 17 running locally with databases cti and cti_test (DEPLOYMENT_GUIDE.md §4)
uv sync --project backend
uv run --project backend alembic -c backend/alembic.ini upgrade head
uv run --project backend cti create-admin --username admin
uv run --project backend uvicorn app.main:app --port 8000      # terminal 1
uv run --project backend cti worker                            # terminal 2
cd frontend && npm ci && npm run dev                           # terminal 3: http://localhost:5173
```

Docker Compose is optional (containerised verification only): see
[DEPLOYMENT_GUIDE.md §11](DEPLOYMENT_GUIDE.md#11-optional-docker-compose-containerised-verification).

## Documentation

| Start here | |
|---|---|
| [PROJECT_OVERVIEW.md](PROJECT_OVERVIEW.md) | Vision, goals, scope, requirements |
| [ARCHITECTURE.md](ARCHITECTURE.md) | System design and data flow |
| [IMPLEMENTATION_ROADMAP.md](IMPLEMENTATION_ROADMAP.md) | Phases 1–8 |
| [CLAUDE.md](CLAUDE.md) | Rules for AI-assisted development |

| Specifications | |
|---|---|
| [DATABASE_DESIGN.md](DATABASE_DESIGN.md) | Warehouse schema |
| [DATA_INGESTION.md](DATA_INGESTION.md) | Adapters and validation |
| [DATA_DICTIONARY.md](DATA_DICTIONARY.md) | Canonical fields |
| [ML_CLASSIFICATION.md](ML_CLASSIFICATION.md) | Supervised pipeline |
| [ANOMALY_DETECTION.md](ANOMALY_DETECTION.md) | Unsupervised pipeline |
| [THREAT_INTELLIGENCE.md](THREAT_INTELLIGENCE.md) | Indicators, feeds, ATT&CK |
| [ATTACK_CORRELATION.md](ATTACK_CORRELATION.md) | Rules, alerts, risk scores |
| [API_SPECIFICATION.md](API_SPECIFICATION.md) | REST API `/api/v1` |
| [FRONTEND_SPECIFICATION.md](FRONTEND_SPECIFICATION.md) | Dashboard |
| [SECURITY_REQUIREMENTS.md](SECURITY_REQUIREMENTS.md) | Security controls |

| Process | |
|---|---|
| [TECH_STACK.md](TECH_STACK.md) | Approved dependencies |
| [DEVELOPMENT_RULES.md](DEVELOPMENT_RULES.md) | Conventions and review checklist |
| [TESTING_STRATEGY.md](TESTING_STRATEGY.md) | Test types and commands |
| [ACCEPTANCE_CRITERIA.md](ACCEPTANCE_CRITERIA.md) | Measurable definition of done |
| [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md) | Setup and operations |
| [TROUBLESHOOTING.md](TROUBLESHOOTING.md) | Common problems |
| [docs/diagrams/](docs/diagrams/README.md) | Diagram conventions |
| [docs/decisions/](docs/decisions/README.md) | Architecture Decision Records |

## Important limitations

- Detection is not perfect. Classifiers only recognise the attack categories present in their training data, and results on one dataset do not transfer automatically to another network.
- Anomalies indicate *unusual* behaviour, not confirmed malicious activity.
- Threat-intelligence feeds are optional; no feeds or credentials are bundled.
- Public datasets are **not** included in the repository; you download them yourself under their own licences.

## Data and licensing

Use only public or synthetic data during development. Respect the licence and citation terms of any dataset you download. The project licence is an open decision (see [docs/decisions/README.md](docs/decisions/README.md#open-decisions)).
