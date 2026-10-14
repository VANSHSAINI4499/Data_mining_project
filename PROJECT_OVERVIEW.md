# Project Overview — CTI Warehouse

## 1. Vision

Give a small security team or a security-analytics student a single, reproducible platform where raw security telemetry becomes **explainable investigative evidence**: events are preserved with provenance, classified against known attack patterns, checked for unusual behaviour, enriched with threat intelligence, and correlated into alerts an analyst can review — with every number traceable back to stored data.

## 2. Problem statement

Security data arrives in many formats (flow exports, IDS alerts, authentication logs, endpoint telemetry, threat feeds). Typical student or small-team setups have these problems:

- Data is analysed in ad-hoc notebooks and is not preserved, versioned, or queryable historically.
- ML results on public IDS datasets are frequently inflated by leakage (duplicates across splits, identifier features, preprocessing fitted on test data) and reported with accuracy alone.
- Model predictions, anomaly scores, and analyst conclusions are mixed together, so it is unclear what was observed versus inferred.
- Threat intelligence and detection outputs are not connected to the events that triggered them.

CTI Warehouse addresses these with a dimensional warehouse, reproducible ML pipelines, separate storage of facts vs. predictions vs. conclusions, and transparent correlation.

## 3. Goals

| ID | Goal |
|---|---|
| G1 | Ingest heterogeneous security data safely, idempotently, and with full provenance. |
| G2 | Store normalised events in a queryable historical warehouse while preserving raw records. |
| G3 | Train, evaluate, version, and apply a supervised attack classifier with honest, leakage-aware metrics. |
| G4 | Detect unusual host, account, and network behaviour with unsupervised methods and explain scores. |
| G5 | Enrich events with optional threat intelligence and MITRE ATT&CK references. |
| G6 | Correlate related evidence into deduplicated, risk-scored alerts with visible supporting evidence. |
| G7 | Support analyst review: alerts → cases → feedback, with an audit trail. |
| G8 | Provide a dashboard where every displayed metric is backed by real API data. |
| G9 | Be runnable locally by one developer with documented commands and no external credentials. |

## 4. Non-goals

- Not a production SIEM, SOAR, or EDR replacement; no real-time sub-second detection guarantees.
- No packet capture or live network sniffing; inputs are files or optional feeds.
- No automated response actions (blocking, quarantining, ticket creation in external systems).
- No deep-learning models, LLM-based triage, or vector search in the MVP.
- No distributed infrastructure (Kafka, Spark, Kubernetes) in the MVP.
- No claim of detecting attack categories absent from training data.
- No active interaction with indicators (no visiting URLs, resolving domains, or downloading samples).

## 5. Expected users

| Role | Needs | System role ([RBAC](SECURITY_REQUIREMENTS.md#2-role-based-authorization)) |
|---|---|---|
| SOC / security analyst | Explore events, triage alerts, open cases, record feedback | `analyst` |
| Data / ML engineer | Ingest datasets, train and promote models, review metrics | `admin` (MVP) |
| Platform administrator | Manage users, sources, feeds, correlation rules, audit | `admin` |
| Instructor / reviewer / manager | Read-only dashboards and reports | `viewer` |

## 6. Core user workflows

1. **Ingest a dataset** — select or create a source, upload a file (≤ the upload limit) or use the CLI for large datasets, watch batch status, review rejected records and data-quality results.
2. **Explore history** — filter events by time, source, entity, type, label, prediction; view an event's raw record, normalised fields, labels, predictions, anomaly context, indicator matches, and related alerts.
3. **Train and evaluate a classifier** — choose a dataset snapshot and configuration, start a background training job, inspect per-class metrics and confusion matrix, promote a candidate model to active.
4. **Score anomalies** — build entity-window features, train/score an anomaly model, explore flagged windows with baseline comparisons.
5. **Manage threat intelligence** — import indicators (manual, CSV, STIX 2.1 bundle, optional TAXII), run matching, review matches.
6. **Investigate** — review correlated alerts with risk-score breakdown and evidence timeline, promote an alert to a case, add notes, set disposition, record feedback.
7. **Audit** — see who did what and when.

## 7. Functional requirements

| ID | Requirement | Spec |
|---|---|---|
| FR-01 | Upload files (CSV, JSON, JSONL, Zeek TSV/JSON, Suricata EVE JSON) through the API and the CLI. | [DATA_INGESTION.md](DATA_INGESTION.md) |
| FR-02 | Preserve every raw record with batch, source, file hash, and line number. | [DATABASE_DESIGN.md](DATABASE_DESIGN.md) |
| FR-03 | Validate and normalise records into canonical events; quarantine invalid records with reasons. | [DATA_INGESTION.md](DATA_INGESTION.md), [DATA_DICTIONARY.md](DATA_DICTIONARY.md) |
| FR-04 | Deduplicate idempotently across re-imports. | [DATA_INGESTION.md](DATA_INGESTION.md#6-deduplication-and-idempotency) |
| FR-05 | Query events and historical aggregations with filters and pagination. | [API_SPECIFICATION.md](API_SPECIFICATION.md) |
| FR-06 | Train, evaluate, persist, version, promote, and apply a supervised classifier. | [ML_CLASSIFICATION.md](ML_CLASSIFICATION.md) |
| FR-07 | Build entity-window features, score anomalies, and explain them against baselines. | [ANOMALY_DETECTION.md](ANOMALY_DETECTION.md) |
| FR-08 | Manage indicators with provenance, confidence, and expiry; exact-match them against events. | [THREAT_INTELLIGENCE.md](THREAT_INTELLIGENCE.md) |
| FR-09 | Map attack categories to MITRE ATT&CK techniques with documented rationale. | [THREAT_INTELLIGENCE.md](THREAT_INTELLIGENCE.md#9-mitre-attck-references) |
| FR-10 | Correlate evidence with configurable rules into deduplicated, risk-scored alerts. | [ATTACK_CORRELATION.md](ATTACK_CORRELATION.md) |
| FR-11 | Manage alerts, cases, timelines, and analyst feedback. | [ATTACK_CORRELATION.md](ATTACK_CORRELATION.md#8-analyst-review-workflow) |
| FR-12 | Show dashboards for overview, ingestion, events, classification, anomalies, TI, investigations, models, data quality, settings, audit. | [FRONTEND_SPECIFICATION.md](FRONTEND_SPECIFICATION.md) |
| FR-13 | Authenticate users and enforce role-based access. | [SECURITY_REQUIREMENTS.md](SECURITY_REQUIREMENTS.md) |
| FR-14 | Record audit entries for state-changing actions. | [DATABASE_DESIGN.md](DATABASE_DESIGN.md#36-operations-and-security) |

## 8. Non-functional requirements

| ID | Requirement | Target (MVP, single developer laptop) |
|---|---|---|
| NFR-01 Reproducibility | Same data snapshot + config + seed + library versions → same model metrics. | Exact equality on the same platform. |
| NFR-02 Traceability | Any displayed metric, prediction, or alert traceable to stored rows. | 100 % of dashboard widgets. |
| NFR-03 Performance — ingestion | CLI ingest of the full UNSW-NB15 training partition (≈175k rows). | Completes; throughput recorded, target ≥ 2,000 rows/s (to be measured, not assumed). |
| NFR-04 Performance — API | Paginated event queries on ≈3M events with indexed filters. | p95 < 1 s on a laptop (to be measured). |
| NFR-05 Safety | Untrusted input never executed or fetched. | Enforced by tests ([SECURITY_REQUIREMENTS.md](SECURITY_REQUIREMENTS.md)). |
| NFR-06 Portability | Runs natively (PostgreSQL + Python + Node.js) on Linux, macOS, Windows; Docker Compose optional. | Native path verified on Windows; Docker path documented. |
| NFR-07 Maintainability | Lint, type check, and tests run in CI-equivalent commands. | All required tests pass per phase. |
| NFR-08 Usability | Honest loading, empty, and error states. | All pages. |

Performance targets are goals to measure in Phase 7; they must be reported as measured values, never assumed.

## 9. MVP scope (Phases 1–7)

- Native local stack: PostgreSQL, backend API, background worker, frontend dev server (optional Docker Compose files for containerised verification).
- Local authentication with roles `viewer`, `analyst`, `admin`.
- Ingestion adapters: canonical CSV/JSON/JSONL, CIC-IDS2017, UNSW-NB15, Zeek `conn.log`, Suricata EVE, auth JSONL, endpoint JSONL.
- Warehouse schema with raw preservation, dimensions, facts, data-quality results.
- Supervised classification: Dummy and Logistic Regression baselines, Random Forest primary model, model registry.
- Anomaly mining: robust z-score baseline and Isolation Forest on entity windows.
- Threat intelligence: manual, CSV, and STIX 2.1 file import; exact matching; ATT&CK technique import and category mapping.
- Correlation: rule engine with five default rules, alert dedup, transparent risk score, cases, feedback.
- Dashboard covering all pages in [FRONTEND_SPECIFICATION.md](FRONTEND_SPECIFICATION.md).

## 10. Advanced features (Phase 8 and later — **future work**)

- Temporal / sequential pattern mining across entity event sequences.
- Incremental ingestion (watch folder, scheduled feeds) and incremental scoring with watermarks.
- Concept-drift monitoring and retraining recommendations.
- Optional TAXII 2.1 polling (designed in Phase 5, may be completed in Phase 8).
- Optional Redis + Celery job execution if the PostgreSQL job queue proves insufficient (requires ADR).
- CIDR / wildcard indicator matching, external SSO, PDF report export.

## 11. Constraints

- Single developer laptop as the reference environment (assume 16 GB RAM, 4+ cores).
- No paid services or external credentials required.
- Public datasets downloaded manually by the user; never committed.
- Approved stack only ([TECH_STACK.md](TECH_STACK.md)).

## 12. Assumptions

- **A1:** Users can install Python 3.12, uv, Node.js ≥ 22.22, and PostgreSQL ≥ 17 natively (Docker is optional).
- **A2:** Datasets are labelled at the flow/record level with dataset-specific conventions that must be mapped ([ML_CLASSIFICATION.md](ML_CLASSIFICATION.md#3-label-mapping)).
- **A3:** Timestamps without timezone are interpreted per source configuration (default UTC) and that choice is recorded.
- **A4:** The deployment is single-tenant and trusted-network; internet exposure is out of scope for the MVP.

## 13. Unresolved decisions

Tracked in [docs/decisions/README.md](docs/decisions/README.md#open-decisions).
