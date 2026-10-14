# API Specification — `/api/v1`

REST/JSON API served by FastAPI. The generated OpenAPI document (`/api/v1/openapi.json`, Swagger UI at `/api/v1/docs` in non-production modes) must agree with this file; when they differ, fix one of them in the same change ([DEVELOPMENT_RULES.md](DEVELOPMENT_RULES.md#10-api-contract-changes)).

## 1. Conventions

- **Base path:** `/api/v1`. All paths below are relative to it.
- **Content type:** `application/json; charset=utf-8`, except uploads (`multipart/form-data`) and errors (`application/problem+json`).
- **Timestamps:** RFC 3339 / ISO-8601 strings in UTC with `Z` (e.g., `2017-07-05T13:42:10Z`). Inputs without timezone are rejected (422).
- **IDs:** UUID strings for workflow entities (batch, job, model, run, alert, case, feed, rule); integers (serialised as JSON numbers; `event_id` serialised as **string** to avoid JavaScript precision loss) for high-volume rows.
- **Naming:** `snake_case` JSON fields; plural nouns for collections.
- **Asynchronous work** returns `202 Accepted` with `{ "job_id": "…", "status": "queued", "links": { "job": "/api/v1/jobs/{job_id}" } }`.
- **Result categories:** response objects that mix observed data and inferences group them under `observed`, `model_outputs`, `threat_intel`, `analyst` keys (see event detail) so clients cannot confuse them.
- **Request IDs:** every response carries `X-Request-ID` (echoes a valid client value or generates a UUID).

## 2. Authentication

- `POST /auth/login` with `{ "username", "password" }` → `200 { "user": {…}, "csrf_token": "…" }` and sets an `HttpOnly`, `SameSite=Strict` (`Secure` when `CTI_ENV=production`) cookie `cti_session` containing an opaque random token. The DB stores only a hash ([DATABASE_DESIGN.md](DATABASE_DESIGN.md#36-operations-and-security)).
- Session lifetime: `CTI_SESSION_TTL_MINUTES` (default 480) absolute; idle timeout 60 min.
- **CSRF:** state-changing requests (`POST`, `PUT`, `PATCH`, `DELETE`) must send header `X-CSRF-Token` matching the session's CSRF token; otherwise `403`.
- `POST /auth/logout` revokes the session. `GET /auth/me` returns the current user and role and **rotates** the session's CSRF token, returning the new value (the DB stores only its hash), so the SPA can recover the token after a page reload.
- Failed logins: generic `401` message; lockout after 10 consecutive failures for 15 min ([SECURITY_REQUIREMENTS.md](SECURITY_REQUIREMENTS.md#1-authentication)). A locked, inactive, or unknown account receives the **same** generic `401` (no enumeration); the reason is recorded only in the audit log. `429` is reserved for rate limiting (Phase 7).
- Unauthenticated endpoints: `GET /health`, `GET /health/ready`, `POST /auth/login`. Everything else requires a session.
- CLI commands run in-process with operator privileges and do not use HTTP auth; they are audited with `actor_type = cli`.

## 3. Authorization

Roles: `viewer` < `analyst` < `admin` (each includes the permissions of the previous). The column **Role** below is the minimum role. Full matrix and rationale: [SECURITY_REQUIREMENTS.md](SECURITY_REQUIREMENTS.md#2-role-based-authorization). Authorization is enforced by a FastAPI dependency on every router; a test asserts every route declares a minimum role ([TESTING_STRATEGY.md](TESTING_STRATEGY.md#10-authorization-tests)).

## 4. Errors

RFC 9457 problem details (<https://www.rfc-editor.org/rfc/rfc9457>, verified):

```json
{
  "type": "https://cti-warehouse.local/problems/validation-error",
  "title": "Request validation failed",
  "status": 422,
  "detail": "2 fields are invalid",
  "instance": "/api/v1/events",
  "request_id": "0b5e7c1e-…",
  "errors": [ { "field": "from", "code": "invalid_datetime", "message": "timezone required" } ]
}
```

The `type` URIs are identifiers and need not resolve.

| Status | Problem type slug | When |
|---|---|---|
| 400 | `bad-request` | Malformed request not covered by validation. |
| 401 | `unauthenticated` | Missing/expired session. |
| 403 | `forbidden` / `csrf-failed` | Role insufficient / CSRF token missing or wrong. |
| 404 | `not-found` | Resource absent. (Single-tenant MVP: 403 and 404 are reported truthfully; no existence hiding.) |
| 409 | `conflict` | Duplicate, invalid state transition, job already running. |
| 413 | `payload-too-large` | Upload over limit. |
| 415 | `unsupported-media-type` | Disallowed extension/content. |
| 422 | `validation-error` | Pydantic/semantic validation errors (`errors[]`). |
| 429 | `rate-limited` | Rate limit exceeded; `Retry-After` header. |
| 500 | `internal-error` | Unexpected; no stack trace; `request_id` for log lookup. |
| 503 | `not-ready` | Readiness failure (DB down, migrations behind). |

## 5. Endpoints

### 5.1 Health and readiness

| Method | Path | Role | Description |
|---|---|---|---|
| GET | `/health` | none | Liveness: `200 {"status":"ok","version":"<app version>"}`. No DB access. |
| GET | `/health/ready` | none | Readiness: checks DB connectivity, Alembic revision == head, artifact and upload dirs writable. `200 {"status":"ready","checks":{…}}` or `503` problem with per-check results. No secrets or connection strings in output. |

### 5.2 Auth and users

| Method | Path | Role | Description |
|---|---|---|---|
| POST | `/auth/login` | none | See §2. |
| POST | `/auth/logout` | viewer | Revoke session. |
| GET | `/auth/me` | viewer | Current user. |
| GET | `/users` | admin | List users. |
| POST | `/users` | admin | Create `{username, password, role}`; password policy enforced. |
| PATCH | `/users/{user_id}` | admin | Change role, activate/deactivate, reset password. Cannot demote the last admin (409). |

### 5.3 Jobs

| Method | Path | Role | Description |
|---|---|---|---|
| GET | `/jobs` | viewer | Filter `status`, `job_type`, `created_after`. |
| GET | `/jobs/{job_id}` | viewer | `{job_id, job_type, status, progress:{done,total,unit}, result, error:{code,message}, created_at, started_at, finished_at}`. |
| POST | `/jobs/{job_id}/cancel` | admin | Queued → `cancelled` immediately. Running → `cancel_requested = true`; the worker observes it at its next heartbeat and the handler stops at its next cancellation check. Terminal jobs → 409. |

### 5.4 Sources and adapters

| Method | Path | Role | Description |
|---|---|---|---|
| GET | `/adapters` | viewer | Supported adapters with name, version, extensions, event types, variants. |
| GET | `/sources` | viewer | List sources. |
| POST | `/sources` | admin | Create `{source_key, name, source_type, default_adapter, default_timezone, reliability, description}`. |
| GET | `/sources/{source_id}` | viewer | Detail + batch/event counts. |
| PATCH | `/sources/{source_id}` | admin | Update mutable fields; deactivate. |

### 5.5 Assets

| Method | Path | Role | Description |
|---|---|---|---|
| GET | `/assets` | viewer | Current assets; filter `criticality`, `q` (prefix on hostname/asset_id). |
| POST | `/assets/import` | admin | Upload an asset inventory CSV (≤ 10 MB). Processed synchronously → `200 {created, updated, unchanged, rejected[]}` (small files; no job). |

### 5.6 Uploads and ingestion

| Method | Path | Role | Description |
|---|---|---|---|
| POST | `/ingestion/uploads` | analyst | `multipart/form-data`: `file`, `source_id`, `adapter`, optional `assume_event_date`, `variant`. → `202 {batch_id, job_id}`; duplicate file → `200 {batch_id, status:"duplicate", duplicate_of}`; > limit → 413. |
| GET | `/ingestion/batches` | viewer | Filter `source_id`, `status`, `created_after/before`. |
| GET | `/ingestion/batches/{batch_id}` | viewer | Batch with counters, timing, encoding, timezone assumption, label mapping version, error summary, links to job and DQ. |
| GET | `/ingestion/batches/{batch_id}/rejections` | analyst | Paginated rejected records: `record_number`, `error_code`, `field_name`, sanitised `error_detail`. |
| POST | `/ingestion/batches/{batch_id}/retry` | analyst | Re-enqueue a `failed` batch (409 otherwise). |

Ingestion details: [DATA_INGESTION.md](DATA_INGESTION.md).

### 5.7 Security events

| Method | Path | Role | Description |
|---|---|---|---|
| GET | `/events` | viewer | Cursor-paginated list. Filters in §7. Returns summary fields + latest classification for the active model + `has_indicator_match` + `alert_count`. |
| GET | `/events/{event_id}?event_time=…` | viewer | Detail (event_time optional but enables partition pruning). |
| GET | `/events/{event_id}/raw` | analyst | Raw record (`raw_payload`/`raw_text`) as JSON data — never rendered. |

Event detail shape:

```json
{
  "event_id": "48213377",
  "observed": { "event_time": "…", "event_type": "network_flow", "src_ip": "192.0.2.10", "dst_ip": "198.51.100.7", "dst_port": 22, "protocol": "tcp", "bytes_out": 2048, "attributes": { } },
  "provenance": { "source": {…}, "batch_id": "…", "original_filename": "…", "file_sha256": "…", "record_number": 1532, "adapter_version": "…", "time_quality": "second", "timezone_assumption": "UTC" },
  "ground_truth": { "label_raw": "SSH-Patator", "attack_category": "BRUTE_FORCE", "mapping_status": "mapped", "label_mapping_version": "cicids2017@1" },
  "model_outputs": { "classifications": [ { "model": {"name":"attack_classifier","version":3,"status":"active"}, "predicted_category": "BRUTE_FORCE", "predicted_score": 0.83, "score_is_calibrated": false } ], "anomaly_windows": [ … ] },
  "threat_intel": { "matches": [ … ], "attack_techniques": [ { "technique_id": "T1110", "via": "predicted_category", "mapping_confidence": "high" } ] },
  "alerts": [ { "alert_id": "…", "status": "new", "risk_score": 68 } ],
  "analyst": { "feedback": [ … ] }
}
```

### 5.8 Historical aggregations

All aggregations take a mandatory time range (`from`, `to`, max span `CTI_MAX_AGG_DAYS`, default 400 days) plus the event filters in §7.

| Method | Path | Role | Description |
|---|---|---|---|
| GET | `/analytics/timeseries` | viewer | `interval` ∈ {`hour`,`day`,`week`}; `metric` ∈ {`event_count`,`bytes_total`}; optional `group_by` ∈ {`event_type`,`source`,`ground_truth_category`,`predicted_category`} (top 10 + `other`). Returns `{interval, buckets:[{ts, series:{key:value}}]}`. |
| GET | `/analytics/top-entities` | viewer | `dimension` ∈ {`src_ip`,`dst_ip`,`dst_port`,`user_name`,`host_name`,`signature`}; `limit` ≤ 50. |
| GET | `/analytics/distribution` | viewer | `dimension` ∈ {`event_type`,`protocol`,`ground_truth_category`,`predicted_category`,`source`}. |

Only these enumerated dimensions/metrics are accepted; there is **no** arbitrary query, SQL, or expression endpoint.

### 5.9 Classification

| Method | Path | Role | Description |
|---|---|---|---|
| POST | `/classification/training-runs` | admin | Body: config (validated subset of [ML config](ML_CLASSIFICATION.md#14-configuration-example)) with `snapshot.batch_ids`. → 202 job. |
| GET | `/classification/training-runs` | viewer | List runs. |
| GET | `/classification/training-runs/{run_id}` | viewer | Status, snapshot, config, per-model metrics (per-class P/R/F1/support, macro-F1, weighted-F1, confusion matrix with class order, CIs, permutation importance), leakage checks, data report. |
| POST | `/classification/training-runs/{run_id}/acknowledge-warnings` | admin | `{note}` acknowledges leakage warnings (audited). |
| POST | `/classification/scoring-runs` | analyst | `{batch_ids}` or `{from, to, source_id?}`, optional `model_id` → 202 job. |
| GET | `/classification/results` | viewer | Cursor-paginated predictions; filters `model_id`, `predicted_category`, `min_score`, time range, `disagrees_with_ground_truth`. |
| GET | `/classification/summary` | viewer | For a `model_id` (default active): prediction counts per category over a time range; if ground truth exists for the scored scope, the live confusion matrix for that scope (labelled as such). |

### 5.10 Anomaly detection

| Method | Path | Role | Description |
|---|---|---|---|
| POST | `/anomalies/training-runs` | admin | Anomaly model config → 202 job. |
| GET | `/anomalies/training-runs/{run_id}` | viewer | Reference period, score distribution summary, threshold report (incl. proxy evaluation if labels exist). |
| POST | `/anomalies/scoring-runs` | analyst | `{model_id?, from, to}` → 202 job. |
| GET | `/anomalies` | viewer | Cursor-paginated results; filters `entity_type`, `entity_value`, `is_flagged` (default true), `min_percentile`, `model_id`, time range. |
| GET | `/anomalies/{result_id}` | viewer | Detail with features, baseline, history, top deviations, linked events link ([ANOMALY_DETECTION.md](ANOMALY_DETECTION.md#7-historical-comparisons)). |

### 5.11 Model registry

| Method | Path | Role | Description |
|---|---|---|---|
| GET | `/models` | viewer | Filter `task`, `name`, `status`. |
| GET | `/models/{model_id}` | viewer | Manifest, training run link, metrics summary, promotion history. |
| POST | `/models/{model_id}/promote` | admin | Runs the promotion gate; 409 with failed gate items if not met. |
| POST | `/models/{model_id}/archive` | admin | Active model cannot be archived without promoting another (409). |
| POST | `/models/{model_id}/reject` | admin | `{reason}`. |

There is **no** endpoint to upload model artifacts.

### 5.12 Threat intelligence and ATT&CK

| Method | Path | Role | Description |
|---|---|---|---|
| GET | `/threat-intel/feeds` | viewer | Feeds with health. |
| POST | `/threat-intel/feeds` | admin | Create feed (`credentials_ref` is an env var **name**). |
| PATCH | `/threat-intel/feeds/{feed_id}` | admin | Update / enable / disable. |
| POST | `/threat-intel/feeds/{feed_id}/sync` | admin | Planned → 202 job. **Current build:** TAXII polling is not implemented, so this returns 409 with a pointer to file imports (deferred to Phase 8). |
| POST | `/threat-intel/imports` | admin | Upload CSV or STIX 2.1 bundle `{file, feed_id, format}` → 202 job. |
| GET | `/threat-intel/imports/{feed_run_id}` | viewer | Import run status and report: counts received/created/updated/rejected, rejected rows, unsupported STIX patterns. |
| GET | `/threat-intel/indicators` | viewer | Filters `indicator_type`, `feed_id`, `state` (`active`/`expired`/`revoked`), `min_confidence`, `value` (exact normalised). Values returned raw and `display_value` defanged. |
| POST | `/threat-intel/indicators` | admin | Manual indicator. |
| GET | `/threat-intel/indicators/{indicator_id}` | viewer | Detail + version history + match count. |
| PATCH | `/threat-intel/indicators/{indicator_id}` | admin | Change confidence/validity/revoke (creates version). |
| POST | `/threat-intel/match-runs` | analyst | `{batch_ids}` or `{from, to}`, plus `include_expired` → 202 job. |
| GET | `/threat-intel/matches` | viewer | Cursor-paginated matches; filters `indicator_id`, `state`, time range. |
| GET | `/attack/techniques` | viewer | Imported techniques; filter `tactic`, `q`. |
| GET | `/attack/categories` | viewer | Canonical categories with technique mappings, confidence, rationale. |

### 5.13 Correlation rules and runs

| Method | Path | Role | Description |
|---|---|---|---|
| GET | `/correlation/rules` | viewer | Latest version of each rule + enabled flag. |
| GET | `/correlation/rules/{rule_key}/versions` | viewer | Version history. |
| POST | `/correlation/rules` | admin | Create rule (validated DSL). |
| PUT | `/correlation/rules/{rule_key}` | admin | New version. |
| PATCH | `/correlation/rules/{rule_key}` | admin | `{enabled}` only. |
| POST | `/correlation/runs` | analyst | `{from, to, rule_keys?}` → 202 job. |

### 5.14 Alerts and cases

| Method | Path | Role | Description |
|---|---|---|---|
| GET | `/alerts` | viewer | Filters `status`, `rule_key`, `min_risk`, `entity_type`, `entity_value`, time range, `assigned_to`. Sort `risk_score` (default) or `last_event_time`. |
| GET | `/alerts/{alert_id}` | viewer | Rule version, risk breakdown, evidence (paginated) with category tags, timeline, linked case, feedback. |
| PATCH | `/alerts/{alert_id}` | analyst | `{status, assigned_to, dismiss_reason}`; invalid transitions → 409. |
| POST | `/alerts/{alert_id}/escalate` | analyst | `{case_id?}` or `{new_case:{title, severity}}`. |
| GET | `/cases` | viewer | Filters `status`, `disposition`, `assigned_to`. |
| POST | `/cases` | analyst | Create case. |
| GET | `/cases/{case_id}` | viewer | Case + linked alerts. |
| PATCH | `/cases/{case_id}` | analyst | Status, assignee, severity, summary; closing requires `disposition`. |
| GET | `/cases/{case_id}/timeline` | viewer | Ordered entries. |
| POST | `/cases/{case_id}/notes` | analyst | `{body}` plain text ≤ 10,000 chars. |
| POST | `/cases/{case_id}/alerts` | analyst | Link alert. |

### 5.15 Feedback

| Method | Path | Role | Description |
|---|---|---|---|
| POST | `/feedback` | analyst | `{target_type, target_id, verdict, corrected_category?, comment?}`; target existence validated. |
| GET | `/feedback` | viewer | Filters `target_type`, `target_id`, `verdict`, `analyst_id`. |
| GET | `/feedback/summary` | viewer | Verdict counts per rule, per model, per anomaly model. |

### 5.16 Dashboard analytics

| Method | Path | Role | Description |
|---|---|---|---|
| GET | `/dashboard/overview?from&to` | viewer | One payload for the overview page: event totals by type, ingestion batches by status, active models (name/version/key test metrics with dataset named), open alerts by severity, flagged anomaly count, active indicator count + match count, data-quality failures. Each section includes `as_of` and `is_empty`. Computed from DB at request time (or from materialised aggregates later); never cached fake values. |

### 5.17 Data quality

| Method | Path | Role | Description |
|---|---|---|---|
| GET | `/data-quality/summary` | viewer | Check status counts per source over time range; latest failures. |
| GET | `/data-quality/batches/{batch_id}` | viewer | All `data_quality_result` rows for a batch. |

### 5.18 Audit records

| Method | Path | Role | Description |
|---|---|---|---|
| GET | `/audit-records` | admin | Cursor-paginated; filters `actor_user_id`, `action`, `target_type`, `target_id`, `outcome`, time range. Read-only; no write/delete endpoints exist. |

## 6. Pagination

- **Cursor pagination** on all list endpoints: query `limit` (default 50, max 500) and `cursor` (opaque, base64url of the last sort key, e.g., `(event_time, event_id)`).
- Response envelope:

```json
{ "items": [ … ], "next_cursor": "eyJ0IjoiMjAx…", "limit": 50 }
```

- `next_cursor` is `null` on the last page. Total counts are not returned by default; endpoints where an exact count is cheap may return `total` explicitly documented above (e.g., batch rejections). The UI never invents totals.
- Sorting is restricted to documented keys per endpoint.

## 7. Event filters

`from`, `to` (required for `/events`; max span `CTI_MAX_QUERY_DAYS`, default 400 days), `source_id[]`, `batch_id`, `event_type[]`, `src_ip`, `dst_ip` (exact; CIDR filter is future work), `ip` (either side), `dst_port`, `protocol`, `user_name`, `host_name`, `signature_id`, `ground_truth_category[]`, `predicted_category[]`, `min_predicted_score`, `has_indicator_match`, `has_alert`, `time_quality`.

All filters are typed and validated; values are bound parameters. Unknown query parameters → 422.

## 8. Rate limiting

In-process limits (single API process in the MVP; see [SECURITY_REQUIREMENTS.md](SECURITY_REQUIREMENTS.md#8-rate-limiting)): login 10/min per IP+username; uploads 10/min per user; job-starting endpoints 30/min per user; other endpoints 600/min per user. Exceeding → 429 with `Retry-After`.

## 9. Explicit restrictions

- No endpoint executes caller-supplied SQL, expressions, regex, templates, or code.
- No synchronous training or bulk scoring in request handlers; such endpoints always return 202 + job.
- No endpoint fetches a caller-supplied URL (feed URLs are admin configuration used only by the worker, validated to `https`).
- No model-artifact or code upload.
- Response sizes are bounded by pagination limits and aggregation caps.

## 10. Versioning

- Breaking changes (removing/renaming fields, changing types or semantics) require `/api/v2` or a deprecation period documented here; additive changes are allowed in `/api/v1`.
- Frontend types in `frontend/src/api/types.ts` are updated in the same change as backend schemas.

## 11. Implementation status

| Group | Status |
|---|---|
| §5.1–§5.3 health, auth, users, jobs | Implemented (Phase 1). |
| §5.4 adapters & sources, §5.5 assets, §5.6 uploads & batches, §5.17 data quality | Implemented (Phase 2). Upload endpoints also return `411` without `Content-Length`; the limit is enforced before the multipart body is parsed. |
| §5.7 events, §5.8 aggregations | Implemented (Phase 2) with the filters available so far (`predicted_category`, `min_predicted_score`, `has_indicator_match`, `has_alert` arrive with the phases that create that data and are rejected as unknown parameters until then). Event detail currently returns `observed`, `provenance`, and `ground_truth`; `model_outputs`, `threat_intel`, `alerts`, and `analyst` keys are added by later phases. |
| §5.9 classification, §5.11 model registry | Implemented (Phase 3), plus `GET /classification/scoring-runs/{id}`. Training configs are validated strictly (unknown keys → 422). Promotion returns `409` with `gate_problems` when the gate is not met. Event search accepts `predicted_category` and `min_predicted_score` (active `attack_classifier`; 422 if none is active) and event detail includes `model_outputs.classifications`. |
| §5.10 anomaly detection | Implemented (Phase 4). `GET /anomalies` defaults to `is_flagged=true` and is ordered by score; every result carries `score_is_probability: false` and an interpretation note. Detail includes features, baseline, deviations, history, seasonal comparison, and a ready-made `linked_events` query. |
| §5.12 onwards | Later phases. |
