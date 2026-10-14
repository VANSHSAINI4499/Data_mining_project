# Security Requirements

CTI Warehouse processes **untrusted, potentially hostile data** (attack traffic logs, IDS signatures, threat indicators, command lines). Every requirement here is testable; tests are listed in [TESTING_STRATEGY.md](TESTING_STRATEGY.md). Deployment assumption for the MVP: single tenant, trusted local network, not exposed to the internet ([PROJECT_OVERVIEW.md](PROJECT_OVERVIEW.md#12-assumptions)).

## 1. Authentication

- Local accounts; passwords hashed with **argon2id** (`argon2-cffi` defaults or stronger). Minimum length 12; reject the username as password and a small built-in list of common passwords.
- Opaque session tokens (≥ 256 bits from `secrets`), stored **hashed** (HMAC-SHA-256 keyed with `CTI_SECRET_KEY`) in `auth_session`; cookie `cti_session` is `HttpOnly`, `SameSite=Strict`, `Path=/api`, `Secure` in production.
- Absolute session lifetime 8 h (configurable), idle timeout 60 min; logout and user deactivation revoke sessions immediately.
- CSRF protection via `X-CSRF-Token` on state-changing requests ([API_SPECIFICATION.md](API_SPECIFICATION.md#2-authentication)).
- Lockout after 10 consecutive failures for 15 min; generic error messages (no user enumeration); all logins (success/failure) audited.
- First admin is created with `cti create-admin` (interactive password prompt or `--password-stdin`); there are **no default credentials** anywhere.
- External SSO/OIDC is future work (ADR required).

## 2. Role-based authorization

| Capability | viewer | analyst | admin |
|---|:-:|:-:|:-:|
| Read dashboards, events, results, alerts, cases, models, indicators | ✓ | ✓ | ✓ |
| View raw records and rejected-record details | | ✓ | ✓ |
| Upload event files; retry batches | | ✓ | ✓ |
| Start scoring, matching, correlation runs | | ✓ | ✓ |
| Change alert status, escalate, manage cases, add notes, submit feedback | | ✓ | ✓ |
| Train models, promote/archive/reject models, acknowledge leakage warnings | | | ✓ |
| Manage sources, assets, feeds, indicators, correlation rules | | | ✓ |
| Manage users; view audit records; run retention | | | ✓ |

- Enforced server-side by a dependency on every route (`require_role("analyst")`); route registration fails in tests if a route lacks a declared role (except health/login).
- Default deny: unknown roles have no permissions.
- The last active admin cannot be demoted or deactivated.

## 3. Secrets management

- Secrets only via environment variables or Docker secrets: `CTI_SECRET_KEY`, `POSTGRES_PASSWORD`/`CTI_DATABASE_URL`, optional feed credentials referenced by name (`credentials_ref`).
- `.env` is git-ignored; `.env.example` contains names and safe placeholders only (e.g., `change-me`).
- Startup fails in `CTI_ENV=production` if any secret equals a placeholder or `CTI_SECRET_KEY` is shorter than 32 bytes.
- Secrets never appear in logs, API responses, audit `details`, error messages, model manifests, or the readiness endpoint. Logging uses a redaction filter for keys matching `password|secret|token|key|authorization|cookie`.
- The database stores feed credential **references**, never credential values.

## 4. Upload validation and safe parsing

Based on the OWASP File Upload Cheat Sheet (<https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html>, verified):

- Authenticated, authorised (analyst+) and CSRF-protected.
- Extension allowlist (`.csv .tsv .log .json .jsonl .ndjson`); content sniff rejects binary content (NUL bytes in first 8 KiB) and obvious format mismatch.
- Size limit enforced while streaming (`CTI_MAX_UPLOAD_MB`, default 50) — the server stops reading and returns 413; reverse proxy limit set to the same value in production builds.
- Server-generated filenames under `CTI_UPLOAD_DIR` (outside any web-served directory); original name stored as text only; path traversal impossible by construction (no user input in paths).
- No archives/compressed files in the MVP (decompression bombs).
- Parsing limits per record (size, field count, nesting depth) and rejection-ratio cut-off ([DATA_INGESTION.md](DATA_INGESTION.md#3-upload-limits-and-safe-parsing)).
- Parsers: standard `csv`/`json` and pandas with string dtypes. Forbidden on untrusted input: `eval`, `exec`, `pickle`/`joblib.load`, `yaml.load`, `subprocess`, shell, template engines, XML parsers without hardened settings (no XML formats are accepted in the MVP).
- CLI imports are restricted to paths under `CTI_IMPORT_ROOT` (resolved real path check, symlinks resolved).

## 5. Safe handling of untrusted logs and indicators

- **Never execute** uploaded content, embedded commands, command lines, scripts, macros, or file paths found in logs.
- **Never fetch or resolve** URLs, domains, or IPs from events or indicators (no HTTP requests, DNS lookups, WHOIS, screenshots, sandbox submissions). The only outbound network calls are admin-configured TI feed endpoints (optional), made by the worker over HTTPS.
- Untrusted strings are stored as data, bound as SQL parameters, logged only in truncated and escaped form, and rendered in the UI as text (React escaping; no `dangerouslySetInnerHTML`; no Markdown/HTML rendering of log or user content). URLs/domains displayed defanged and non-clickable.
- CSV exports (if added) neutralise formula injection by prefixing cells starting with `= + - @ \t \r` with `'`.
- Log lines include record numbers and error codes, not full raw payloads.
- STIX patterns are parsed by a restricted tokenizer; unsupported constructs are stored, never evaluated ([THREAT_INTELLIGENCE.md](THREAT_INTELLIGENCE.md#8-stixtaxii-integration)).

## 6. SQL injection prevention

- All queries via SQLAlchemy Core/ORM with bound parameters. `text()` is allowed only with bound parameters and static SQL (e.g., partition functions in migrations), reviewed explicitly.
- Dynamic identifiers (sort keys, group-by dimensions, aggregation metrics) come from **allowlisted enums** mapped to column objects — never string-interpolated.
- No endpoint accepts SQL, expressions, or arbitrary filter DSL; correlation rules use an allowlisted DSL compiled to SQLAlchemy ([ATTACK_CORRELATION.md](ATTACK_CORRELATION.md#3-rule-definition)).
- The application DB role is not a superuser; in production it lacks DDL rights (migrations run with a separate migration role) and lacks `UPDATE`/`DELETE` on `audit_log`.

## 7. Audit logging

- Every state-changing action writes an `audit_log` row in the **same transaction** as the change: login/logout/failed login, user/role changes, source/feed/rule/asset changes, uploads, batch retries, training/scoring/matching/correlation job starts, model promotion/archive/reject, leakage acknowledgements, alert/case transitions, notes, feedback, retention runs, CLI operations (`actor_type = cli`).
- Authorization denials on state-changing endpoints are audited with `outcome = denied`.
- `details` contains identifiers and changed field names/old→new values for configuration; never secrets or raw payloads.
- Audit records are read-only through the API (admin) and append-only in the DB.

## 8. Rate limiting

- In-process token-bucket limiter (MVP has a single API process): limits listed in [API_SPECIFICATION.md](API_SPECIFICATION.md#8-rate-limiting). Implemented in Phase 7 (`app/core/ratelimit.py`, `RateLimitMiddleware`): authenticated requests are keyed by session (a hash of the session cookie), anonymous requests by client IP; login is keyed by client IP + username. Health endpoints are not limited. Each API process has its own buckets.
- If multiple API processes are introduced, limits move to a shared store (Redis, via ADR).
- Job concurrency limits: at most `CTI_MAX_CONCURRENT_JOBS` (default 2) running per worker; training jobs at most 1 concurrently.

## 9. ML artifact safety

- joblib/pickle can execute arbitrary code on load (scikit-learn model persistence docs: <https://scikit-learn.org/stable/model_persistence.html>, verified). Therefore:
  - Only artifacts **produced by this system's training jobs** are loaded.
  - No API or UI path uploads or imports artifacts.
  - Loading checks the path is within `CTI_ARTIFACT_DIR` and the SHA-256 equals the registry value before deserialising.
  - The artifact directory is writable only by the backend/worker user.
- `skops` (non-pickle format) is an open decision ([docs/decisions/README.md](docs/decisions/README.md#open-decisions)).

## 10. Privacy

- Security logs contain personal data (usernames, IPs, hostnames, command lines). Use **public or synthetic data during development**; never commit real organisational logs.
- Committed fixtures use documentation IP ranges and fictional names.
- Access to raw records is analyst+; all exports are future work and would be audited.
- Retention policies (§12) limit how long data is kept; a deployment must document its legal basis before ingesting real personal data (out of MVP scope).
- Logs of the application itself avoid personal data beyond IDs needed for debugging.

## 11. Dependency management

- Lockfiles committed (`uv.lock`, `package-lock.json`); Docker base images pinned to major/minor tags.
- Phase 7 and before each release: `uv run pip-audit` and `npm audit --omit=dev`; high/critical findings are fixed or documented with justification in the release notes.
- New dependencies follow [TECH_STACK.md](TECH_STACK.md#9-conditions-for-introducing-new-technology); prefer well-maintained packages with compatible licences.

## 12. Data retention

Defined in [DATABASE_DESIGN.md](DATABASE_DESIGN.md#9-retention). Retention is executed only by the admin `cti retention apply` command with `--dry-run` first; every execution is audited with counts.

## 13. HTTP and runtime hardening

- CORS: only `CTI_CORS_ORIGINS` (default `http://localhost:5173`), credentials allowed for those origins only.
- Security headers on API and production frontend: `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`, a restrictive `Content-Security-Policy` for the built frontend (`default-src 'self'`; no inline scripts).
- Production mode disables Swagger UI and debug tracebacks.
- Containers run as non-root users; only required ports exposed; PostgreSQL not published to the host in the production-like compose profile.

## 14. Security testing (summary)

Authorization matrix tests for every route, CSRF tests, upload limit/extension/traversal tests, malicious-content ingestion tests (HTML/JS in fields, formula-like CSV values, huge lines, deep JSON, NUL bytes), SQL-injection probes on filters, artifact-integrity tests, secret-redaction tests, and dependency audits. Details: [TESTING_STRATEGY.md](TESTING_STRATEGY.md#11-security-tests).
