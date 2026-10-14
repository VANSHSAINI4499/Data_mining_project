# Frontend Specification — Investigation Dashboard

React + TypeScript single-page app built with Vite, styled with Tailwind CSS, charts with Recharts, server state with TanStack Query, routing with React Router ([TECH_STACK.md](TECH_STACK.md#2-frontend)). It consumes only the API in [API_SPECIFICATION.md](API_SPECIFICATION.md).

## 1. Honesty rules (non-negotiable)

1. **Every displayed metric, count, chart, and table row originates from an actual backend response.** No hard-coded, sample, random, or "demo" values in production code paths.
2. **Empty datasets produce honest empty states** ("No events ingested yet — upload a file") with a next action; never placeholder statistics or decorative fake charts.
3. **Facts, model outputs, hypotheses, and analyst conclusions are visually distinct** using a consistent tag component (`Observed`, `Model output`, `Hypothesis`, `Analyst`), matching [DATA_DICTIONARY.md](DATA_DICTIONARY.md#1-conventions).
4. **Scores are labelled correctly:** classification `predicted_score` → "model score (uncalibrated)"; anomaly → "unusualness percentile"; risk → "risk score (0–100, rule-based)". Never "probability" or "% malicious".
5. Model metrics always show the dataset/snapshot, split strategy, and model version they come from.
6. Untrusted strings (log fields, signatures, command lines, URLs, indicator values, notes) are rendered as **text only** — never `dangerouslySetInnerHTML`, never clickable links. URLs and domains are shown defanged.

## 2. Structure

```text
frontend/src/
  main.tsx, App.tsx, routes.tsx
  api/          client.ts (fetch wrapper: base URL, credentials, CSRF header, problem+json parsing), types.ts, endpoints/*.ts
  hooks/        TanStack Query hooks per resource (useEvents, useJob, …)
  components/   shared UI (below)
  features/<area>/  page-specific components
  pages/        route components
  lib/          formatting (dates in UTC + local toggle, numbers, defanging), constants
  test/         setup, MSW handlers, fixtures (test-only)
```

## 3. Navigation and routes

Left sidebar (collapsible) + top bar (global time range picker, user menu, job indicator).

| Route | Page | Min role |
|---|---|---|
| `/login` | Login | — |
| `/` | Overview dashboard | viewer |
| `/ingestion`, `/ingestion/batches/:batchId` | Data ingestion | viewer (upload: analyst) |
| `/events`, `/events/:eventId` | Event explorer | viewer |
| `/classification`, `/classification/runs/:runId` | Classification analytics | viewer (train: admin) |
| `/anomalies`, `/anomalies/:resultId` | Anomaly explorer | viewer |
| `/threat-intel`, `/threat-intel/indicators/:indicatorId` | Threat intelligence | viewer (manage: admin) |
| `/alerts`, `/alerts/:alertId` | Investigations — alerts | viewer (act: analyst) |
| `/cases`, `/cases/:caseId` | Investigations — cases | viewer (act: analyst) |
| `/models`, `/models/:modelId` | Model registry | viewer (promote: admin) |
| `/data-quality` | Data quality | viewer |
| `/settings` (tabs: users, sources, feeds, correlation rules, assets) | Settings | admin (sources/rules read: viewer) |
| `/audit` | Audit history | admin |

Controls the user's role does not permit are hidden or disabled with a tooltip; the backend still enforces authorization. Unknown routes → 404 page.

## 4. Reusable components

| Component | Purpose |
|---|---|
| `AppShell`, `Sidebar`, `TopBar` | Layout. |
| `TimeRangePicker` | Global range (presets + absolute UTC), stored in URL query. |
| `FilterBar` | Typed filters bound to URL search params. |
| `DataTable` | Cursor pagination ("Load more"/next), sortable documented keys, column chooser, row link. |
| `StatCard` | Single metric with source label and `as_of`; shows `—` + reason when unavailable. |
| `ChartCard` | Wraps Recharts charts with title, units, loading/empty/error states, and an accessible data-table toggle. |
| `TimeSeriesChart`, `BarChartCard`, `StackedBarChart`, `ConfusionMatrix` (grid with counts + row-normalised %, labelled axes "true"/"predicted"), `ScoreHistogram` | Charts. |
| `ProvenanceTag` / `CategoryTag` | `Observed` / `Model output` / `Hypothesis` / `Analyst`. |
| `RiskBadge`, `SeverityBadge`, `StatusBadge` | Status display. |
| `RiskBreakdownTable` | Component, value, weight, evidence link. |
| `EvidenceTimeline` | Ordered evidence/timeline entries. |
| `JobProgress` | Polls `/jobs/{id}` (every 2 s while running, stops on terminal state). |
| `FileUpload` | Size/extension pre-check (server remains authoritative), progress. |
| `SafeText`, `DefangedValue`, `CodeBlockText` | Inert rendering of untrusted strings with truncation + expand. |
| `EmptyState`, `ErrorState` (shows problem title/detail + `request_id`), `LoadingSkeleton` | States. |
| `ConfirmDialog` | Destructive/irreversible actions (promote, dismiss, close case). In-app modal, not `window.confirm`. |

## 5. Pages

### 5.1 Login
Username/password; the same generic error for every failed login (including locked accounts, which the API does not distinguish); a "too many attempts" message only for `429` rate limiting (Phase 7).

### 5.2 Overview dashboard
Data: `GET /dashboard/overview`, `GET /analytics/timeseries`.
- Stat cards: events in range, batches (completed / with errors / failed), open alerts by severity, flagged anomalies, active indicators and matches, DQ failures.
- Event volume over time by `event_type`; alerts opened over time.
- Active models panel: name, version, promoted at, test macro-F1 **with dataset/snapshot named** — or "No active model".
- First-run state: guided checklist (create source → upload → train → score) driven by real `is_empty` flags.

### 5.3 Data ingestion
- Upload form: source, adapter (from `/adapters`), variant, optional assumed date (with warning that assumed times exclude anomaly/temporal correlation).
- Batch list with status, counters, duration; batch detail with counters reconciliation, encoding, timezone assumption, DQ results, rejected records table, retry button (analyst, failed only).

### 5.4 Event explorer
- Filters from [API §7](API_SPECIFICATION.md#7-event-filters) in URL; table with key fields and tags for prediction/match/alert presence.
- Event detail sections: Observed, Provenance, Ground truth (dataset), Model outputs, Threat intel & ATT&CK (with "via" source), Alerts, Analyst feedback, Raw record (analyst, inert JSON viewer). Pivot links: same src/dst IP, same user, same host (pre-filled explorer queries).

### 5.5 Classification analytics
- Training runs list; start training form (admin) with validated config fields; job progress.
- Run detail: snapshot and data report, leakage checks (warnings prominent, acknowledge action for admin), per-model comparison table (baselines included) with macro-F1/weighted-F1, per-class P/R/F1/support table, confusion matrix (counts & normalised toggle), bootstrap CI, permutation importance bar chart.
- Live predictions view: predicted category distribution over time for the active model; disagreement with ground truth where labels exist (clearly labelled "on scored scope").

### 5.6 Anomaly explorer
- Filters: entity type, entity, model, min percentile, time range.
- Flagged windows table with percentile and top deviation.
- Detail: feature vs. baseline table, entity score history chart with threshold line, seasonal comparison (or "insufficient history"), linked events, feedback form. Persistent banner: "Unusual behaviour is not necessarily malicious."

### 5.7 Threat intelligence
- Feeds table with reliability, health, last sync, enable toggle, sync button (admin); "No feeds configured — the system works without them" empty state.
- Indicator search (type, state, confidence, feed), defanged display; indicator detail with version history and matches.
- Import form (CSV / STIX 2.1) with run report (created/updated/rejected/unsupported patterns).
- ATT&CK tab: imported version, techniques search, category→technique mappings with confidence and rationale.

### 5.8 Incident investigations
- **Alerts queue:** sort by risk, filters, bulk acknowledge (analyst). Label: "Alerts are hypotheses for review."
- **Alert detail:** rule (version, description), `RiskBreakdownTable`, evidence timeline with category tags, entity pivots, actions (acknowledge, review, dismiss with reason, escalate to case).
- **Cases list** and **case detail:** summary, status, disposition (required on close), linked alerts, timeline with notes, assignee.

### 5.9 Model registry
- Models by task/name with status; detail with manifest (feature list, class labels, versions, artifact hash), training run link, metrics summary, promotion history, drift warnings (Phase 8). Promote/archive/reject (admin) with gate results shown on failure.

### 5.10 Data quality
- Check status over time per source; latest failures; per-batch drill-down; unmapped label list.

### 5.11 Settings
- Users (admin): create, role change, deactivate.
- Sources: list (viewer), create/edit (admin), timezone setting with explanation.
- Feeds (admin), correlation rules (list for viewer; edit = new version for admin with JSON/TOML-like form validated by the API), assets import.

### 5.12 Audit history
- Filterable table (admin) of audit records with actor, action, target, outcome, request ID; read-only.

## 6. State management

- **Server state:** TanStack Query only. Query keys `[resource, params]`. Default `staleTime` 30 s; job queries poll while non-terminal; invalidate related queries after mutations (e.g., promotion invalidates `models` and `dashboard`).
- **URL state:** filters, time range, pagination cursor, tabs — shareable links.
- **Local UI state:** React state; no global store library in the MVP.
- **Auth state:** `/auth/me` query; the session cookie is HttpOnly (not readable by JS); the CSRF token from login is held in memory and re-fetched by re-login after reload (`GET /auth/me` returns a fresh CSRF token for an existing session).
- Persisted browser storage only for harmless preferences (theme, sidebar collapsed, UTC/local toggle).

## 7. Charts

- Recharts; every chart has title, axis labels with units, legend when > 1 series, tooltip with exact values, and an accessible "view as table" toggle.
- Time axes in UTC by default (toggle to local), bucket size shown.
- Categorical colours from a fixed, colour-blind-safe palette mapped consistently to attack categories; severity colours consistent across pages; text labels never rely on colour alone.
- Confusion matrix rendered as a CSS grid (not a misleading continuous heatmap legend), with counts and row-normalised percentages.
- No 3D, no dual axes without explicit labelling, y-axis starts at zero for counts.

## 8. Loading, empty, and error states

| State | Behaviour |
|---|---|
| Loading | Skeletons sized like final content; no fake numbers. |
| Empty | Explain why (no data in range / no data at all / feature not configured) + next action link. |
| Error | `ErrorState` with problem `title`, `detail`, `request_id`, retry button. 401 → redirect to login preserving return URL. 403 → "You need role X". 503 → "Backend not ready" with readiness checks. |
| Partial | Each card handles its own state; one failing widget doesn't blank the page. |
| Long jobs | `JobProgress` with honest progress (`done/total` only if the backend provides them). |

## 9. Accessibility and UX baseline

Keyboard navigable, visible focus, semantic tables, ARIA labels on icon buttons, colour contrast WCAG AA, responsive down to 1280 px wide desktop (mobile is not a target).

## 10. Configuration

- `VITE_API_BASE_URL` (default `/api/v1`; dev server proxies `/api` → `http://localhost:8000`).
- No secrets in frontend env vars (they are public in the bundle).
