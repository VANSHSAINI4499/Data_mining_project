// Test-only HTTP mocking (MSW). Never imported by application code.
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";

import type { Problem, Role, SessionInfo } from "../api/types";

export const API = "/api/v1";

export function problem(status: number, title: string, detail: string, extra = {}): Problem {
  return {
    type: `https://cti-warehouse.local/problems/${title.toLowerCase().replace(/\s+/g, "-")}`,
    title,
    status,
    detail,
    instance: "/test",
    request_id: "req-test-1",
    ...extra,
  };
}

export function problemResponse(body: Problem) {
  return HttpResponse.json(body, {
    status: body.status,
    headers: { "Content-Type": "application/problem+json" },
  });
}

export function sessionFor(role: Role, username = `${role}-user`): SessionInfo {
  return {
    user: {
      user_id: "00000000-0000-4000-8000-000000000001",
      username,
      role,
      is_active: true,
      created_at: "2026-10-14T00:00:00Z",
      last_login_at: null,
    },
    csrf_token: `csrf-${role}`,
  };
}

export const readyBody = {
  status: "ready",
  checks: {
    database: { status: "ok" },
    migrations: { status: "ok", revision: ["3f9a2c7d1b04"] },
    upload_dir: { status: "ok" },
    artifact_dir: { status: "ok" },
  },
};

const AS_OF = "2026-10-15T00:00:00Z";

/** Overview payload of a fresh installation: every section empty. */
export const emptyOverview = {
  range: { from: "2025-10-15T00:00:00Z", to: "2026-10-15T00:00:00Z" },
  events: { as_of: AS_OF, is_empty: true, total: 0, by_type: {} },
  ingestion: { as_of: AS_OF, is_empty: true, batches_by_status: {} },
  models: { as_of: AS_OF, is_empty: true, active: [] },
  alerts: {
    as_of: AS_OF,
    is_empty: true,
    open_total: 0,
    open_by_severity: { critical: 0, high: 0, medium: 0, low: 0 },
    open_by_status: {},
    note: "alerts are hypotheses for review, not confirmed incidents",
  },
  anomalies: { as_of: AS_OF, is_empty: true, flagged: 0 },
  threat_intel: { as_of: AS_OF, is_empty: true, active_indicators: 0, matches: 0 },
  data_quality: { as_of: AS_OF, is_empty: true, status_counts: {}, recent_problems: [] },
};

export const emptyPage = { items: [], next_cursor: null, limit: 50 };

/** Default handlers: logged out, backend healthy, no data. Tests override per case. */
export const defaultHandlers = [
  http.get(`${API}/dashboard/overview`, () => HttpResponse.json(emptyOverview)),
  http.get(`${API}/analytics/timeseries`, () =>
    HttpResponse.json({
      interval: "day",
      metric: "event_count",
      group_by: "event_type",
      buckets: [],
    }),
  ),
  http.get(`${API}/events`, () => HttpResponse.json(emptyPage)),
  http.get(`${API}/web-payloads/results`, () => HttpResponse.json(emptyPage)),
  http.get(`${API}/auth/me`, () =>
    problemResponse(problem(401, "Authentication required", "Authentication required")),
  ),
  http.get(`${API}/health`, () => HttpResponse.json({ status: "ok", version: "0.1.0" })),
  http.get(`${API}/health/ready`, () => HttpResponse.json(readyBody)),
];

export const server = setupServer(...defaultHandlers);
