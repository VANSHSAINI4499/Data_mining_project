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

/** Default handlers: logged out, backend healthy. Tests override per case. */
export const defaultHandlers = [
  http.get(`${API}/auth/me`, () =>
    problemResponse(problem(401, "Authentication required", "Authentication required")),
  ),
  http.get(`${API}/health`, () => HttpResponse.json({ status: "ok", version: "0.1.0" })),
  http.get(`${API}/health/ready`, () => HttpResponse.json(readyBody)),
];

export const server = setupServer(...defaultHandlers);
