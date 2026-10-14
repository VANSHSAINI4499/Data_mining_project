// Types mirroring backend schemas (API_SPECIFICATION.md). Update together with backend changes.

export type Role = "viewer" | "analyst" | "admin";

export interface User {
  user_id: string;
  username: string;
  role: Role;
  is_active: boolean;
  created_at: string;
  last_login_at: string | null;
}

export interface SessionInfo {
  user: User;
  csrf_token: string;
}

export interface FieldProblem {
  field: string;
  code: string;
  message: string;
}

/** RFC 9457 problem details plus CTI extensions. */
export interface Problem {
  type: string;
  title: string;
  status: number;
  detail: string;
  instance: string;
  request_id: string | null;
  errors?: FieldProblem[];
  [extension: string]: unknown;
}

export interface Health {
  status: "ok";
  version: string;
}

export interface ReadinessCheck {
  status: "ok" | "fail" | "unknown";
  detail?: string;
  [key: string]: unknown;
}

export interface Readiness {
  status: "ready";
  checks: Record<string, ReadinessCheck>;
}

export interface Page<T> {
  items: T[];
  next_cursor: string | null;
  limit: number;
}
