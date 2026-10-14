import { apiRequest } from "../client";
import type { SessionInfo } from "../types";

export function login(username: string, password: string): Promise<SessionInfo> {
  return apiRequest<SessionInfo>("/auth/login", { method: "POST", body: { username, password } });
}

export function logout(): Promise<undefined> {
  return apiRequest<undefined>("/auth/logout", { method: "POST" });
}

/** Current session; rotates and returns the CSRF token. */
export function fetchSession(signal?: AbortSignal): Promise<SessionInfo> {
  return apiRequest<SessionInfo>("/auth/me", { signal });
}
