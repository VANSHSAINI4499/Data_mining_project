import type { Problem } from "./types";

export const API_BASE_URL: string = import.meta.env.VITE_API_BASE_URL ?? "/api/v1";

const UNSAFE_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

/** Error carrying the backend's problem details (or a network failure description). */
export class ApiError extends Error {
  readonly status: number;
  readonly problem: Problem | null;
  readonly requestId: string | null;

  constructor(status: number, problem: Problem | null, requestId: string | null, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.problem = problem;
    this.requestId = requestId;
  }
}

// The CSRF token is held in memory only (FRONTEND_SPECIFICATION.md §6).
let csrfToken: string | null = null;

export function setCsrfToken(token: string | null): void {
  csrfToken = token;
}

type UnauthorizedListener = () => void;
const unauthorizedListeners = new Set<UnauthorizedListener>();

/** Subscribe to 401 responses (e.g., to return to the login page). Returns an unsubscribe. */
export function onUnauthorized(listener: UnauthorizedListener): () => void {
  unauthorizedListeners.add(listener);
  return () => unauthorizedListeners.delete(listener);
}

export interface RequestOptions {
  method?: string;
  body?: unknown;
  signal?: AbortSignal;
}

async function parseProblem(response: Response): Promise<Problem | null> {
  const type = response.headers.get("content-type") ?? "";
  if (!type.includes("json")) return null;
  try {
    return (await response.json()) as Problem;
  } catch {
    return null;
  }
}

export async function apiRequest<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const method = (options.method ?? "GET").toUpperCase();
  const headers: Record<string, string> = { Accept: "application/json" };
  if (options.body !== undefined) headers["Content-Type"] = "application/json";
  if (UNSAFE_METHODS.has(method) && csrfToken) headers["X-CSRF-Token"] = csrfToken;

  let response: Response;
  try {
    response = await fetch(`${API_BASE_URL}${path}`, {
      method,
      headers,
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
      credentials: "same-origin",
      signal: options.signal,
    });
  } catch (cause) {
    if (cause instanceof DOMException && cause.name === "AbortError") throw cause;
    throw new ApiError(0, null, null, "Cannot reach the backend API. Is it running?");
  }

  if (!response.ok) {
    const problem = await parseProblem(response);
    const requestId = problem?.request_id ?? response.headers.get("X-Request-ID");
    if (response.status === 401) unauthorizedListeners.forEach((listener) => listener());
    throw new ApiError(
      response.status,
      problem,
      requestId,
      problem?.detail ?? problem?.title ?? `Request failed with status ${response.status}`,
    );
  }
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}
