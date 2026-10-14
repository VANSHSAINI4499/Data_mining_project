import { apiRequest } from "../client";
import type { Health, Readiness } from "../types";

export function fetchHealth(signal?: AbortSignal): Promise<Health> {
  return apiRequest<Health>("/health", { signal });
}

/** Resolves when ready; a 503 rejects with an ApiError whose problem carries `checks`. */
export function fetchReadiness(signal?: AbortSignal): Promise<Readiness> {
  return apiRequest<Readiness>("/health/ready", { signal });
}
