import { useQuery } from "@tanstack/react-query";

import type { ApiError } from "../api/client";
import { fetchHealth, fetchReadiness } from "../api/endpoints/health";
import type { Health, Readiness } from "../api/types";

export function useHealth() {
  return useQuery<Health, ApiError>({
    queryKey: ["health"],
    queryFn: ({ signal }) => fetchHealth(signal),
  });
}

export function useReadiness() {
  return useQuery<Readiness, ApiError>({
    queryKey: ["health", "ready"],
    queryFn: ({ signal }) => fetchReadiness(signal),
    retry: false,
  });
}
