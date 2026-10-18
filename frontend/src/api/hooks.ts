import {
  keepPreviousData,
  useInfiniteQuery,
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";

import { apiRequest, type ApiError } from "./client";
import type { Page } from "./types";

export type Params = Record<string, string | number | boolean | string[] | null | undefined>;

/** Builds a query string; empty values are dropped, arrays become repeated keys. */
export function toQuery(params: Params = {}): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === "") continue;
    if (Array.isArray(value)) value.forEach((v) => search.append(key, v));
    else search.set(key, String(value));
  }
  const text = search.toString();
  return text ? `?${text}` : "";
}

/** GET a resource. Query key is `[path, params]` (FRONTEND_SPECIFICATION.md §6). */
export function useApi<T>(
  path: string | null,
  params: Params = {},
  options: { refetchInterval?: number | false | ((data: T | undefined) => number | false) } = {},
) {
  return useQuery<T, ApiError>({
    queryKey: [path, params],
    queryFn: ({ signal }) => apiRequest<T>(`${path}${toQuery(params)}`, { signal }),
    enabled: path !== null,
    placeholderData: keepPreviousData,
    refetchInterval:
      typeof options.refetchInterval === "function"
        ? (query) =>
            (options.refetchInterval as (data: T | undefined) => number | false)(query.state.data)
        : options.refetchInterval,
  });
}

/** Cursor-paginated list ("Load more"). `refetchInterval` (ms) re-fetches the first page on a
 * timer, so a list stays current during live ingestion; omit it for a static list. */
export function usePaged<T>(
  path: string,
  params: Params = {},
  options: { refetchInterval?: number | false } = {},
) {
  return useInfiniteQuery<Page<T>, ApiError>({
    queryKey: [path, params, "paged"],
    queryFn: ({ signal, pageParam }) =>
      apiRequest<Page<T>>(
        `${path}${toQuery({ ...params, cursor: pageParam as string | undefined })}`,
        { signal },
      ),
    initialPageParam: undefined,
    getNextPageParam: (last) => last.next_cursor ?? undefined,
    refetchInterval: options.refetchInterval,
  });
}

/** Drops one key from mutation variables (it belongs in the URL, not the body). */
export function without<K extends string>(key: K) {
  return <T extends Record<K, unknown>>(body: T) =>
    Object.fromEntries(Object.entries(body).filter(([name]) => name !== key));
}

/** A mutation that invalidates the given query path prefixes on success. */
export function useApiMutation<TBody, TResult = unknown>(
  method: string,
  path: string | ((body: TBody) => string),
  invalidate: string[] = [],
  /** Request body derived from the mutation variables (e.g., to drop the ID used in the path). */
  select?: (body: TBody) => unknown,
) {
  const queryClient = useQueryClient();
  return useMutation<TResult, ApiError, TBody>({
    mutationFn: (body) =>
      apiRequest<TResult>(typeof path === "function" ? path(body) : path, {
        method,
        body: select ? select(body) : body,
      }),
    onSuccess: () =>
      Promise.all(
        invalidate.map((prefix) =>
          queryClient.invalidateQueries({
            predicate: (query) =>
              typeof query.queryKey[0] === "string" && query.queryKey[0].startsWith(prefix),
          }),
        ),
      ),
  });
}
