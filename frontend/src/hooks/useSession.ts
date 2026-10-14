import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { ApiError, setCsrfToken } from "../api/client";
import { fetchSession, login, logout } from "../api/endpoints/auth";
import type { Role, SessionInfo, User } from "../api/types";

export const SESSION_KEY = ["session"] as const;

const ROLE_RANK: Record<Role, number> = { viewer: 1, analyst: 2, admin: 3 };

export function hasRole(user: User | undefined, required: Role): boolean {
  return user !== undefined && ROLE_RANK[user.role] >= ROLE_RANK[required];
}

/**
 * The current session. `null` data means "not logged in" (a 401), which is a normal state,
 * not an error. Each successful fetch rotates the CSRF token, so this query never refetches
 * automatically.
 */
export function useSession() {
  return useQuery<SessionInfo | null, ApiError>({
    queryKey: SESSION_KEY,
    queryFn: async ({ signal }) => {
      try {
        const session = await fetchSession(signal);
        setCsrfToken(session.csrf_token);
        return session;
      } catch (error) {
        if (error instanceof ApiError && error.status === 401) {
          setCsrfToken(null);
          return null;
        }
        throw error;
      }
    },
    staleTime: Infinity,
    refetchOnWindowFocus: false,
    retry: false,
  });
}

export function useLogin() {
  const queryClient = useQueryClient();
  return useMutation<SessionInfo, ApiError, { username: string; password: string }>({
    mutationFn: ({ username, password }) => login(username, password),
    onSuccess: (session) => {
      setCsrfToken(session.csrf_token);
      queryClient.setQueryData(SESSION_KEY, session);
    },
  });
}

export function useLogout() {
  const queryClient = useQueryClient();
  return useMutation<undefined, ApiError>({
    mutationFn: () => logout(),
    onSettled: () => {
      setCsrfToken(null);
      // Drop cached data from the previous user, but keep the (now empty) session query so it
      // is not refetched.
      queryClient.removeQueries({ predicate: (query) => query.queryKey[0] !== SESSION_KEY[0] });
      queryClient.setQueryData(SESSION_KEY, null);
    },
  });
}
