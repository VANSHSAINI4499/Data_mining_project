import { useQueryClient } from "@tanstack/react-query";
import { useEffect } from "react";
import { Navigate, Route, Routes, useLocation } from "react-router";

import { onUnauthorized } from "./api/client";
import { AppShell } from "./components/AppShell";
import { PlannedFeature } from "./components/PlannedFeature";
import { ErrorState, LoadingSkeleton } from "./components/States";
import { hasRole, SESSION_KEY, useSession } from "./hooks/useSession";
import { PLANNED_PAGES } from "./lib/navigation";
import { LoginPage } from "./pages/LoginPage";
import { OverviewPage } from "./pages/OverviewPage";
import { ForbiddenPage, NotFoundPage } from "./pages/StatusPages";

interface FromState {
  from?: string;
}

export function App() {
  const queryClient = useQueryClient();
  const session = useSession();
  const location = useLocation();

  // Any 401 from the API means the session ended: drop it so the login page appears.
  useEffect(() => onUnauthorized(() => queryClient.setQueryData(SESSION_KEY, null)), [queryClient]);

  if (session.isPending) {
    return (
      <div className="p-6">
        <LoadingSkeleton label="Checking your session" />
      </div>
    );
  }
  if (session.isError) {
    return (
      <div className="mx-auto max-w-xl p-6">
        <ErrorState error={session.error} onRetry={() => void session.refetch()} />
      </div>
    );
  }

  const user = session.data?.user;
  if (!user) {
    const from = location.pathname === "/login" ? "/" : location.pathname + location.search;
    return (
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="*" element={<Navigate to="/login" replace state={{ from }} />} />
      </Routes>
    );
  }

  const returnTo = (location.state as FromState | null)?.from ?? "/";
  return (
    <Routes>
      <Route path="/login" element={<Navigate to={returnTo} replace />} />
      <Route element={<AppShell user={user} />}>
        <Route index element={<OverviewPage />} />
        {PLANNED_PAGES.flatMap((item) =>
          [item.path, ...(item.detailPaths ?? [])].map((path) => (
            <Route
              key={path}
              path={path}
              element={
                hasRole(user, item.minRole) ? (
                  <PlannedFeature item={item} />
                ) : (
                  <ForbiddenPage role={item.minRole} />
                )
              }
            />
          )),
        )}
        <Route path="*" element={<NotFoundPage />} />
      </Route>
    </Routes>
  );
}
