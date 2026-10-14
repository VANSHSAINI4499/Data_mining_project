import { useQueryClient } from "@tanstack/react-query";
import { useEffect, type ReactElement } from "react";
import { Navigate, Route, Routes, useLocation } from "react-router";

import { onUnauthorized } from "./api/client";
import { AppShell } from "./components/AppShell";
import { PlannedFeature } from "./components/PlannedFeature";
import { ErrorState, LoadingSkeleton } from "./components/States";
import { hasRole, SESSION_KEY, useSession } from "./hooks/useSession";
import { NAV_PAGES, PLANNED_PATHS } from "./lib/navigation";
import { AuditPage, DataQualityPage, SettingsPage } from "./pages/AdminPages";
import { EventDetailPage, EventsPage } from "./pages/EventPages";
import { BatchDetailPage, IngestionPage } from "./pages/IngestionPages";
import { AlertDetailPage, AlertsPage, CaseDetailPage, CasesPage } from "./pages/InvestigationPages";
import { LoginPage } from "./pages/LoginPage";
import {
  AnomaliesPage,
  AnomalyDetailPage,
  ClassificationPage,
  ModelDetailPage,
  ModelsPage,
  RunDetailPage,
} from "./pages/MlPages";
import { OverviewPage } from "./pages/OverviewPage";
import { ForbiddenPage, NotFoundPage } from "./pages/StatusPages";
import { IndicatorDetailPage, ThreatIntelPage } from "./pages/ThreatIntelPages";

interface FromState {
  from?: string;
}

/** Page components by route path (FRONTEND_SPECIFICATION.md §3). */
const PAGE_ELEMENTS: Record<string, () => ReactElement> = {
  "/ingestion": IngestionPage,
  "/ingestion/batches/:batchId": BatchDetailPage,
  "/events": EventsPage,
  "/events/:eventId": EventDetailPage,
  "/classification": ClassificationPage,
  "/classification/runs/:runId": RunDetailPage,
  "/anomalies": AnomaliesPage,
  "/anomalies/:resultId": AnomalyDetailPage,
  "/threat-intel": ThreatIntelPage,
  "/threat-intel/indicators/:indicatorId": IndicatorDetailPage,
  "/alerts": AlertsPage,
  "/alerts/:alertId": AlertDetailPage,
  "/cases": CasesPage,
  "/cases/:caseId": CaseDetailPage,
  "/models": ModelsPage,
  "/models/:modelId": ModelDetailPage,
  "/data-quality": DataQualityPage,
  "/settings": SettingsPage,
  "/audit": AuditPage,
};

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
        {NAV_PAGES.flatMap((item) =>
          [item.path, ...(item.detailPaths ?? [])].map((path) => {
            const Page = PAGE_ELEMENTS[path];
            const content =
              PLANNED_PATHS.has(item.path) || !Page ? <PlannedFeature item={item} /> : <Page />;
            return (
              <Route
                key={path}
                path={path}
                element={
                  hasRole(user, item.minRole) ? content : <ForbiddenPage role={item.minRole} />
                }
              />
            );
          }),
        )}
        <Route path="*" element={<NotFoundPage />} />
      </Route>
    </Routes>
  );
}
