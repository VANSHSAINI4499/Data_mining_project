import { useQueryClient } from "@tanstack/react-query";
import { lazy, useEffect, type ComponentType } from "react";
import { Navigate, Route, Routes, useLocation } from "react-router";

import { onUnauthorized } from "./api/client";
import { AppShell } from "./components/AppShell";
import { PlannedFeature } from "./components/PlannedFeature";
import { ErrorState, LoadingSkeleton } from "./components/States";
import { hasRole, SESSION_KEY, useSession } from "./hooks/useSession";
import { NAV_PAGES, PLANNED_PATHS } from "./lib/navigation";
import { LoginPage } from "./pages/LoginPage";
import { ForbiddenPage, NotFoundPage } from "./pages/StatusPages";

interface FromState {
  from?: string;
}

/** Loads one named page export on first use; pages of a module share a chunk. */
function page<M extends Record<string, unknown>>(load: () => Promise<M>, name: keyof M) {
  return lazy(async () => ({ default: (await load())[name] as ComponentType }));
}

const admin = () => import("./pages/AdminPages");
const events = () => import("./pages/EventPages");
const ingestion = () => import("./pages/IngestionPages");
const investigations = () => import("./pages/InvestigationPages");
const ml = () => import("./pages/MlPages");
const threatIntel = () => import("./pages/ThreatIntelPages");

const OverviewPage = page(() => import("./pages/OverviewPage"), "OverviewPage");
const IngestionPage = page(ingestion, "IngestionPage");
const BatchDetailPage = page(ingestion, "BatchDetailPage");
const EventsPage = page(events, "EventsPage");
const EventDetailPage = page(events, "EventDetailPage");
const ClassificationPage = page(ml, "ClassificationPage");
const RunDetailPage = page(ml, "RunDetailPage");
const AnomaliesPage = page(ml, "AnomaliesPage");
const AnomalyDetailPage = page(ml, "AnomalyDetailPage");
const ModelsPage = page(ml, "ModelsPage");
const ModelDetailPage = page(ml, "ModelDetailPage");
const ThreatIntelPage = page(threatIntel, "ThreatIntelPage");
const IndicatorDetailPage = page(threatIntel, "IndicatorDetailPage");
const AlertsPage = page(investigations, "AlertsPage");
const AlertDetailPage = page(investigations, "AlertDetailPage");
const CasesPage = page(investigations, "CasesPage");
const CaseDetailPage = page(investigations, "CaseDetailPage");
const DataQualityPage = page(admin, "DataQualityPage");
const SettingsPage = page(admin, "SettingsPage");
const AuditPage = page(admin, "AuditPage");

/** Page components by route path (FRONTEND_SPECIFICATION.md §3). */
const PAGE_ELEMENTS: Record<string, ComponentType> = {
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
