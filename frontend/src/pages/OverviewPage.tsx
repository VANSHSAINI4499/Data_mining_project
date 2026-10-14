import type { ReadinessCheck } from "../api/types";
import { EmptyState, ErrorState, LoadingSkeleton } from "../components/States";
import { useHealth, useReadiness } from "../hooks/useSystemStatus";

const CHECK_LABELS: Record<string, string> = {
  database: "Database",
  migrations: "Database migrations",
  upload_dir: "Upload directory",
  artifact_dir: "Model artifact directory",
};

function CheckList({ checks }: { checks: Record<string, ReadinessCheck> }) {
  return (
    <ul className="divide-y divide-line">
      {Object.entries(checks).map(([name, check]) => (
        <li key={name} className="flex items-center justify-between py-2 text-sm">
          <span>{CHECK_LABELS[name] ?? name}</span>
          <span className={check.status === "ok" ? "text-ok" : "text-danger"}>
            {check.status === "ok" ? "OK" : `Failing${check.detail ? `: ${check.detail}` : ""}`}
          </span>
        </li>
      ))}
    </ul>
  );
}

function SystemStatus() {
  const health = useHealth();
  const readiness = useReadiness();

  if (readiness.isPending) return <LoadingSkeleton label="Loading system status" />;

  // A 503 is an expected "not ready" answer that still carries per-check results.
  const notReadyChecks = readiness.error?.problem?.checks as
    Record<string, ReadinessCheck> | undefined;

  return (
    <div className="space-y-3">
      {readiness.isSuccess && (
        <p className="text-sm text-ok" role="status">
          Backend is ready.
        </p>
      )}
      {readiness.isError && notReadyChecks && (
        <p className="text-sm text-danger" role="status">
          Backend is not ready.
        </p>
      )}
      {readiness.isSuccess && <CheckList checks={readiness.data.checks} />}
      {readiness.isError &&
        (notReadyChecks ? (
          <CheckList checks={notReadyChecks} />
        ) : (
          <ErrorState error={readiness.error} onRetry={() => void readiness.refetch()} />
        ))}
      {health.isSuccess && <p className="text-xs text-muted">API version {health.data.version}</p>}
    </div>
  );
}

export function OverviewPage() {
  return (
    <div className="space-y-6">
      <h1 className="text-xl font-semibold">Overview</h1>
      <section aria-labelledby="status-title" className="rounded border border-line bg-surface p-4">
        <h2 id="status-title" className="mb-3 font-medium">
          System status
        </h2>
        <SystemStatus />
      </section>
      <section aria-labelledby="dashboard-title">
        <h2 id="dashboard-title" className="sr-only">
          Security overview
        </h2>
        <EmptyState title="No security analytics yet">
          Event, alert, anomaly, and model statistics appear here once data ingestion (Phase 2) and
          the dashboard endpoints (milestone 6.1) exist. Nothing is shown until then.
        </EmptyState>
      </section>
    </div>
  );
}
