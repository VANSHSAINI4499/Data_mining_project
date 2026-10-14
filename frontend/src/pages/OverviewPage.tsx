import type { ReactNode } from "react";
import { Link } from "react-router";

import { useApi } from "../api/hooks";
import type { ReadinessCheck } from "../api/types";
import { TimeSeriesChart, type SeriesPoint } from "../components/charts";
import { EmptyState, ErrorState, LoadingSkeleton } from "../components/States";
import { Card, PageHeader, SeverityBadge, TimeRangePicker } from "../components/ui";
import { useHealth, useReadiness } from "../hooks/useSystemStatus";
import { formatNumber, formatScore, formatTime } from "../lib/format";
import { useTimeRange } from "../lib/timeRange";

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

interface Section {
  as_of: string;
  is_empty: boolean;
}

export interface ActiveModel {
  model_id: string;
  name: string;
  version: number;
  task: string;
  algorithm: string;
  promoted_at: string | null;
  test_metrics?: Record<string, number | null>;
  evaluated_on?: { split: string; datasets: string[]; snapshot_rows: number | null };
  reference_period?: { start: string; end: string; windows: number; entities: number };
  note?: string;
}

export interface Overview {
  events: Section & { total: number; by_type: Record<string, number> };
  ingestion: Section & { batches_by_status: Record<string, number> };
  models: Section & { active: ActiveModel[] };
  alerts: Section & {
    open_total: number;
    open_by_severity: Record<string, number>;
    note: string;
  };
  anomalies: Section & { flagged: number };
  threat_intel: Section & { active_indicators: number; matches: number };
  data_quality: Section & {
    status_counts: Record<string, number>;
    recent_problems: { check_name: string; batch_id: string; status: string; checked_at: string }[];
  };
}

interface Timeseries {
  interval: string;
  buckets: { ts: string; series: Record<string, number> }[];
}

function StatCard({
  label,
  value,
  source,
  asOf,
  to,
  children,
}: {
  label: string;
  value: string;
  source: string;
  asOf: string;
  to?: string;
  children?: ReactNode;
}) {
  return (
    <div className="rounded border border-line bg-surface p-4">
      <p className="text-sm text-muted">{label}</p>
      <p className="mt-1 text-2xl font-semibold tabular-nums">
        {to ? <Link to={to}>{value}</Link> : value}
      </p>
      {children}
      <p className="mt-2 text-xs text-muted" title={`computed ${formatTime(asOf)}`}>
        Source: {source}
      </p>
    </div>
  );
}

function FirstRun({ data }: { data: Overview }) {
  const steps = [
    {
      done: !data.ingestion.is_empty,
      text: "Import data (Data ingestion or `cti ingest`)",
      to: "/ingestion",
    },
    { done: !data.events.is_empty, text: "Events exist in the selected range", to: "/events" },
    { done: !data.models.is_empty, text: "Train and promote a model", to: "/models" },
    { done: !data.alerts.is_empty, text: "Run correlation to produce alerts", to: "/alerts" },
  ];
  return (
    <Card title="Getting started">
      <ul className="space-y-1 text-sm">
        {steps.map((s) => (
          <li key={s.text}>
            <span aria-hidden="true">{s.done ? "✔" : "○"}</span>{" "}
            <span className="sr-only">{s.done ? "done:" : "to do:"}</span>
            <Link to={s.to} className={s.done ? "text-muted" : "text-accent underline"}>
              {s.text}
            </Link>
          </li>
        ))}
      </ul>
    </Card>
  );
}

function ModelsPanel({ models }: { models: ActiveModel[] }) {
  if (models.length === 0) return <EmptyState title="No active model" />;
  return (
    <ul className="space-y-3 text-sm">
      {models.map((m) => (
        <li key={m.model_id}>
          <Link to={`/models/${m.model_id}`} className="font-medium text-accent">
            {m.name} v{m.version}
          </Link>{" "}
          <span className="text-muted">
            ({m.task}, {m.algorithm}, promoted {formatTime(m.promoted_at)})
          </span>
          {m.test_metrics && m.evaluated_on && (
            <p>
              Test macro-F1 {formatScore(m.test_metrics.macro_f1)}, weighted-F1{" "}
              {formatScore(m.test_metrics.weighted_f1)} on the {m.evaluated_on.split} (
              {m.evaluated_on.datasets.join(", ") || "unknown dataset"},{" "}
              {formatNumber(m.test_metrics.rows)} test rows)
            </p>
          )}
          {m.reference_period && (
            <p className="text-muted">
              Reference {m.reference_period.start.slice(0, 10)} –{" "}
              {m.reference_period.end.slice(0, 10)}, {m.reference_period.windows} windows. {m.note}
            </p>
          )}
        </li>
      ))}
    </ul>
  );
}

export function OverviewPage() {
  const { range } = useTimeRange();
  const params = { from: range.from, to: range.to };
  const overview = useApi<Overview>("/dashboard/overview", params);
  const series = useApi<Timeseries>("/analytics/timeseries", {
    ...params,
    interval: "day",
    group_by: "event_type",
  });

  const data = overview.data;
  const keys = [
    ...new Set(series.data?.buckets.flatMap((b) => Object.keys(b.series)) ?? []),
  ].sort();
  const points: SeriesPoint[] = series.data?.buckets.map((b) => ({ ts: b.ts, ...b.series })) ?? [];
  const allEmpty = data && data.events.is_empty && data.ingestion.is_empty && data.models.is_empty;

  return (
    <div className="space-y-6">
      <PageHeader title="Overview">
        <TimeRangePicker />
      </PageHeader>
      <section aria-labelledby="status-title" className="rounded border border-line bg-surface p-4">
        <h2 id="status-title" className="mb-3 font-medium">
          System status
        </h2>
        <SystemStatus />
      </section>
      <section aria-labelledby="dashboard-title" className="space-y-4">
        <h2 id="dashboard-title" className="sr-only">
          Security overview
        </h2>
        {overview.isPending && <LoadingSkeleton label="Loading overview" lines={4} />}
        {overview.error && (
          <ErrorState error={overview.error} onRetry={() => void overview.refetch()} />
        )}
        {data && allEmpty && (
          <EmptyState title="No security analytics yet">
            No events, ingestion batches, or models exist yet. Follow the steps below; nothing is
            shown until real data exists.
          </EmptyState>
        )}
        {data && allEmpty && <FirstRun data={data} />}
        {data && !allEmpty && (
          <>
            <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
              <StatCard
                label="Events in range"
                value={formatNumber(data.events.total)}
                source="fact_security_event"
                asOf={data.events.as_of}
                to="/events"
              />
              <StatCard
                label="Open alerts"
                value={formatNumber(data.alerts.open_total)}
                source="correlation alerts (hypotheses)"
                asOf={data.alerts.as_of}
                to="/alerts"
              >
                <p className="mt-1 flex flex-wrap gap-1 text-xs">
                  {Object.entries(data.alerts.open_by_severity).map(([sev, n]) => (
                    <span key={sev}>
                      <SeverityBadge severity={sev} /> {n}
                    </span>
                  ))}
                </p>
              </StatCard>
              <StatCard
                label="Flagged anomaly windows"
                value={formatNumber(data.anomalies.flagged)}
                source="active anomaly models"
                asOf={data.anomalies.as_of}
                to="/anomalies"
              />
              <StatCard
                label="Indicator matches in range"
                value={formatNumber(data.threat_intel.matches)}
                source={`${formatNumber(data.threat_intel.active_indicators)} indicators active now`}
                asOf={data.threat_intel.as_of}
                to="/threat-intel"
              />
              <StatCard
                label="Ingestion batches"
                value={formatNumber(
                  Object.values(data.ingestion.batches_by_status).reduce((a, b) => a + b, 0),
                )}
                source={
                  Object.entries(data.ingestion.batches_by_status)
                    .map(([s, n]) => `${n} ${s.replaceAll("_", " ")}`)
                    .join(", ") || "no batches"
                }
                asOf={data.ingestion.as_of}
                to="/ingestion"
              />
              <StatCard
                label="Data-quality failures"
                value={formatNumber(data.data_quality.status_counts.fail ?? 0)}
                source={`${formatNumber(data.data_quality.status_counts.warn ?? 0)} warnings, all batches`}
                asOf={data.data_quality.as_of}
                to="/data-quality"
              />
            </div>
            {series.error ? (
              <ErrorState error={series.error} />
            ) : (
              <TimeSeriesChart
                title="Event volume by type"
                description="Events per day (UTC buckets), stacked by event type."
                data={points}
                series={keys}
                yLabel="events / day"
              />
            )}
            <Card title="Active models">
              <ModelsPanel models={data.models.active} />
            </Card>
          </>
        )}
      </section>
    </div>
  );
}
