import { useState } from "react";
import { Link, useParams } from "react-router";

import { useApi, useApiMutation, usePaged } from "../api/hooks";
import { BarChartCard, ConfusionMatrix, ScoreHistoryChart } from "../components/charts";
import { ConfirmButton } from "../components/ConfirmDialog";
import { DataTable } from "../components/DataTable";
import { JobProgress } from "../components/JobProgress";
import { EmptyState, ErrorState, LoadingSkeleton } from "../components/States";
import {
  Badge,
  Button,
  Card,
  CodeBlockText,
  Field,
  inputClass,
  KeyValue,
  MutationError,
  Notice,
  PageHeader,
  SafeText,
  StatusBadge,
  TimeRangePicker,
} from "../components/ui";
import { hasRole, useSession } from "../hooks/useSession";
import { formatNumber, formatScore, formatTime, shortId } from "../lib/format";
import { useTimeRange } from "../lib/timeRange";
import { FeedbackForm } from "./FeedbackForm";
import { ScoredHttpParamsCard } from "./ScoredHttpParamsCard";
import { WebPayloadCard } from "./WebPayloadCard";

// --- classification ------------------------------------------------------------------------------

interface RunRow {
  run_id: string;
  name: string;
  status: string;
  feature_set_version: string;
  split_strategy: string;
  created_at: string;
  finished_at: string | null;
  error: string | null;
}

interface SplitMetrics {
  rows: number;
  accuracy: number;
  macro_f1: number;
  weighted_f1: number;
  balanced_accuracy: number;
  binary?: { malicious_recall: number; benign_false_positive_rate: number };
  per_class: Record<string, { precision: number; recall: number; f1: number; support: number }>;
  confusion_matrix: { labels: string[]; counts: number[][] };
}

interface RunDetail extends RunRow {
  config: Record<string, unknown>;
  dataset_snapshot: Record<string, unknown> | null;
  metrics: {
    models: Record<string, { test: SplitMetrics; validation: SplitMetrics }>;
    primary_model: string;
    selection_metric: string;
    test_macro_f1_ci?: { low: number; high: number; level: number; resamples: number };
    permutation_importance?: { feature: string; mean: number; std: number }[];
    leakage?: { failures: unknown[]; warnings: unknown[]; shortcut_features: unknown[] };
    comparison?: Record<string, unknown>;
    split?: Record<string, unknown>;
    data?: Record<string, unknown>;
  } | null;
  leakage_checks: Record<string, unknown> | null;
  warnings_acknowledged: boolean;
  environment: Record<string, string> | null;
  job_id: string | null;
}

interface Summary {
  model: { model_id: string; name: string; version: number } | null;
  predictions_by_category: { category: string; count: number }[];
  scored_scope_confusion_matrix?: { note: string; labels: string[]; counts: number[][] };
}

const DEFAULT_TRAINING_CONFIG = {
  name: "attack_classifier",
  random_seed: 42,
  feature_set: "flow_v1",
  label_level: "canonical",
  split_strategy: "group_stratified",
  group_key: "feature_hash",
  test_fraction: 0.2,
  validation_fraction: 0.2,
  min_class_support_train: 50,
  rare_class_policy: "merge",
  snapshot: { batch_ids: [] as string[], event_types: ["network_flow"] },
  models: {
    random_forest: { n_estimators: [100, 300], max_depth: [0, 20], min_samples_leaf: [1, 5] },
  },
};

function TrainForm() {
  const [text, setText] = useState(JSON.stringify(DEFAULT_TRAINING_CONFIG, null, 2));
  const [parseError, setParseError] = useState("");
  const start = useApiMutation<unknown, { id: string; job_id: string }>(
    "POST",
    "/classification/training-runs",
    ["/classification"],
  );
  return (
    <Card title="Start a training run (admin)">
      <p className="mb-2 text-sm text-muted">
        Configuration is validated strictly by the API (unknown keys are rejected). Add the batch
        IDs to train on under <code>snapshot.batch_ids</code>.
      </p>
      <textarea
        aria-label="Training configuration (JSON)"
        className={`${inputClass} h-56 w-full font-mono text-xs`}
        value={text}
        onChange={(e) => setText(e.target.value)}
      />
      <div className="mt-2 flex gap-2">
        <Button
          variant="primary"
          disabled={start.isPending}
          onClick={() => {
            try {
              setParseError("");
              start.mutate(JSON.parse(text));
            } catch {
              setParseError("The configuration is not valid JSON.");
            }
          }}
        >
          Start training
        </Button>
      </div>
      {parseError && (
        <p role="alert" className="text-sm text-danger">
          {parseError}
        </p>
      )}
      <MutationError error={start.error} />
      {start.data && (
        <p className="mt-2 text-sm">
          Run{" "}
          <Link className="text-accent" to={`/classification/runs/${start.data.id}`}>
            {shortId(start.data.id)}
          </Link>
          <JobProgress jobId={start.data.job_id} />
        </p>
      )}
    </Card>
  );
}

export function ClassificationPage() {
  const session = useSession();
  const { range } = useTimeRange();
  const runs = useApi<RunRow[]>("/classification/training-runs");
  const summary = useApi<Summary>("/classification/summary", { from: range.from, to: range.to });
  return (
    <div className="space-y-4">
      <PageHeader title="Classification">
        <TimeRangePicker />
      </PageHeader>
      <Notice>
        Predictions are model outputs, not observations. Scores are uncalibrated and are not
        probabilities.
      </Notice>
      {summary.error && summary.error.status !== 404 ? (
        <ErrorState error={summary.error} />
      ) : summary.error?.status === 404 || (summary.data && !summary.data.model) ? (
        <EmptyState title="No active classifier">
          Train and promote a model to see live predictions.
        </EmptyState>
      ) : summary.data ? (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          <BarChartCard
            title={`Predicted categories — ${summary.data.model?.name} v${summary.data.model?.version}`}
            description="Count of scored events per predicted category in the selected range."
            data={summary.data.predictions_by_category.map((p) => ({
              label: p.category,
              value: p.count,
            }))}
            xLabel="Predicted category"
            yLabel="events"
          />
          {summary.data.scored_scope_confusion_matrix && (
            <ConfusionMatrix
              title="Dataset label vs. prediction (scored scope)"
              note={summary.data.scored_scope_confusion_matrix.note}
              labels={summary.data.scored_scope_confusion_matrix.labels}
              counts={summary.data.scored_scope_confusion_matrix.counts}
            />
          )}
        </div>
      ) : (
        <LoadingSkeleton label="Loading predictions" />
      )}
      <Card title="Training runs">
        <DataTable
          rows={runs.data}
          rowKey={(r) => r.run_id}
          isPending={runs.isPending}
          error={runs.error}
          emptyTitle="No training runs yet"
          emptyHint="Start one below (admin) or with `cti train classifier`."
          columns={[
            {
              key: "id",
              header: "Run",
              render: (r) => (
                <Link className="text-accent" to={`/classification/runs/${r.run_id}`}>
                  {shortId(r.run_id)}
                </Link>
              ),
            },
            { key: "name", header: "Name", render: (r) => r.name },
            { key: "status", header: "Status", render: (r) => <StatusBadge status={r.status} /> },
            { key: "split", header: "Split", render: (r) => r.split_strategy },
            { key: "created", header: "Created", render: (r) => formatTime(r.created_at) },
          ]}
        />
      </Card>
      <ScoredHttpParamsCard range={range} canScore={hasRole(session.data?.user, "analyst")} />
      {hasRole(session.data?.user, "analyst") && <WebPayloadCard />}
      {hasRole(session.data?.user, "admin") && <TrainForm />}
    </div>
  );
}

export function RunDetailPage() {
  const { runId = "" } = useParams();
  const session = useSession();
  const run = useApi<RunDetail>(`/classification/training-runs/${runId}`);
  const [note, setNote] = useState("");
  const ack = useApiMutation<{ note: string }>(
    "POST",
    `/classification/training-runs/${runId}/acknowledge-warnings`,
    ["/classification"],
  );
  if (run.isPending) return <LoadingSkeleton label="Loading run" />;
  if (run.error) return <ErrorState error={run.error} onRetry={() => void run.refetch()} />;
  const r = run.data;
  const m = r.metrics;
  const primary = m ? m.models[m.primary_model] : null;
  const warnings = (m?.leakage?.warnings ?? []) as unknown[];
  const failures = (m?.leakage?.failures ?? []) as unknown[];
  return (
    <div className="space-y-4">
      <PageHeader title={`Training run ${shortId(r.run_id)}`} />
      {r.job_id && !["succeeded", "failed"].includes(r.status) && <JobProgress jobId={r.job_id} />}
      {r.error && <Notice tone="warn">{r.error}</Notice>}
      {(warnings.length > 0 || failures.length > 0) && (
        <Card title="Leakage checks">
          <CodeBlockText
            value={{ failures, warnings, shortcut_features: m?.leakage?.shortcut_features }}
          />
          {warnings.length > 0 &&
            !r.warnings_acknowledged &&
            hasRole(session.data?.user, "admin") && (
              <div className="mt-2 flex items-end gap-2">
                <Field label="Acknowledgement note (min 10 characters)">
                  <input
                    className={`${inputClass} w-96`}
                    value={note}
                    onChange={(e) => setNote(e.target.value)}
                  />
                </Field>
                <Button
                  disabled={note.length < 10 || ack.isPending}
                  onClick={() => ack.mutate({ note })}
                >
                  Acknowledge warnings
                </Button>
              </div>
            )}
          <MutationError error={ack.error} />
        </Card>
      )}
      <Card title="Run">
        <KeyValue
          rows={[
            ["Status", <StatusBadge key="s" status={r.status} />],
            ["Name", r.name],
            ["Split", r.split_strategy],
            ["Feature set", r.feature_set_version],
            ["Selected by", m?.selection_metric],
            ["Snapshot rows", formatNumber(r.dataset_snapshot?.rows as number | undefined)],
            [
              "Snapshot hash",
              <code key="h" className="text-xs break-all">
                {String(r.dataset_snapshot?.snapshot_hash ?? "—")}
              </code>,
            ],
            ["Created / finished", `${formatTime(r.created_at)} / ${formatTime(r.finished_at)}`],
            [
              "Environment",
              r.environment
                ? Object.entries(r.environment)
                    .map(([k, v]) => `${k} ${v}`)
                    .join(", ")
                : "—",
            ],
          ]}
        />
      </Card>
      {m && (
        <Card title="Model comparison (baselines included)">
          <DataTable
            rows={Object.entries(m.models)}
            rowKey={([name]) => name}
            columns={[
              {
                key: "model",
                header: "Model",
                render: ([name]) =>
                  name === m.primary_model ? <strong>{name} (selected)</strong> : name,
              },
              {
                key: "vf1",
                header: "Validation macro-F1",
                render: ([, v]) => formatScore(v.validation.macro_f1),
              },
              {
                key: "tf1",
                header: "Test macro-F1",
                render: ([, v]) => formatScore(v.test.macro_f1),
              },
              {
                key: "twf1",
                header: "Test weighted-F1",
                render: ([, v]) => formatScore(v.test.weighted_f1),
              },
              {
                key: "bacc",
                header: "Test balanced acc.",
                render: ([, v]) => formatScore(v.test.balanced_accuracy),
              },
              {
                key: "rec",
                header: "Malicious recall",
                render: ([, v]) => formatScore(v.test.binary?.malicious_recall),
              },
            ]}
          />
          {m.test_macro_f1_ci && (
            <p className="mt-2 text-sm text-muted">
              Test macro-F1 {Math.round(m.test_macro_f1_ci.level * 100)}% bootstrap interval:{" "}
              {formatScore(m.test_macro_f1_ci.low)} – {formatScore(m.test_macro_f1_ci.high)} (
              {m.test_macro_f1_ci.resamples} resamples).
            </p>
          )}
        </Card>
      )}
      {primary && (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          <Card title={`Per-class test metrics (${m?.primary_model})`}>
            <DataTable
              rows={Object.entries(primary.test.per_class)}
              rowKey={([c]) => c}
              columns={[
                { key: "c", header: "Class", render: ([c]) => c },
                { key: "p", header: "Precision", render: ([, v]) => formatScore(v.precision) },
                { key: "r", header: "Recall", render: ([, v]) => formatScore(v.recall) },
                { key: "f", header: "F1", render: ([, v]) => formatScore(v.f1) },
                { key: "s", header: "Support", render: ([, v]) => formatNumber(v.support) },
              ]}
            />
          </Card>
          <ConfusionMatrix
            title="Confusion matrix (held-out test split)"
            labels={primary.test.confusion_matrix.labels}
            counts={primary.test.confusion_matrix.counts}
          />
        </div>
      )}
      {m?.permutation_importance && (
        <BarChartCard
          title="Permutation importance (test split)"
          description="Mean drop in macro-F1 when a feature is shuffled."
          data={m.permutation_importance
            .slice(0, 15)
            .map((p) => ({ label: p.feature, value: p.mean }))}
          xLabel="Feature"
          yLabel="importance"
        />
      )}
      <Card title="Configuration">
        <CodeBlockText value={r.config} />
      </Card>
    </div>
  );
}

// --- model registry --------------------------------------------------------------------------------

interface ModelRow {
  model_id: string;
  name: string;
  version: number;
  task: string;
  algorithm: string;
  status: string;
  training_run_id: string;
  artifact_sha256: string;
  feature_set_version: string;
  class_labels: string[] | null;
  created_at: string;
  promoted_at: string | null;
  status_note: string | null;
  metrics_summary: Record<string, unknown>;
  latest_drift: { status: string; warnings: number; created_at: string } | null;
}

interface DriftReportRow {
  report_id: string;
  period_start: string;
  period_end: string;
  status: string;
  metrics: Record<string, unknown>;
  warnings: string[];
  created_at: string;
  note: string;
}

const DRIFT_TONE: Record<string, string> = {
  ok: "ok",
  warning: "warn",
  insufficient_data: "muted",
};

function DriftBadge({ drift }: { drift: ModelRow["latest_drift"] }) {
  if (!drift) return <span className="text-muted">not checked</span>;
  return (
    <Badge tone={DRIFT_TONE[drift.status] ?? "muted"}>
      {drift.status.replace("_", " ")}
      {drift.warnings ? ` (${drift.warnings})` : ""}
    </Badge>
  );
}

function DriftPanel({ modelId, canRun }: { modelId: string; canRun: boolean }) {
  const reports = useApi<DriftReportRow[]>(`/models/${modelId}/drift-reports`);
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const start = useApiMutation<Record<string, string>, { job_id: string }>(
    "POST",
    `/models/${modelId}/drift-reports`,
    [`/models/${modelId}`],
  );
  return (
    <Card title="Drift reports">
      <Notice>
        Drift checks are informational. They never retrain, re-threshold, or promote a model.
      </Notice>
      {canRun && (
        <div className="mt-3 flex flex-wrap items-end gap-2">
          <Field label="Check period from (UTC)">
            <input
              type="datetime-local"
              className={inputClass}
              value={from}
              onChange={(e) => setFrom(e.target.value)}
            />
          </Field>
          <Field label="to (UTC)">
            <input
              type="datetime-local"
              className={inputClass}
              value={to}
              onChange={(e) => setTo(e.target.value)}
            />
          </Field>
          <Button
            disabled={!from || !to || start.isPending}
            onClick={() => start.mutate({ from: `${from}:00Z`, to: `${to}:00Z` })}
          >
            Run drift check
          </Button>
        </div>
      )}
      <MutationError error={start.error} />
      {start.data && <JobProgress jobId={start.data.job_id} />}
      <div className="mt-3">
        <DataTable
          rows={reports.data}
          rowKey={(r) => r.report_id}
          isPending={reports.isPending}
          error={reports.error}
          emptyTitle="No drift reports yet"
          columns={[
            {
              key: "p",
              header: "Period (UTC)",
              render: (r) => `${formatTime(r.period_start)} – ${formatTime(r.period_end)}`,
            },
            {
              key: "s",
              header: "Status",
              render: (r) => (
                <Badge tone={DRIFT_TONE[r.status] ?? "muted"}>{r.status.replace("_", " ")}</Badge>
              ),
            },
            {
              key: "w",
              header: "Warnings",
              render: (r) => (r.warnings.length ? r.warnings.join("; ") : "none"),
            },
            {
              key: "m",
              header: "Metrics",
              render: (r) => <SafeText value={JSON.stringify(r.metrics)} max={120} />,
            },
          ]}
        />
      </div>
    </Card>
  );
}

interface ModelDetail extends ModelRow {
  promotion_gate: { eligible: boolean; problems: string[] };
  manifest: Record<string, unknown>;
}

export function ModelsPage() {
  const models = useApi<ModelRow[]>("/models");
  return (
    <div className="space-y-4">
      <PageHeader title="Model registry" />
      <Card>
        <DataTable
          rows={models.data}
          rowKey={(m) => m.model_id}
          isPending={models.isPending}
          error={models.error}
          emptyTitle="No models registered yet"
          emptyHint="Training runs register candidate models."
          columns={[
            {
              key: "name",
              header: "Model",
              render: (m) => (
                <Link className="text-accent" to={`/models/${m.model_id}`}>
                  {m.name} v{m.version}
                </Link>
              ),
            },
            { key: "task", header: "Task", render: (m) => m.task },
            { key: "algo", header: "Algorithm", render: (m) => m.algorithm },
            { key: "status", header: "Status", render: (m) => <StatusBadge status={m.status} /> },
            {
              key: "metric",
              header: "Test macro-F1",
              render: (m) =>
                typeof m.metrics_summary.test_macro_f1 === "number"
                  ? formatScore(m.metrics_summary.test_macro_f1)
                  : "n/a",
            },
            { key: "created", header: "Created", render: (m) => formatTime(m.created_at) },
            { key: "promoted", header: "Promoted", render: (m) => formatTime(m.promoted_at) },
            { key: "drift", header: "Drift", render: (m) => <DriftBadge drift={m.latest_drift} /> },
          ]}
        />
      </Card>
    </div>
  );
}

export function ModelDetailPage() {
  const { modelId = "" } = useParams();
  const session = useSession();
  const isAdmin = hasRole(session.data?.user, "admin");
  const model = useApi<ModelDetail>(`/models/${modelId}`);
  const [reason, setReason] = useState("");
  const invalidate = ["/models", "/dashboard", "/classification", "/anomalies"];
  const promote = useApiMutation<undefined>("POST", `/models/${modelId}/promote`, invalidate);
  const archive = useApiMutation<undefined>("POST", `/models/${modelId}/archive`, invalidate);
  const reject = useApiMutation<{ reason: string }>(
    "POST",
    `/models/${modelId}/reject`,
    invalidate,
  );
  if (model.isPending) return <LoadingSkeleton label="Loading model" />;
  if (model.error) return <ErrorState error={model.error} onRetry={() => void model.refetch()} />;
  const m = model.data;
  return (
    <div className="space-y-4">
      <PageHeader title={`${m.name} v${m.version}`}>
        {isAdmin && m.status === "candidate" && (
          <>
            <ConfirmButton
              label="Promote"
              variant="primary"
              title="Promote this model?"
              description="The current active model with this name will be archived and this one will be used for scoring."
              onConfirm={() => promote.mutate(undefined)}
            />
            <ConfirmButton
              label="Reject"
              variant="danger"
              title="Reject this model?"
              description="Rejected models can never be promoted."
              onConfirm={() => reject.mutate({ reason })}
              confirmDisabled={reason.length < 3}
            >
              <Field label="Reason">
                <input
                  className={inputClass}
                  value={reason}
                  onChange={(e) => setReason(e.target.value)}
                />
              </Field>
            </ConfirmButton>
          </>
        )}
        {isAdmin && m.status !== "archived" && m.status !== "rejected" && (
          <ConfirmButton
            label="Archive"
            title="Archive this model?"
            description="Archived models are kept for audit but no longer used."
            onConfirm={() => archive.mutate(undefined)}
          />
        )}
      </PageHeader>
      <MutationError error={promote.error ?? archive.error ?? reject.error} />
      <Card title="Summary">
        <KeyValue
          rows={[
            ["Status", <StatusBadge key="s" status={m.status} />],
            ["Task / algorithm", `${m.task} / ${m.algorithm}`],
            ["Feature set", m.feature_set_version],
            ["Classes", m.class_labels?.join(", ") ?? "—"],
            [
              "Artifact SHA-256",
              <code key="h" className="text-xs break-all">
                {m.artifact_sha256}
              </code>,
            ],
            [
              "Training run",
              m.task === "classification" ? (
                <Link
                  key="r"
                  className="text-accent"
                  to={`/classification/runs/${m.training_run_id}`}
                >
                  {shortId(m.training_run_id)}
                </Link>
              ) : (
                shortId(m.training_run_id)
              ),
            ],
            ["Created / promoted", `${formatTime(m.created_at)} / ${formatTime(m.promoted_at)}`],
            ["Status note", m.status_note],
            [
              "Promotion gate",
              m.promotion_gate.eligible ? (
                "eligible"
              ) : (
                <ul key="g" className="list-disc pl-5 text-warn">
                  {m.promotion_gate.problems.map((p) => (
                    <li key={p}>{p}</li>
                  ))}
                </ul>
              ),
            ],
          ]}
        />
      </Card>
      <DriftPanel modelId={m.model_id} canRun={hasRole(session.data?.user, "analyst")} />
      <Card title="Metrics summary">
        <CodeBlockText value={m.metrics_summary} />
      </Card>
      <Card title="Manifest">
        <CodeBlockText value={m.manifest} />
      </Card>
    </div>
  );
}

// --- anomalies -------------------------------------------------------------------------------------

interface Deviation {
  feature: string;
  value: number;
  robust_z?: number;
  baseline_median?: number;
  baseline_mad?: number;
  against: string;
}

interface AnomalyRow {
  result_id: number;
  model_id: string;
  method: string;
  entity_type: string;
  entity_value: string;
  window_start: string;
  window_end: string;
  anomaly_score: number;
  score_percentile: number | null;
  threshold: number | null;
  is_flagged: boolean;
  top_deviation: Deviation | null;
}

interface AnomalyDetail extends AnomalyRow {
  feature_snapshot: Record<string, number>;
  baseline: {
    median?: Record<string, number>;
    mad?: Record<string, number>;
    windows?: number;
  } | null;
  top_deviations: Deviation[];
  history: { window_start: string; anomaly_score: number; is_flagged: boolean }[];
  seasonal_comparison: unknown;
  model: { name: string; version: number; status: string };
  linked_events: { endpoint: string; params: Record<string, string> };
  interpretation: string;
}

const INTERPRETATION =
  "Unusual behaviour is not necessarily malicious. Anomaly scores are not probabilities.";

export function AnomaliesPage() {
  const { range } = useTimeRange();
  const [entityType, setEntityType] = useState("");
  const [entity, setEntity] = useState("");
  const [flagged, setFlagged] = useState("true");
  const results = usePaged<AnomalyRow>("/anomalies", {
    from: range.from,
    to: range.to,
    entity_type: entityType || undefined,
    entity_value: entity || undefined,
    is_flagged: flagged || undefined,
    limit: 100,
  });
  return (
    <div className="space-y-4">
      <PageHeader title="Anomalies">
        <TimeRangePicker />
      </PageHeader>
      <Notice tone="warn">{INTERPRETATION}</Notice>
      <Card>
        <div className="flex flex-wrap gap-2">
          <Field label="Entity type">
            <select
              className={inputClass}
              value={entityType}
              onChange={(e) => setEntityType(e.target.value)}
            >
              <option value="">Any</option>
              <option value="account">account</option>
              <option value="host">host</option>
              <option value="src_ip">src_ip</option>
            </select>
          </Field>
          <Field label="Entity">
            <input
              className={inputClass}
              value={entity}
              onChange={(e) => setEntity(e.target.value)}
            />
          </Field>
          <Field label="Flagged">
            <select
              className={inputClass}
              value={flagged}
              onChange={(e) => setFlagged(e.target.value)}
            >
              <option value="true">Flagged only</option>
              <option value="false">Not flagged</option>
            </select>
          </Field>
        </div>
      </Card>
      <Card title="Entity windows (highest score first)">
        <DataTable
          rows={results.data?.pages.flatMap((p) => p.items)}
          rowKey={(a) => String(a.result_id)}
          isPending={results.isPending}
          error={results.error}
          emptyTitle="No anomaly results in this range"
          emptyHint="Score windows with an active anomaly model (`cti score anomaly`)."
          hasMore={results.hasNextPage}
          onLoadMore={() => void results.fetchNextPage()}
          columns={[
            {
              key: "entity",
              header: "Entity",
              render: (a) => (
                <Link className="text-accent" to={`/anomalies/${a.result_id}`}>
                  {a.entity_type} {a.entity_value}
                </Link>
              ),
            },
            { key: "window", header: "Window (UTC)", render: (a) => formatTime(a.window_start) },
            { key: "method", header: "Method", render: (a) => a.method },
            { key: "score", header: "Score", render: (a) => formatScore(a.anomaly_score) },
            {
              key: "pct",
              header: "Percentile",
              render: (a) => formatNumber(a.score_percentile, 1),
            },
            {
              key: "dev",
              header: "Top deviation",
              render: (a) =>
                a.top_deviation
                  ? `${a.top_deviation.feature} = ${formatNumber(a.top_deviation.value, 2)} (median ${formatNumber(a.top_deviation.baseline_median, 2)})`
                  : "—",
            },
          ]}
        />
      </Card>
    </div>
  );
}

export function AnomalyDetailPage() {
  const { resultId = "" } = useParams();
  const session = useSession();
  const detail = useApi<AnomalyDetail>(`/anomalies/${resultId}`);
  if (detail.isPending) return <LoadingSkeleton label="Loading anomaly" />;
  if (detail.error)
    return <ErrorState error={detail.error} onRetry={() => void detail.refetch()} />;
  const d = detail.data;
  const linked = new URLSearchParams(d.linked_events.params).toString();
  return (
    <div className="space-y-4">
      <PageHeader title={`${d.entity_type} ${d.entity_value}`} />
      <Notice tone="warn">{d.interpretation || INTERPRETATION}</Notice>
      <Card title="Window">
        <KeyValue
          rows={[
            ["Window (UTC)", `${formatTime(d.window_start)} – ${formatTime(d.window_end)}`],
            ["Model", `${d.model.name} v${d.model.version} (${d.model.status}), ${d.method}`],
            ["Score / threshold", `${formatScore(d.anomaly_score)} / ${formatScore(d.threshold)}`],
            ["Percentile", formatNumber(d.score_percentile, 1)],
            ["Flagged", d.is_flagged ? "yes" : "no"],
            ["Baseline windows", formatNumber(d.baseline?.windows)],
            [
              "Seasonal comparison",
              typeof d.seasonal_comparison === "string" ? (
                d.seasonal_comparison.replaceAll("_", " ")
              ) : (
                <CodeBlockText key="sc" value={d.seasonal_comparison} />
              ),
            ],
            [
              "Linked events",
              <Link key="l" className="text-accent" to={`/events?${linked}`}>
                Events in this window for this entity
              </Link>,
            ],
          ]}
        />
      </Card>
      <Card title="Features vs. baseline">
        <DataTable
          rows={Object.entries(d.feature_snapshot)}
          rowKey={([f]) => f}
          columns={[
            { key: "f", header: "Feature", render: ([f]) => f },
            { key: "v", header: "This window", render: ([, v]) => formatNumber(v, 3) },
            {
              key: "m",
              header: "Baseline median",
              render: ([f]) => formatNumber(d.baseline?.median?.[f], 3),
            },
            {
              key: "mad",
              header: "Baseline MAD",
              render: ([f]) => formatNumber(d.baseline?.mad?.[f], 3),
            },
          ]}
        />
      </Card>
      <ScoreHistoryChart title="Entity score history" data={d.history} threshold={d.threshold} />
      {hasRole(session.data?.user, "analyst") && (
        <Card title="Analyst feedback">
          <FeedbackForm
            targetType="anomaly_result"
            targetId={String(d.result_id)}
            invalidate={[]}
          />
        </Card>
      )}
    </div>
  );
}
