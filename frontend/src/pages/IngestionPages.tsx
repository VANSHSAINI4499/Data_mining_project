import { useState, type FormEvent } from "react";
import { Link, useParams } from "react-router";

import { useApi, useApiMutation, usePaged } from "../api/hooks";
import { DataTable } from "../components/DataTable";
import { JobProgress } from "../components/JobProgress";
import { ErrorState, LoadingSkeleton } from "../components/States";
import {
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
} from "../components/ui";
import { hasRole, useSession } from "../hooks/useSession";
import { formatBytes, formatNumber, formatTime, shortId } from "../lib/format";

export interface Source {
  source_id: number;
  source_key: string;
  name: string;
  source_type: string;
  default_adapter: string | null;
  default_timezone: string | null;
  reliability: string;
  description: string | null;
  is_active: boolean;
}

interface Adapter {
  name: string;
  version: string;
  description: string;
  extensions: string[];
  variants: string[];
}

export interface Batch {
  batch_id: string;
  source_id: number;
  adapter: string;
  original_filename: string;
  file_sha256: string;
  file_size_bytes: number;
  status: string;
  records_total: number;
  records_loaded: number;
  records_rejected: number;
  records_duplicate: number;
  timezone_assumption: string | null;
  label_mapping_version: string | null;
  metadata: Record<string, unknown>;
  error_summary: unknown;
  duplicate_of: string | null;
  job_id: string | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
}

interface DqResult {
  check_name: string;
  status: string;
  metric_value: number | null;
  threshold: number | null;
  details: Record<string, unknown>;
  checked_at: string;
}

interface Rejection {
  record_number: number;
  error_code: string;
  field_name: string | null;
  error_detail: string;
}

const MAX_UPLOAD_MB = 50;

function UploadForm() {
  const sources = useApi<Source[]>("/sources");
  const adapters = useApi<Adapter[]>("/adapters");
  const [file, setFile] = useState<File | null>(null);
  const [sourceId, setSourceId] = useState("");
  const [adapter, setAdapter] = useState("");
  const [variant, setVariant] = useState("");
  const [assumeDate, setAssumeDate] = useState("");
  const [localError, setLocalError] = useState("");
  const upload = useApiMutation<
    FormData,
    { batch_id: string; job_id: string | null; status: string }
  >("POST", "/ingestion/uploads", ["/ingestion", "/dashboard"]);
  const selected = adapters.data?.find((a) => a.name === adapter);

  const submit = (e: FormEvent) => {
    e.preventDefault();
    setLocalError("");
    if (!file || !sourceId) return setLocalError("Choose a source and a file.");
    // Pre-check only; the server enforces limits and formats.
    if (file.size > MAX_UPLOAD_MB * 1024 * 1024)
      return setLocalError(`Files are limited to ${MAX_UPLOAD_MB} MB.`);
    const form = new FormData();
    form.append("file", file);
    form.append("source_id", sourceId);
    if (adapter) form.append("adapter", adapter);
    if (variant) form.append("variant", variant);
    if (assumeDate) form.append("assume_event_date", assumeDate);
    upload.mutate(form);
  };

  return (
    <Card title="Upload a file">
      <form onSubmit={submit} className="grid grid-cols-1 gap-3 md:grid-cols-3">
        <Field label="Source">
          <select
            className={inputClass}
            value={sourceId}
            onChange={(e) => setSourceId(e.target.value)}
          >
            <option value="">Select…</option>
            {sources.data?.map((s) => (
              <option key={s.source_id} value={s.source_id}>
                {s.name} ({s.source_key})
              </option>
            ))}
          </select>
        </Field>
        <Field label="Adapter (default: the source's)">
          <select
            className={inputClass}
            value={adapter}
            onChange={(e) => setAdapter(e.target.value)}
          >
            <option value="">Source default</option>
            {adapters.data?.map((a) => (
              <option key={a.name} value={a.name}>
                {a.name} ({a.extensions.join(", ")})
              </option>
            ))}
          </select>
        </Field>
        {selected && selected.variants.length > 0 && (
          <Field label="Variant">
            <select
              className={inputClass}
              value={variant}
              onChange={(e) => setVariant(e.target.value)}
            >
              <option value="">Auto-detect</option>
              {selected.variants.map((v) => (
                <option key={v}>{v}</option>
              ))}
            </select>
          </Field>
        )}
        <Field label="Assumed event date (only for files without timestamps)">
          <input
            type="date"
            className={inputClass}
            value={assumeDate}
            onChange={(e) => setAssumeDate(e.target.value)}
          />
        </Field>
        <Field label="File">
          <input type="file" onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
        </Field>
        <div className="flex items-end">
          <Button type="submit" variant="primary" disabled={upload.isPending}>
            {upload.isPending ? "Uploading…" : "Upload"}
          </Button>
        </div>
      </form>
      {assumeDate && (
        <div className="mt-3">
          <Notice tone="warn">
            Assumed dates are recorded as assumptions; such events are classification-only and are
            excluded from anomaly windows and temporal correlation.
          </Notice>
        </div>
      )}
      <div className="mt-3 space-y-2">
        {localError && (
          <p role="alert" className="text-sm text-danger">
            {localError}
          </p>
        )}
        <MutationError error={upload.error} />
        {upload.data && (
          <div className="text-sm">
            <p>
              Batch{" "}
              <Link className="text-accent" to={`/ingestion/batches/${upload.data.batch_id}`}>
                {shortId(upload.data.batch_id)}
              </Link>{" "}
              <StatusBadge status={upload.data.status} />
            </p>
            {upload.data.job_id && <JobProgress jobId={upload.data.job_id} />}
          </div>
        )}
      </div>
    </Card>
  );
}

export function IngestionPage() {
  const session = useSession();
  const canUpload = hasRole(session.data?.user, "analyst");
  const batches = usePaged<Batch>("/ingestion/batches", { limit: 50 });
  const rows = batches.data?.pages.flatMap((p) => p.items);
  return (
    <div className="space-y-4">
      <PageHeader title="Data ingestion" />
      {canUpload && <UploadForm />}
      <Card title="Ingestion batches">
        <DataTable
          caption="Ingestion batches"
          rows={rows}
          rowKey={(b) => b.batch_id}
          isPending={batches.isPending}
          error={batches.error}
          onRetry={() => void batches.refetch()}
          emptyTitle="No ingestion batches yet"
          emptyHint="Upload a file above or run `cti ingest`."
          hasMore={batches.hasNextPage}
          onLoadMore={() => void batches.fetchNextPage()}
          loadingMore={batches.isFetchingNextPage}
          columns={[
            {
              key: "id",
              header: "Batch",
              render: (b) => (
                <Link className="text-accent" to={`/ingestion/batches/${b.batch_id}`}>
                  {shortId(b.batch_id)}
                </Link>
              ),
            },
            {
              key: "file",
              header: "File",
              render: (b) => <SafeText value={b.original_filename} max={40} />,
            },
            { key: "adapter", header: "Adapter", render: (b) => b.adapter },
            { key: "status", header: "Status", render: (b) => <StatusBadge status={b.status} /> },
            {
              key: "loaded",
              header: "Loaded",
              render: (b) => formatNumber(b.records_loaded),
              className: "text-right",
            },
            {
              key: "rejected",
              header: "Rejected",
              render: (b) => formatNumber(b.records_rejected),
              className: "text-right",
            },
            {
              key: "dup",
              header: "Duplicates",
              render: (b) => formatNumber(b.records_duplicate),
              className: "text-right",
            },
            { key: "created", header: "Created", render: (b) => formatTime(b.created_at) },
          ]}
        />
      </Card>
    </div>
  );
}

export function BatchDetailPage() {
  const { batchId = "" } = useParams();
  const session = useSession();
  const batch = useApi<Batch>(`/ingestion/batches/${batchId}`);
  const dq = useApi<DqResult[]>(`/data-quality/batches/${batchId}`);
  const rejections = usePaged<Rejection>(`/ingestion/batches/${batchId}/rejections`, { limit: 50 });
  const retry = useApiMutation<undefined, Batch>("POST", `/ingestion/batches/${batchId}/retry`, [
    "/ingestion",
  ]);
  if (batch.isPending) return <LoadingSkeleton label="Loading batch" />;
  if (batch.error) return <ErrorState error={batch.error} onRetry={() => void batch.refetch()} />;
  const b = batch.data;
  const accounted = b.records_loaded + b.records_rejected + b.records_duplicate;
  return (
    <div className="space-y-4">
      <PageHeader title={`Batch ${shortId(b.batch_id)}`}>
        {b.status === "failed" && hasRole(session.data?.user, "analyst") && (
          <Button onClick={() => retry.mutate(undefined)} disabled={retry.isPending}>
            Retry
          </Button>
        )}
      </PageHeader>
      <MutationError error={retry.error} />
      {retry.data?.job_id && <JobProgress jobId={retry.data.job_id} />}
      {b.job_id &&
        !["completed", "failed", "duplicate", "completed_with_errors"].includes(b.status) && (
          <JobProgress jobId={b.job_id} />
        )}
      <Card title="Summary">
        <KeyValue
          rows={[
            ["Status", <StatusBadge key="s" status={b.status} />],
            ["File", <SafeText key="f" value={b.original_filename} />],
            ["Size", formatBytes(b.file_size_bytes)],
            [
              "SHA-256",
              <code key="h" className="text-xs">
                {b.file_sha256}
              </code>,
            ],
            ["Adapter", b.adapter],
            ["Records total", formatNumber(b.records_total)],
            [
              "Loaded / rejected / duplicate",
              `${formatNumber(b.records_loaded)} / ${formatNumber(b.records_rejected)} / ${formatNumber(b.records_duplicate)}` +
                (b.records_total
                  ? accounted === b.records_total
                    ? " (reconciled)"
                    : " (does not add up)"
                  : ""),
            ],
            [
              "Timezone assumption",
              b.timezone_assumption ?? "none (timestamps carried their own offset)",
            ],
            ["Label mapping", b.label_mapping_version],
            [
              "Duplicate of",
              b.duplicate_of ? (
                <Link key="d" className="text-accent" to={`/ingestion/batches/${b.duplicate_of}`}>
                  {shortId(b.duplicate_of)}
                </Link>
              ) : null,
            ],
            ["Created", formatTime(b.created_at)],
            ["Finished", formatTime(b.finished_at)],
            [
              "Events",
              <Link key="e" className="text-accent" to={`/events?batch_id=${b.batch_id}`}>
                View events from this batch
              </Link>,
            ],
          ]}
        />
        {b.error_summary ? (
          <div className="mt-3">
            <CodeBlockText value={b.error_summary} />
          </div>
        ) : null}
      </Card>
      <Card title="Data-quality checks">
        <DataTable
          rows={dq.data}
          rowKey={(r) => r.check_name}
          isPending={dq.isPending}
          error={dq.error}
          emptyTitle="No data-quality results for this batch"
          columns={[
            { key: "check", header: "Check", render: (r) => r.check_name },
            { key: "status", header: "Status", render: (r) => <StatusBadge status={r.status} /> },
            { key: "value", header: "Value", render: (r) => formatNumber(r.metric_value, 3) },
            { key: "threshold", header: "Threshold", render: (r) => formatNumber(r.threshold, 3) },
          ]}
        />
      </Card>
      <Card title="Rejected records">
        <DataTable
          rows={rejections.data?.pages.flatMap((p) => p.items)}
          rowKey={(r) => String(r.record_number)}
          isPending={rejections.isPending}
          error={rejections.error}
          emptyTitle="No rejected records"
          hasMore={rejections.hasNextPage}
          onLoadMore={() => void rejections.fetchNextPage()}
          columns={[
            { key: "n", header: "Record", render: (r) => r.record_number },
            { key: "code", header: "Error", render: (r) => r.error_code },
            { key: "field", header: "Field", render: (r) => r.field_name ?? "—" },
            {
              key: "detail",
              header: "Detail",
              render: (r) => <SafeText value={r.error_detail} max={160} />,
            },
          ]}
        />
      </Card>
    </div>
  );
}
