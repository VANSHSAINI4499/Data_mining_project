import { useApi } from "../api/hooks";
import { ErrorState } from "./States";
import { StatusBadge } from "./ui";

interface Job {
  job_id: string;
  job_type: string;
  status: string;
  progress: { done: number; total: number | null; unit: string } | null;
  result: Record<string, unknown> | null;
  error: string | null;
}

const TERMINAL = new Set(["succeeded", "failed", "cancelled"]);

/** Polls a job every 2 s until it reaches a terminal state; progress only as reported. */
export function JobProgress({ jobId }: { jobId: string }) {
  const job = useApi<Job>(
    `/jobs/${jobId}`,
    {},
    { refetchInterval: (data) => (data && TERMINAL.has(data.status) ? false : 2000) },
  );
  if (job.error) return <ErrorState error={job.error} />;
  const data = job.data;
  if (!data) return <p className="text-sm text-muted">Job {jobId.slice(0, 8)} queued…</p>;
  return (
    <div className="space-y-1 text-sm" role="status">
      <p>
        Job <code>{data.job_type}</code> <StatusBadge status={data.status} />
        {data.progress && (
          <span className="ml-2 text-muted">
            {data.progress.done}
            {data.progress.total !== null ? ` / ${data.progress.total}` : ""} {data.progress.unit}
          </span>
        )}
      </p>
      {data.status === "queued" && (
        <p className="text-xs text-muted">Waiting for the worker (`cti worker`) to pick it up.</p>
      )}
      {data.error && <p className="text-danger">{data.error}</p>}
    </div>
  );
}
