import type { ReactNode } from "react";

import { ApiError } from "../api/client";

export function LoadingSkeleton({ label, lines = 3 }: { label: string; lines?: number }) {
  return (
    <div role="status" aria-label={label} className="animate-pulse space-y-2">
      {Array.from({ length: lines }, (_, i) => (
        <div key={i} className="h-4 rounded bg-line" style={{ width: `${90 - i * 15}%` }} />
      ))}
      <span className="sr-only">{label}</span>
    </div>
  );
}

export function EmptyState({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="rounded border border-dashed border-line bg-surface p-6 text-center">
      <p className="font-medium">{title}</p>
      {children && <div className="mt-2 text-sm text-muted">{children}</div>}
    </div>
  );
}

/** Shows the backend's problem title/detail and request ID; never substitutes data. */
export function ErrorState({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  const apiError = error instanceof ApiError ? error : null;
  const title = apiError?.problem?.title ?? "Something went wrong";
  const detail =
    apiError?.problem?.detail ?? (error instanceof Error ? error.message : String(error));
  return (
    <div role="alert" className="rounded border border-danger/40 bg-danger/5 p-4 text-sm">
      <p className="font-medium text-danger">{title}</p>
      <p className="mt-1">{detail}</p>
      {apiError?.requestId && (
        <p className="mt-1 text-muted">
          Request ID: <code>{apiError.requestId}</code>
        </p>
      )}
      {onRetry && (
        <button
          type="button"
          onClick={onRetry}
          className="mt-3 rounded border border-line bg-surface px-3 py-1 hover:bg-canvas"
        >
          Retry
        </button>
      )}
    </div>
  );
}
