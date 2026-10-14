import type { ReactNode } from "react";

import { EmptyState, ErrorState, LoadingSkeleton } from "./States";

export interface Column<T> {
  key: string;
  header: string;
  render: (row: T) => ReactNode;
  className?: string;
}

/** Semantic table with loading/empty/error states and optional "Load more". */
export function DataTable<T>({
  columns,
  rows,
  rowKey,
  isPending,
  error,
  onRetry,
  emptyTitle = "Nothing to show",
  emptyHint,
  hasMore,
  onLoadMore,
  loadingMore,
  caption,
}: {
  columns: Column<T>[];
  rows: T[] | undefined;
  rowKey: (row: T) => string;
  isPending?: boolean;
  error?: unknown;
  onRetry?: () => void;
  emptyTitle?: string;
  emptyHint?: ReactNode;
  hasMore?: boolean;
  onLoadMore?: () => void;
  loadingMore?: boolean;
  caption?: string;
}) {
  if (error) return <ErrorState error={error} onRetry={onRetry} />;
  if (isPending || rows === undefined) return <LoadingSkeleton label="Loading" lines={4} />;
  if (rows.length === 0) return <EmptyState title={emptyTitle}>{emptyHint}</EmptyState>;
  return (
    <div className="overflow-x-auto">
      <table className="w-full border-collapse text-sm">
        {caption && <caption className="sr-only">{caption}</caption>}
        <thead>
          <tr className="border-b border-line text-left text-muted">
            {columns.map((c) => (
              <th
                key={c.key}
                scope="col"
                className={`px-2 py-1.5 font-medium ${c.className ?? ""}`}
              >
                {c.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={rowKey(row)} className="border-b border-line/60 align-top hover:bg-canvas">
              {columns.map((c) => (
                <td key={c.key} className={`px-2 py-1.5 ${c.className ?? ""}`}>
                  {c.render(row)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
      {hasMore && onLoadMore && (
        <div className="mt-3">
          <button
            type="button"
            onClick={onLoadMore}
            disabled={loadingMore}
            className="rounded border border-line bg-surface px-3 py-1 text-sm hover:bg-canvas disabled:opacity-50"
          >
            {loadingMore ? "Loading…" : "Load more"}
          </button>
        </div>
      )}
    </div>
  );
}
