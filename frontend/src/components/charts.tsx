import { useState, type ReactNode } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import { formatNumber } from "../lib/format";
import { EmptyState } from "./States";

// Colour-blind-safe categorical palette (Okabe-Ito), assigned by sorted key order.
export const PALETTE = [
  "#0072B2",
  "#E69F00",
  "#009E73",
  "#D55E00",
  "#CC79A7",
  "#56B4E9",
  "#F0E442",
  "#000000",
  "#999999",
  "#882255",
  "#44AA99",
];

export interface TableData {
  columns: string[];
  rows: (string | number)[][];
}

/** Chart wrapper: title, units, empty state, and an accessible "view as table" toggle. */
export function ChartCard({
  title,
  description,
  isEmpty,
  emptyText = "No data in the selected range.",
  table,
  children,
}: {
  title: string;
  description?: string;
  isEmpty: boolean;
  emptyText?: string;
  table: TableData;
  children: ReactNode;
}) {
  const [asTable, setAsTable] = useState(false);
  return (
    <figure className="rounded border border-line bg-surface p-4" aria-label={title}>
      <div className="mb-2 flex items-start justify-between gap-2">
        <figcaption>
          <p className="font-medium">{title}</p>
          {description && <p className="text-xs text-muted">{description}</p>}
        </figcaption>
        {!isEmpty && (
          <button
            type="button"
            className="text-xs text-accent underline"
            onClick={() => setAsTable(!asTable)}
          >
            {asTable ? "View as chart" : "View as table"}
          </button>
        )}
      </div>
      {isEmpty ? (
        <EmptyState title={emptyText} />
      ) : asTable ? (
        <div className="max-h-80 overflow-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-line text-left text-muted">
                {table.columns.map((c) => (
                  <th key={c} scope="col" className="px-2 py-1 font-medium">
                    {c}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {table.rows.map((row, i) => (
                <tr key={i} className="border-b border-line/60">
                  {row.map((cell, j) => (
                    <td key={j} className="px-2 py-1 tabular-nums">
                      {typeof cell === "number"
                        ? formatNumber(cell, Number.isInteger(cell) ? 0 : 3)
                        : cell}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="h-64 w-full">{children}</div>
      )}
    </figure>
  );
}

export interface SeriesPoint {
  ts: string;
  [series: string]: number | string;
}

export function TimeSeriesChart({
  title,
  description,
  data,
  series,
  yLabel,
  stacked = true,
}: {
  title: string;
  description?: string;
  data: SeriesPoint[];
  series: string[];
  yLabel: string;
  stacked?: boolean;
}) {
  const table: TableData = {
    columns: ["Bucket (UTC)", ...series],
    rows: data.map((d) => [d.ts, ...series.map((s) => Number(d[s] ?? 0))]),
  };
  return (
    <ChartCard title={title} description={description} isEmpty={data.length === 0} table={table}>
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} margin={{ left: 8, right: 8 }}>
          <CartesianGrid strokeDasharray="3 3" />
          <XAxis dataKey="ts" tickFormatter={(v: string) => v.slice(0, 10)} fontSize={11} />
          <YAxis
            fontSize={11}
            domain={[0, "auto"]}
            label={{ value: yLabel, angle: -90, position: "insideLeft", fontSize: 11 }}
          />
          <Tooltip />
          {series.length > 1 && <Legend />}
          {series.map((s, i) => (
            <Bar
              key={s}
              dataKey={s}
              stackId={stacked ? "a" : undefined}
              fill={PALETTE[i % PALETTE.length]}
            />
          ))}
        </BarChart>
      </ResponsiveContainer>
    </ChartCard>
  );
}

export function BarChartCard({
  title,
  description,
  data,
  xLabel,
  yLabel,
}: {
  title: string;
  description?: string;
  data: { label: string; value: number }[];
  xLabel: string;
  yLabel: string;
}) {
  return (
    <ChartCard
      title={title}
      description={description}
      isEmpty={data.length === 0}
      table={{ columns: [xLabel, yLabel], rows: data.map((d) => [d.label, d.value]) }}
    >
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} margin={{ left: 8, right: 8 }}>
          <CartesianGrid strokeDasharray="3 3" />
          <XAxis dataKey="label" fontSize={11} />
          <YAxis
            fontSize={11}
            domain={[0, "auto"]}
            label={{ value: yLabel, angle: -90, position: "insideLeft", fontSize: 11 }}
          />
          <Tooltip />
          <Bar dataKey="value" name={yLabel} fill={PALETTE[0]} />
        </BarChart>
      </ResponsiveContainer>
    </ChartCard>
  );
}

export function ScoreHistoryChart({
  title,
  data,
  threshold,
}: {
  title: string;
  data: { window_start: string; anomaly_score: number }[];
  threshold: number | null;
}) {
  return (
    <ChartCard
      title={title}
      description="Anomaly score per window; dashed line is the model threshold. Scores are not probabilities."
      isEmpty={data.length === 0}
      table={{
        columns: ["Window start (UTC)", "Score"],
        rows: data.map((d) => [d.window_start, d.anomaly_score]),
      }}
    >
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={data} margin={{ left: 8, right: 8 }}>
          <CartesianGrid strokeDasharray="3 3" />
          <XAxis
            dataKey="window_start"
            tickFormatter={(v: string) => v.slice(0, 13)}
            fontSize={11}
          />
          <YAxis fontSize={11} label={{ value: "score", angle: -90, position: "insideLeft" }} />
          <Tooltip />
          <Line dataKey="anomaly_score" stroke={PALETTE[0]} dot />
          {threshold !== null && (
            <ReferenceLine
              y={threshold}
              stroke={PALETTE[3]}
              strokeDasharray="4 4"
              label="threshold"
            />
          )}
        </LineChart>
      </ResponsiveContainer>
    </ChartCard>
  );
}

/** Confusion matrix as a CSS grid with counts and row-normalised percentages. */
export function ConfusionMatrix({
  labels,
  counts,
  title,
  note,
}: {
  labels: string[];
  counts: number[][];
  title: string;
  note?: string;
}) {
  const [normalised, setNormalised] = useState(false);
  if (labels.length === 0) return <EmptyState title="No confusion matrix available" />;
  const max = Math.max(1, ...counts.flat());
  return (
    <figure className="rounded border border-line bg-surface p-4" aria-label={title}>
      <div className="mb-2 flex items-start justify-between gap-2">
        <figcaption>
          <p className="font-medium">{title}</p>
          {note && <p className="text-xs text-muted">{note}</p>}
        </figcaption>
        <button
          type="button"
          className="text-xs text-accent underline"
          onClick={() => setNormalised(!normalised)}
        >
          {normalised ? "Show counts" : "Show row %"}
        </button>
      </div>
      <div className="overflow-x-auto">
        <table className="text-xs">
          <thead>
            <tr>
              <th scope="col" className="px-2 py-1 text-left text-muted">
                true ↓ / predicted →
              </th>
              {labels.map((l) => (
                <th key={l} scope="col" className="px-2 py-1 font-medium">
                  {l}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {counts.map((row, i) => {
              const total = row.reduce((a, b) => a + b, 0);
              return (
                <tr key={labels[i]}>
                  <th scope="row" className="px-2 py-1 text-left font-medium">
                    {labels[i]}
                  </th>
                  {row.map((value, j) => {
                    const share = total ? value / total : 0;
                    return (
                      <td
                        key={j}
                        className={`px-2 py-1 text-center tabular-nums ${i === j ? "font-semibold" : ""}`}
                        style={{ backgroundColor: `rgba(0, 114, 178, ${(value / max) * 0.6})` }}
                      >
                        {normalised ? `${formatNumber(share * 100, 1)}%` : value}
                      </td>
                    );
                  })}
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </figure>
  );
}
