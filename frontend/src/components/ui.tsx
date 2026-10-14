import { useState, type ReactNode } from "react";

import { ApiError } from "../api/client";
import { formatTime } from "../lib/format";
import { PRESETS, useTimeRange } from "../lib/timeRange";

export function PageHeader({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
      <h1 className="text-xl font-semibold">{title}</h1>
      {children && <div className="flex flex-wrap items-center gap-2">{children}</div>}
    </div>
  );
}

export function Card({
  title,
  children,
  actions,
}: {
  title?: string;
  children: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <section className="rounded border border-line bg-surface p-4">
      {(title || actions) && (
        <div className="mb-3 flex items-center justify-between gap-2">
          {title && <h2 className="font-medium">{title}</h2>}
          {actions}
        </div>
      )}
      {children}
    </section>
  );
}

/** Banner for interpretation notes that must stay visible (honesty rules). */
export function Notice({
  children,
  tone = "info",
}: {
  children: ReactNode;
  tone?: "info" | "warn";
}) {
  const cls =
    tone === "warn" ? "border-warn/40 bg-warn/5 text-warn" : "border-accent/30 bg-accent/5";
  return <p className={`rounded border px-3 py-2 text-sm ${cls}`}>{children}</p>;
}

const BADGE_TONES: Record<string, string> = {
  ok: "bg-ok/10 text-ok border-ok/30",
  warn: "bg-warn/10 text-warn border-warn/30",
  danger: "bg-danger/10 text-danger border-danger/30",
  info: "bg-accent/10 text-accent border-accent/30",
  muted: "bg-canvas text-muted border-line",
};

const STATUS_TONE: Record<string, string> = {
  completed: "ok",
  succeeded: "ok",
  active: "ok",
  pass: "ok",
  closed: "muted",
  archived: "muted",
  duplicate: "muted",
  dismissed: "muted",
  candidate: "info",
  new: "info",
  queued: "info",
  open: "info",
  acknowledged: "info",
  in_review: "warn",
  investigating: "warn",
  running: "warn",
  processing: "warn",
  warn: "warn",
  escalated: "warn",
  completed_with_errors: "warn",
  expired: "muted",
  revoked: "muted",
  failed: "danger",
  fail: "danger",
  rejected: "danger",
  error: "danger",
  cancelled: "muted",
};

export function Badge({ children, tone = "muted" }: { children: ReactNode; tone?: string }) {
  return (
    <span
      className={`inline-block rounded border px-1.5 py-0.5 text-xs font-medium ${
        BADGE_TONES[tone] ?? BADGE_TONES.muted
      }`}
    >
      {children}
    </span>
  );
}

export function StatusBadge({ status }: { status: string | null | undefined }) {
  if (!status) return <span className="text-muted">—</span>;
  return <Badge tone={STATUS_TONE[status] ?? "muted"}>{status.replaceAll("_", " ")}</Badge>;
}

const SEVERITY_TONE: Record<string, string> = {
  critical: "danger",
  high: "danger",
  medium: "warn",
  low: "info",
};

/** Severity is always spelled out; colour is never the only signal. */
export function SeverityBadge({ severity }: { severity: string | null | undefined }) {
  if (!severity) return <span className="text-muted">—</span>;
  return <Badge tone={SEVERITY_TONE[severity] ?? "muted"}>{severity}</Badge>;
}

export function RiskBadge({ score, severity }: { score: number; severity?: string | null }) {
  return (
    <span className="inline-flex items-center gap-1">
      <strong className="tabular-nums">{score}</strong>
      <SeverityBadge severity={severity} />
    </span>
  );
}

/** Provenance tags (FRONTEND_SPECIFICATION.md §4). */
export const TAGS = {
  observed: { label: "Observed", tone: "ok" },
  model_output: { label: "Model output", tone: "info" },
  threat_intel_match: { label: "Threat intel match", tone: "warn" },
  hypothesis: { label: "Hypothesis", tone: "warn" },
  analyst: { label: "Analyst", tone: "muted" },
  dataset: { label: "Dataset label", tone: "muted" },
} as const;

export function ProvenanceTag({ kind }: { kind: keyof typeof TAGS | string }) {
  const tag = TAGS[kind as keyof typeof TAGS] ?? { label: kind, tone: "muted" };
  return <Badge tone={tag.tone}>{tag.label}</Badge>;
}

export function KeyValue({ rows }: { rows: [string, ReactNode][] }) {
  return (
    <dl className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 text-sm">
      {rows.map(([key, value]) => (
        <div key={key} className="contents">
          <dt className="text-muted">{key}</dt>
          <dd className="min-w-0 break-words">{value ?? "—"}</dd>
        </div>
      ))}
    </dl>
  );
}

/** Untrusted text rendered inertly (React escapes it), truncated with an expand toggle. */
export function SafeText({ value, max = 200 }: { value: string | null | undefined; max?: number }) {
  const [open, setOpen] = useState(false);
  if (value === null || value === undefined || value === "")
    return <span className="text-muted">—</span>;
  if (value.length <= max) return <span className="break-all">{value}</span>;
  return (
    <span className="break-all">
      {open ? value : `${value.slice(0, max)}…`}{" "}
      <button type="button" className="text-accent underline" onClick={() => setOpen(!open)}>
        {open ? "show less" : "show more"}
      </button>
    </span>
  );
}

/** JSON data shown as text, never as HTML. */
export function CodeBlockText({ value }: { value: unknown }) {
  return (
    <pre className="max-h-96 overflow-auto rounded border border-line bg-canvas p-3 text-xs">
      {JSON.stringify(value, null, 2)}
    </pre>
  );
}

export function Button({
  children,
  onClick,
  disabled,
  variant = "default",
  type = "button",
}: {
  children: ReactNode;
  onClick?: () => void;
  disabled?: boolean;
  variant?: "default" | "primary" | "danger";
  type?: "button" | "submit";
}) {
  const cls = {
    default: "border-line bg-surface hover:bg-canvas",
    primary: "border-accent bg-accent text-white hover:opacity-90",
    danger: "border-danger bg-danger text-white hover:opacity-90",
  }[variant];
  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled}
      className={`rounded border px-3 py-1 text-sm disabled:opacity-50 ${cls}`}
    >
      {children}
    </button>
  );
}

export const inputClass = "rounded border border-line bg-surface px-2 py-1 text-sm";

export function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="flex flex-col gap-1 text-sm">
      <span className="text-muted">{label}</span>
      {children}
    </label>
  );
}

export function Tabs({
  tabs,
  active,
  onChange,
}: {
  tabs: { key: string; label: string }[];
  active: string;
  onChange: (key: string) => void;
}) {
  return (
    <div role="tablist" className="mb-4 flex gap-1 border-b border-line">
      {tabs.map((tab) => (
        <button
          key={tab.key}
          type="button"
          role="tab"
          aria-selected={tab.key === active}
          onClick={() => onChange(tab.key)}
          className={`-mb-px border-b-2 px-3 py-1.5 text-sm ${
            tab.key === active ? "border-accent font-medium" : "border-transparent text-muted"
          }`}
        >
          {tab.label}
        </button>
      ))}
    </div>
  );
}

/** Mutation error, including field errors from the API. */
export function MutationError({ error }: { error: unknown }) {
  if (!error) return null;
  const apiError = error instanceof ApiError ? error : null;
  return (
    <div
      role="alert"
      className="rounded border border-danger/40 bg-danger/5 p-2 text-sm text-danger"
    >
      <p>{apiError?.problem?.detail ?? (error instanceof Error ? error.message : String(error))}</p>
      {apiError?.problem?.errors && (
        <ul className="mt-1 list-disc pl-5">
          {apiError.problem.errors.map((e) => (
            <li key={`${e.field}-${e.code}`}>
              {e.field}: {e.message || e.code}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

export function TimeRangePicker() {
  const { range, setPreset, setAbsolute } = useTimeRange();
  const [from, setFrom] = useState(range.from.slice(0, 16));
  const [to, setTo] = useState(range.to.slice(0, 16));
  return (
    <div className="flex flex-wrap items-end gap-2 text-sm" aria-label="Time range">
      <Field label="Time range (UTC)">
        <select
          className={inputClass}
          value={range.preset ?? "custom"}
          onChange={(e) => e.target.value !== "custom" && setPreset(e.target.value)}
        >
          {PRESETS.map((p) => (
            <option key={p.key} value={p.key}>
              {p.label}
            </option>
          ))}
          <option value="custom">Custom</option>
        </select>
      </Field>
      <Field label="From">
        <input
          type="datetime-local"
          className={inputClass}
          value={from}
          onChange={(e) => setFrom(e.target.value)}
        />
      </Field>
      <Field label="To">
        <input
          type="datetime-local"
          className={inputClass}
          value={to}
          onChange={(e) => setTo(e.target.value)}
        />
      </Field>
      <Button onClick={() => from && to && setAbsolute(`${from}:00Z`, `${to}:00Z`)}>Apply</Button>
      <span className="text-xs text-muted">
        {formatTime(range.from)} – {formatTime(range.to)}
      </span>
    </div>
  );
}
