import { useState, type FormEvent } from "react";
import { Link, useParams, useSearchParams } from "react-router";

import { useApi, usePaged } from "../api/hooks";
import { DataTable } from "../components/DataTable";
import { ErrorState, LoadingSkeleton } from "../components/States";
import {
  Badge,
  Button,
  Card,
  CodeBlockText,
  Field,
  inputClass,
  KeyValue,
  Notice,
  PageHeader,
  ProvenanceTag,
  SafeText,
  StatusBadge,
  TimeRangePicker,
} from "../components/ui";
import { hasRole, useSession } from "../hooks/useSession";
import { formatNumber, formatScore, formatTime, shortId } from "../lib/format";
import { useTimeRange } from "../lib/timeRange";
import { FeedbackForm } from "./FeedbackForm";

interface EventRow {
  event_id: string;
  event_time: string;
  event_type: string;
  src_ip: string | null;
  src_port: number | null;
  dst_ip: string | null;
  dst_port: number | null;
  protocol: string | null;
  user_name: string | null;
  host_name: string | null;
  signature: string | null;
  ground_truth_category: string | null;
  predicted_category?: string | null;
  predicted_score?: number | null;
}

const FILTERS = [
  ["event_type", "Event type"],
  ["src_ip", "Source IP"],
  ["dst_ip", "Destination IP"],
  ["ip", "Either IP"],
  ["dst_port", "Destination port"],
  ["user_name", "User"],
  ["host_name", "Host"],
  ["ground_truth_category", "Dataset label"],
  ["predicted_category", "Predicted category"],
  ["batch_id", "Batch ID"],
] as const;

function FilterBar() {
  const [search, setSearch] = useSearchParams();
  const [draft, setDraft] = useState<Record<string, string>>(() =>
    Object.fromEntries(FILTERS.map(([k]) => [k, search.get(k) ?? ""])),
  );
  const apply = (e: FormEvent) => {
    e.preventDefault();
    setSearch((prev) => {
      const next = new URLSearchParams(prev);
      for (const [key] of FILTERS) {
        if (draft[key]) next.set(key, draft[key].trim());
        else next.delete(key);
      }
      return next;
    });
  };
  return (
    <form
      onSubmit={apply}
      className="grid grid-cols-2 gap-2 md:grid-cols-5"
      aria-label="Event filters"
    >
      {FILTERS.map(([key, label]) => (
        <Field key={key} label={label}>
          <input
            className={inputClass}
            value={draft[key]}
            onChange={(e) => setDraft({ ...draft, [key]: e.target.value })}
          />
        </Field>
      ))}
      <div className="col-span-2 flex items-end gap-2 md:col-span-5">
        <Button type="submit" variant="primary">
          Apply filters
        </Button>
        <Button
          onClick={() => {
            setDraft(Object.fromEntries(FILTERS.map(([k]) => [k, ""])));
            setSearch((prev) => {
              const next = new URLSearchParams(prev);
              FILTERS.forEach(([k]) => next.delete(k));
              return next;
            });
          }}
        >
          Clear
        </Button>
      </div>
    </form>
  );
}

export function EventsPage() {
  const [search] = useSearchParams();
  const { range } = useTimeRange();
  const params: Record<string, string> = { from: range.from, to: range.to, limit: "100" };
  for (const [key] of FILTERS) {
    const value = search.get(key);
    if (value) params[key] = value;
  }
  const events = usePaged<EventRow>("/events", params);
  const rows = events.data?.pages.flatMap((p) => p.items);
  return (
    <div className="space-y-4">
      <PageHeader title="Event explorer">
        <TimeRangePicker />
      </PageHeader>
      <Card>
        <FilterBar />
      </Card>
      <Card title="Events (newest first)">
        <DataTable
          caption="Events"
          rows={rows}
          rowKey={(e) => e.event_id}
          isPending={events.isPending}
          error={events.error}
          onRetry={() => void events.refetch()}
          emptyTitle="No events match these filters in the selected range"
          emptyHint="Widen the time range or clear filters."
          hasMore={events.hasNextPage}
          onLoadMore={() => void events.fetchNextPage()}
          loadingMore={events.isFetchingNextPage}
          columns={[
            {
              key: "time",
              header: "Time (UTC)",
              render: (e) => (
                <Link className="text-accent" to={`/events/${e.event_id}`}>
                  {formatTime(e.event_time)}
                </Link>
              ),
            },
            { key: "type", header: "Type", render: (e) => e.event_type },
            {
              key: "src",
              header: "Source",
              render: (e) => `${e.src_ip ?? "—"}${e.src_port ? `:${e.src_port}` : ""}`,
            },
            {
              key: "dst",
              header: "Destination",
              render: (e) => `${e.dst_ip ?? "—"}${e.dst_port ? `:${e.dst_port}` : ""}`,
            },
            {
              key: "user",
              header: "User / host",
              render: (e) => <SafeText value={e.user_name ?? e.host_name} max={30} />,
            },
            {
              key: "label",
              header: "Dataset label",
              render: (e) => e.ground_truth_category ?? "—",
            },
            {
              key: "pred",
              header: "Prediction (model output)",
              render: (e) =>
                e.predicted_category
                  ? `${e.predicted_category} (${formatScore(e.predicted_score)})`
                  : "—",
            },
          ]}
        />
      </Card>
    </div>
  );
}

interface Classification {
  model: { model_id: string; name: string; version: number; status: string };
  predicted_category: string;
  predicted_score: number;
  class_scores: Record<string, number>;
  scored_at: string;
}

interface Match {
  match_id: number;
  indicator_id: number;
  indicator_type: string;
  display_value: string;
  matched_field: string;
  indicator_confidence_at_match: number;
  indicator_state_at_match: string;
  feed_key: string;
  feed_reliability: string;
}

interface EventDetail {
  event_id: string;
  observed: Record<string, unknown>;
  provenance: {
    source: { source_key: string; name: string };
    batch_id: string;
    original_filename: string;
    record_number: number;
    record_sha256: string;
    adapter_version: string;
    normalizer_version: string;
    time_quality: string;
    timezone_assumption: string | null;
    ingested_at: string;
  };
  ground_truth: {
    label_raw: string;
    attack_category: string | null;
    mapping_status: string;
    label_origin: string;
  } | null;
  model_outputs: { classifications: Classification[] };
  threat_intel: {
    matches: Match[];
    attack_techniques: { technique_id: string; name?: string; via: string; category?: string }[];
  };
  alerts: { alert_id: string; status: string; risk_score: number; title: string }[];
  analyst: {
    feedback: {
      feedback_id: number;
      verdict: string;
      comment: string | null;
      created_at: string;
    }[];
  };
}

function Pivots({ observed }: { observed: Record<string, unknown> }) {
  const links: [string, string][] = [];
  for (const [field, param] of [
    ["src_ip", "ip"],
    ["dst_ip", "ip"],
    ["user_name", "user_name"],
    ["host_name", "host_name"],
  ] as const) {
    const value = observed[field];
    if (typeof value === "string" && value)
      links.push([`${field} ${value}`, `/events?${param}=${encodeURIComponent(value)}`]);
  }
  if (links.length === 0) return null;
  return (
    <p className="flex flex-wrap gap-3 text-sm">
      Pivot:{" "}
      {links.map(([label, to]) => (
        <Link key={label} className="text-accent underline" to={to}>
          same {label}
        </Link>
      ))}
    </p>
  );
}

function RawRecord({ eventId }: { eventId: string }) {
  const [show, setShow] = useState(false);
  const raw = useApi<{ raw_payload: unknown; raw_text: string | null; raw_truncated: boolean }>(
    show ? `/events/${eventId}/raw` : null,
  );
  return (
    <Card
      title="Raw record"
      actions={<Button onClick={() => setShow(!show)}>{show ? "Hide" : "Show"}</Button>}
    >
      {!show && (
        <p className="text-sm text-muted">The original record as received, shown as inert text.</p>
      )}
      {show && raw.isPending && <LoadingSkeleton label="Loading raw record" />}
      {show && raw.error && <ErrorState error={raw.error} />}
      {show && raw.data && (
        <>
          {raw.data.raw_truncated && (
            <Notice tone="warn">The stored raw record was truncated.</Notice>
          )}
          <CodeBlockText value={raw.data.raw_payload ?? raw.data.raw_text} />
        </>
      )}
    </Card>
  );
}

export function EventDetailPage() {
  const { eventId = "" } = useParams();
  const session = useSession();
  const detail = useApi<EventDetail>(`/events/${eventId}`);
  if (detail.isPending) return <LoadingSkeleton label="Loading event" />;
  if (detail.error)
    return <ErrorState error={detail.error} onRetry={() => void detail.refetch()} />;
  const d = detail.data;
  const observed = Object.entries(d.observed).filter(
    ([, v]) => v !== null && !(typeof v === "object" && Object.keys(v as object).length === 0),
  );
  return (
    <div className="space-y-4">
      <PageHeader title={`Event ${d.event_id}`} />
      <Pivots observed={d.observed} />
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card title="Observed" actions={<ProvenanceTag kind="observed" />}>
          <KeyValue
            rows={observed.map(([k, v]) => [
              k,
              typeof v === "object" ? (
                <CodeBlockText key={k} value={v} />
              ) : (
                <SafeText key={k} value={String(v)} />
              ),
            ])}
          />
        </Card>
        <Card title="Provenance">
          <KeyValue
            rows={[
              ["Source", `${d.provenance.source.name} (${d.provenance.source.source_key})`],
              [
                "Batch",
                <Link
                  key="b"
                  className="text-accent"
                  to={`/ingestion/batches/${d.provenance.batch_id}`}
                >
                  {shortId(d.provenance.batch_id)}
                </Link>,
              ],
              ["File", <SafeText key="f" value={d.provenance.original_filename} />],
              ["Record number", formatNumber(d.provenance.record_number)],
              [
                "Record SHA-256",
                <code key="h" className="text-xs break-all">
                  {d.provenance.record_sha256}
                </code>,
              ],
              ["Adapter", d.provenance.adapter_version],
              ["Normaliser", d.provenance.normalizer_version],
              ["Time quality", d.provenance.time_quality],
              ["Timezone assumption", d.provenance.timezone_assumption ?? "none"],
              ["Ingested", formatTime(d.provenance.ingested_at)],
            ]}
          />
        </Card>
        <Card title="Ground truth" actions={<ProvenanceTag kind="dataset" />}>
          {d.ground_truth ? (
            <KeyValue
              rows={[
                ["Raw label", <SafeText key="l" value={d.ground_truth.label_raw} />],
                ["Category", d.ground_truth.attack_category ?? "unmapped"],
                ["Mapping", d.ground_truth.mapping_status],
                ["Origin", d.ground_truth.label_origin],
              ]}
            />
          ) : (
            <p className="text-sm text-muted">This event carries no dataset label.</p>
          )}
        </Card>
        <Card title="Model outputs" actions={<ProvenanceTag kind="model_output" />}>
          {d.model_outputs.classifications.length === 0 ? (
            <p className="text-sm text-muted">No model has scored this event.</p>
          ) : (
            <ul className="space-y-2 text-sm">
              {d.model_outputs.classifications.map((c) => (
                <li key={c.model.model_id}>
                  <strong>{c.predicted_category}</strong> score {formatScore(c.predicted_score)}{" "}
                  from{" "}
                  <Link className="text-accent" to={`/models/${c.model.model_id}`}>
                    {c.model.name} v{c.model.version}
                  </Link>{" "}
                  <StatusBadge status={c.model.status} />
                  <p className="text-xs text-muted">
                    Uncalibrated score, not a probability. Scored {formatTime(c.scored_at)}.
                  </p>
                </li>
              ))}
            </ul>
          )}
        </Card>
        <Card
          title="Threat intelligence & ATT&CK"
          actions={<ProvenanceTag kind="threat_intel_match" />}
        >
          {d.threat_intel.matches.length === 0 && d.threat_intel.attack_techniques.length === 0 ? (
            <p className="text-sm text-muted">No indicator matches or technique references.</p>
          ) : (
            <div className="space-y-2 text-sm">
              {d.threat_intel.matches.map((m) => (
                <p key={m.match_id}>
                  <code>{m.display_value}</code> ({m.indicator_type}) matched in {m.matched_field};{" "}
                  confidence {m.indicator_confidence_at_match}, feed {m.feed_key} (reliability{" "}
                  {m.feed_reliability}), state at match {m.indicator_state_at_match}.{" "}
                  <Link className="text-accent" to={`/threat-intel/indicators/${m.indicator_id}`}>
                    indicator
                  </Link>
                </p>
              ))}
              {d.threat_intel.attack_techniques.length > 0 && (
                <p className="flex flex-wrap gap-1">
                  {d.threat_intel.attack_techniques.map((t, i) => (
                    <Badge key={`${t.technique_id}-${i}`} tone="info">
                      {t.technique_id} via {t.via.replaceAll("_", " ")}
                    </Badge>
                  ))}
                </p>
              )}
              <p className="text-xs text-muted">
                A match means a value appears on a list; it is not proof of compromise.
              </p>
            </div>
          )}
        </Card>
        <Card title="Alerts" actions={<ProvenanceTag kind="hypothesis" />}>
          {d.alerts.length === 0 ? (
            <p className="text-sm text-muted">This event is not evidence in any alert.</p>
          ) : (
            <ul className="space-y-1 text-sm">
              {d.alerts.map((a) => (
                <li key={a.alert_id}>
                  <Link className="text-accent" to={`/alerts/${a.alert_id}`}>
                    <SafeText value={a.title} />
                  </Link>{" "}
                  risk {a.risk_score} <StatusBadge status={a.status} />
                </li>
              ))}
            </ul>
          )}
        </Card>
        <Card title="Analyst feedback" actions={<ProvenanceTag kind="analyst" />}>
          {d.analyst.feedback.length === 0 ? (
            <p className="text-sm text-muted">No analyst feedback yet.</p>
          ) : (
            <ul className="space-y-1 text-sm">
              {d.analyst.feedback.map((f) => (
                <li key={f.feedback_id}>
                  <strong>{f.verdict.replaceAll("_", " ")}</strong> {formatTime(f.created_at)} —{" "}
                  <SafeText value={f.comment} />
                </li>
              ))}
            </ul>
          )}
          {hasRole(session.data?.user, "analyst") && (
            <div className="mt-3">
              <FeedbackForm
                targetType="event"
                targetId={d.event_id}
                invalidate={[`/events/${eventId}`]}
              />
            </div>
          )}
        </Card>
      </div>
      {hasRole(session.data?.user, "analyst") && <RawRecord eventId={eventId} />}
    </div>
  );
}
