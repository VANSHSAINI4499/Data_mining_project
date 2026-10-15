import { useState, type FormEvent } from "react";
import { Link, useParams } from "react-router";

import { useApi, useApiMutation, usePaged, without } from "../api/hooks";
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
  Tabs,
} from "../components/ui";
import { hasRole, useSession } from "../hooks/useSession";
import { formatNumber, formatTime } from "../lib/format";
import { useSearchParam } from "../lib/timeRange";

export interface Feed {
  feed_id: string;
  feed_key: string;
  name: string;
  feed_type: string;
  reliability: string;
  default_confidence: number;
  default_ttl_days: number;
  enabled: boolean;
  last_success_at: string | null;
  last_error: string | null;
  indicator_count: number;
  health: string;
}

interface Indicator {
  indicator_id: number;
  feed_key: string;
  feed_reliability: string;
  indicator_type: string;
  display_value: string;
  confidence: number;
  tlp: string | null;
  description: string | null;
  first_seen: string;
  last_seen: string;
  valid_from: string;
  valid_until: string | null;
  revoked: boolean;
  technique_ids: string[];
  state: string | null;
  matchable: boolean;
}

interface IndicatorDetail extends Indicator {
  versions: { version_no: number; snapshot: Record<string, unknown>; changed_at: string }[];
  match_count: number;
  stix_id: string | null;
}

interface MatchRow {
  match_id: number;
  event_id: string;
  event_time: string;
  indicator_id: number;
  indicator_type: string;
  display_value: string;
  matched_field: string;
  indicator_confidence_at_match: number;
  indicator_state_at_match: string;
  feed_key: string;
}

const NOT_PROOF =
  "A match means an observed value appears on a list; it is not proof of compromise.";

function FeedsTab({ isAdmin }: { isAdmin: boolean }) {
  const feeds = useApi<Feed[]>("/threat-intel/feeds");
  const toggle = useApiMutation<{ feed_id: string; enabled: boolean }>(
    "PATCH",
    (b) => `/threat-intel/feeds/${b.feed_id}`,
    ["/threat-intel"],
    without("feed_id"),
  );
  const sync = useApiMutation<{ feed_id: string }, { job_id: string }>(
    "POST",
    (b) => `/threat-intel/feeds/${b.feed_id}/sync`,
    ["/threat-intel"],
    () => undefined,
  );
  if (feeds.data && feeds.data.length === 0)
    return (
      <EmptyState title="No feeds configured — the system works without them">
        Threat intelligence is optional. Import indicator files once a feed exists.
      </EmptyState>
    );
  return (
    <>
      <MutationError error={toggle.error ?? sync.error} />
      {sync.data && <JobProgress jobId={sync.data.job_id} />}
      <DataTable
        rows={feeds.data}
        rowKey={(f) => f.feed_id}
        isPending={feeds.isPending}
        error={feeds.error}
        columns={[
          { key: "key", header: "Feed", render: (f) => `${f.name} (${f.feed_key})` },
          { key: "type", header: "Type", render: (f) => f.feed_type },
          { key: "rel", header: "Reliability", render: (f) => f.reliability },
          { key: "count", header: "Indicators", render: (f) => formatNumber(f.indicator_count) },
          {
            key: "health",
            header: "Health",
            render: (f) => <StatusBadge status={f.health === "ok" ? "active" : f.health} />,
          },
          { key: "last", header: "Last success", render: (f) => formatTime(f.last_success_at) },
          {
            key: "enabled",
            header: "Enabled",
            render: (f) =>
              isAdmin ? (
                <span className="flex gap-1">
                  <Button
                    onClick={() => toggle.mutate({ feed_id: f.feed_id, enabled: !f.enabled })}
                  >
                    {f.enabled ? "Disable" : "Enable"}
                  </Button>
                  {f.feed_type === "taxii" && (
                    <Button onClick={() => sync.mutate({ feed_id: f.feed_id })}>Sync now</Button>
                  )}
                </span>
              ) : f.enabled ? (
                "yes"
              ) : (
                "no"
              ),
          },
        ]}
      />
    </>
  );
}

function IndicatorsTab() {
  const [type, setType] = useState("");
  const [state, setState] = useState("");
  const [value, setValue] = useState("");
  const indicators = usePaged<Indicator>("/threat-intel/indicators", {
    indicator_type: type || undefined,
    state: state || undefined,
    value: value || undefined,
    limit: 100,
  });
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap gap-2">
        <Field label="Type">
          <select className={inputClass} value={type} onChange={(e) => setType(e.target.value)}>
            <option value="">Any</option>
            {["ipv4", "ipv6", "domain", "url", "sha256", "sha1", "md5", "email"].map((t) => (
              <option key={t}>{t}</option>
            ))}
          </select>
        </Field>
        <Field label="State (now)">
          <select className={inputClass} value={state} onChange={(e) => setState(e.target.value)}>
            <option value="">Any</option>
            <option value="active">active</option>
            <option value="expired">expired</option>
            <option value="revoked">revoked</option>
          </select>
        </Field>
        <Field label="Exact value">
          <input className={inputClass} value={value} onChange={(e) => setValue(e.target.value)} />
        </Field>
      </div>
      <DataTable
        rows={indicators.data?.pages.flatMap((p) => p.items)}
        rowKey={(i) => String(i.indicator_id)}
        isPending={indicators.isPending}
        error={indicators.error}
        emptyTitle="No indicators"
        emptyHint="Import a CSV or STIX 2.1 file, or add one manually (admin)."
        hasMore={indicators.hasNextPage}
        onLoadMore={() => void indicators.fetchNextPage()}
        columns={[
          {
            key: "value",
            header: "Value (defanged)",
            render: (i) => (
              <Link className="text-accent" to={`/threat-intel/indicators/${i.indicator_id}`}>
                <code>{i.display_value}</code>
              </Link>
            ),
          },
          { key: "type", header: "Type", render: (i) => i.indicator_type },
          { key: "conf", header: "Confidence", render: (i) => i.confidence },
          { key: "feed", header: "Feed", render: (i) => `${i.feed_key} (${i.feed_reliability})` },
          { key: "state", header: "State now", render: (i) => <StatusBadge status={i.state} /> },
          { key: "valid", header: "Valid until", render: (i) => formatTime(i.valid_until) },
          { key: "tech", header: "ATT&CK", render: (i) => i.technique_ids.join(", ") || "—" },
        ]}
      />
    </div>
  );
}

function MatchesTab() {
  const matches = usePaged<MatchRow>("/threat-intel/matches", { limit: 100 });
  const session = useSession();
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const run = useApiMutation<Record<string, string>, { job_id: string }>(
    "POST",
    "/threat-intel/match-runs",
    ["/threat-intel"],
  );
  return (
    <div className="space-y-3">
      <Notice>{NOT_PROOF}</Notice>
      {hasRole(session.data?.user, "analyst") && (
        <div className="flex flex-wrap items-end gap-2">
          <Field label="Match events from (UTC)">
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
            disabled={!from || !to || run.isPending}
            onClick={() => run.mutate({ from: `${from}:00Z`, to: `${to}:00Z` })}
          >
            Run matching
          </Button>
        </div>
      )}
      <MutationError error={run.error} />
      {run.data && <JobProgress jobId={run.data.job_id} />}
      <DataTable
        rows={matches.data?.pages.flatMap((p) => p.items)}
        rowKey={(m) => String(m.match_id)}
        isPending={matches.isPending}
        error={matches.error}
        emptyTitle="No indicator matches"
        hasMore={matches.hasNextPage}
        onLoadMore={() => void matches.fetchNextPage()}
        columns={[
          {
            key: "event",
            header: "Event time (UTC)",
            render: (m) => (
              <Link className="text-accent" to={`/events/${m.event_id}`}>
                {formatTime(m.event_time)}
              </Link>
            ),
          },
          { key: "value", header: "Matched value", render: (m) => <code>{m.display_value}</code> },
          { key: "field", header: "Field", render: (m) => m.matched_field },
          {
            key: "conf",
            header: "Confidence at match",
            render: (m) => m.indicator_confidence_at_match,
          },
          {
            key: "state",
            header: "State at match",
            render: (m) => <StatusBadge status={m.indicator_state_at_match} />,
          },
          { key: "feed", header: "Feed", render: (m) => m.feed_key },
        ]}
      />
    </div>
  );
}

interface FeedRun {
  status: string;
  indicators_received: number;
  indicators_created: number;
  indicators_updated: number;
  indicators_rejected: number;
  error: string | null;
  report: { rejected?: unknown[]; unsupported_patterns?: unknown[] };
}

function ImportTab() {
  const feeds = useApi<Feed[]>("/threat-intel/feeds");
  const [feedId, setFeedId] = useState("");
  const [format, setFormat] = useState("csv");
  const [file, setFile] = useState<File | null>(null);
  const start = useApiMutation<FormData, { id: string; job_id: string }>(
    "POST",
    "/threat-intel/imports",
    ["/threat-intel"],
  );
  const report = useApi<FeedRun>(
    start.data ? `/threat-intel/imports/${start.data.id}` : null,
    {},
    {
      refetchInterval: (d) => (d && ["succeeded", "failed"].includes(d.status) ? false : 2000),
    },
  );
  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (!file || !feedId) return;
    const form = new FormData();
    form.append("file", file);
    form.append("feed_id", feedId);
    form.append("format", format);
    start.mutate(form);
  };
  return (
    <div className="space-y-3">
      <form onSubmit={submit} className="flex flex-wrap items-end gap-2">
        <Field label="Feed">
          <select className={inputClass} value={feedId} onChange={(e) => setFeedId(e.target.value)}>
            <option value="">Select…</option>
            {feeds.data?.map((f) => (
              <option key={f.feed_id} value={f.feed_id}>
                {f.feed_key}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Format">
          <select className={inputClass} value={format} onChange={(e) => setFormat(e.target.value)}>
            <option value="csv">CSV</option>
            <option value="stix">STIX 2.1 bundle (JSON)</option>
          </select>
        </Field>
        <Field label="File">
          <input type="file" onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
        </Field>
        <Button type="submit" variant="primary" disabled={!file || !feedId || start.isPending}>
          Import
        </Button>
      </form>
      <MutationError error={start.error} />
      {start.data && <JobProgress jobId={start.data.job_id} />}
      {report.data && (
        <Card title="Import report">
          <KeyValue
            rows={[
              ["Status", <StatusBadge key="s" status={report.data.status} />],
              ["Received", formatNumber(report.data.indicators_received)],
              ["Created", formatNumber(report.data.indicators_created)],
              ["Updated", formatNumber(report.data.indicators_updated)],
              ["Rejected", formatNumber(report.data.indicators_rejected)],
              ["Error", report.data.error],
            ]}
          />
          {(report.data.report.rejected?.length ?? 0) > 0 && (
            <CodeBlockText value={report.data.report.rejected} />
          )}
          {(report.data.report.unsupported_patterns?.length ?? 0) > 0 && (
            <>
              <p className="mt-2 text-sm">Unsupported STIX patterns (not imported):</p>
              <CodeBlockText value={report.data.report.unsupported_patterns} />
            </>
          )}
        </Card>
      )}
    </div>
  );
}

interface Category {
  code: string;
  name: string;
  techniques: {
    technique_id: string;
    name: string | null;
    mapping_confidence: string;
    rationale: string;
  }[];
}

function AttackTab() {
  const categories = useApi<Category[]>("/attack/categories");
  const [q, setQ] = useState("");
  const techniques = useApi<
    { technique_id: string; name: string; tactics: string[]; attack_version: string | null }[]
  >("/attack/techniques", { q: q || undefined, limit: 50 });
  const mapped = categories.data?.filter((c) => c.techniques.length > 0) ?? [];
  return (
    <div className="space-y-4">
      <Card title="Category → technique suggestions">
        {categories.isPending ? (
          <LoadingSkeleton label="Loading mappings" />
        ) : categories.error ? (
          <ErrorState error={categories.error} />
        ) : mapped.length === 0 ? (
          <EmptyState title="No ATT&CK mappings loaded">
            Download the MITRE ATT&CK Enterprise bundle and run <code>cti attack-import PATH</code>.
          </EmptyState>
        ) : (
          <DataTable
            rows={mapped.flatMap((c) => c.techniques.map((t) => ({ ...t, category: c.code })))}
            rowKey={(r) => `${r.category}-${r.technique_id}`}
            columns={[
              { key: "c", header: "Category", render: (r) => r.category },
              { key: "t", header: "Technique", render: (r) => `${r.technique_id} ${r.name ?? ""}` },
              { key: "conf", header: "Confidence", render: (r) => r.mapping_confidence },
              { key: "why", header: "Rationale", render: (r) => r.rationale },
            ]}
          />
        )}
      </Card>
      <Card title="Imported techniques">
        <Field label="Search">
          <input className={inputClass} value={q} onChange={(e) => setQ(e.target.value)} />
        </Field>
        <div className="mt-2">
          <DataTable
            rows={techniques.data}
            rowKey={(t) => t.technique_id}
            isPending={techniques.isPending}
            error={techniques.error}
            emptyTitle="No techniques imported"
            columns={[
              { key: "id", header: "ID", render: (t) => t.technique_id },
              { key: "name", header: "Name", render: (t) => t.name },
              { key: "tactics", header: "Tactics", render: (t) => t.tactics.join(", ") },
              { key: "ver", header: "ATT&CK version", render: (t) => t.attack_version ?? "—" },
            ]}
          />
        </div>
      </Card>
    </div>
  );
}

export function ThreatIntelPage() {
  const session = useSession();
  const isAdmin = hasRole(session.data?.user, "admin");
  const [tab, setTab] = useSearchParam("tab", "feeds");
  const tabs = [
    { key: "feeds", label: "Feeds" },
    { key: "indicators", label: "Indicators" },
    { key: "matches", label: "Matches" },
    ...(isAdmin ? [{ key: "import", label: "Import" }] : []),
    { key: "attack", label: "MITRE ATT&CK" },
  ];
  return (
    <div>
      <PageHeader title="Threat intelligence" />
      <Tabs tabs={tabs} active={tab} onChange={setTab} />
      {tab === "feeds" && <FeedsTab isAdmin={isAdmin} />}
      {tab === "indicators" && <IndicatorsTab />}
      {tab === "matches" && <MatchesTab />}
      {tab === "import" && isAdmin && <ImportTab />}
      {tab === "attack" && <AttackTab />}
    </div>
  );
}

export function IndicatorDetailPage() {
  const { indicatorId = "" } = useParams();
  const session = useSession();
  const indicator = useApi<IndicatorDetail>(`/threat-intel/indicators/${indicatorId}`);
  const matches = usePaged<MatchRow>("/threat-intel/matches", {
    indicator_id: indicatorId,
    limit: 50,
  });
  const revoke = useApiMutation<{ revoked: boolean }>(
    "PATCH",
    `/threat-intel/indicators/${indicatorId}`,
    ["/threat-intel"],
  );
  if (indicator.isPending) return <LoadingSkeleton label="Loading indicator" />;
  if (indicator.error) return <ErrorState error={indicator.error} />;
  const i = indicator.data;
  return (
    <div className="space-y-4">
      <PageHeader title={`Indicator ${i.indicator_id}`}>
        {hasRole(session.data?.user, "admin") && !i.revoked && (
          <Button variant="danger" onClick={() => revoke.mutate({ revoked: true })}>
            Revoke
          </Button>
        )}
      </PageHeader>
      <MutationError error={revoke.error} />
      <Card title="Indicator">
        <KeyValue
          rows={[
            ["Value (defanged)", <code key="v">{i.display_value}</code>],
            ["Type", `${i.indicator_type}${i.matchable ? "" : " (not matched against events)"}`],
            ["State now", <StatusBadge key="s" status={i.state} />],
            ["Confidence", i.confidence],
            ["Feed", `${i.feed_key} (reliability ${i.feed_reliability})`],
            ["TLP", i.tlp],
            ["Description", <SafeText key="d" value={i.description} />],
            ["First / last seen", `${formatTime(i.first_seen)} / ${formatTime(i.last_seen)}`],
            ["Valid", `${formatTime(i.valid_from)} – ${formatTime(i.valid_until)}`],
            [
              "ATT&CK techniques",
              i.technique_ids.length ? (
                <span key="t" className="flex gap-1">
                  {i.technique_ids.map((t) => (
                    <Badge key={t} tone="info">
                      {t}
                    </Badge>
                  ))}
                </span>
              ) : null,
            ],
            ["STIX ID", i.stix_id],
          ]}
        />
      </Card>
      <Card title="Version history">
        <DataTable
          rows={i.versions}
          rowKey={(v) => String(v.version_no)}
          columns={[
            { key: "n", header: "Version", render: (v) => v.version_no },
            { key: "at", header: "Changed", render: (v) => formatTime(v.changed_at) },
            {
              key: "snap",
              header: "Snapshot",
              render: (v) => <SafeText value={JSON.stringify(v.snapshot)} max={140} />,
            },
          ]}
        />
      </Card>
      <Card title={`Matches (${formatNumber(i.match_count)})`}>
        <Notice>{NOT_PROOF}</Notice>
        <div className="mt-2">
          <DataTable
            rows={matches.data?.pages.flatMap((p) => p.items)}
            rowKey={(m) => String(m.match_id)}
            isPending={matches.isPending}
            error={matches.error}
            emptyTitle="No matches for this indicator"
            hasMore={matches.hasNextPage}
            onLoadMore={() => void matches.fetchNextPage()}
            columns={[
              {
                key: "e",
                header: "Event",
                render: (m) => (
                  <Link className="text-accent" to={`/events/${m.event_id}`}>
                    {formatTime(m.event_time)}
                  </Link>
                ),
              },
              { key: "f", header: "Field", render: (m) => m.matched_field },
              { key: "s", header: "State at match", render: (m) => m.indicator_state_at_match },
            ]}
          />
        </div>
      </Card>
    </div>
  );
}
