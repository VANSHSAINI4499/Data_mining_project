import { useState, type FormEvent } from "react";
import { Link } from "react-router";

import { useApi, useApiMutation, usePaged, without } from "../api/hooks";
import type { User } from "../api/types";
import { DataTable } from "../components/DataTable";
import { ErrorState } from "../components/States";
import {
  Badge,
  Button,
  Card,
  CodeBlockText,
  Field,
  inputClass,
  MutationError,
  Notice,
  PageHeader,
  SafeText,
  StatusBadge,
  Tabs,
  TimeRangePicker,
} from "../components/ui";
import { hasRole, useSession } from "../hooks/useSession";
import { formatNumber, formatTime, shortId } from "../lib/format";
import { useSearchParam, useTimeRange } from "../lib/timeRange";
import type { Source } from "./IngestionPages";
import type { Feed } from "./ThreatIntelPages";

// --- data quality ----------------------------------------------------------------------------------

interface DqSummary {
  by_source: { source_id: number; source_key: string; pass: number; warn: number; fail: number }[];
  latest_failures: {
    batch_id: string;
    check_name: string;
    status: string;
    metric_value: number | null;
    checked_at: string;
  }[];
}

export function DataQualityPage() {
  const { range } = useTimeRange();
  const summary = useApi<DqSummary>("/data-quality/summary", { from: range.from, to: range.to });
  return (
    <div className="space-y-4">
      <PageHeader title="Data quality">
        <TimeRangePicker />
      </PageHeader>
      <Notice>
        The time range applies to when checks ran (each ingestion batch is checked on completion).
      </Notice>
      {summary.error && <ErrorState error={summary.error} onRetry={() => void summary.refetch()} />}
      <Card title="Check results per source">
        <DataTable
          rows={summary.data?.by_source}
          rowKey={(r) => String(r.source_id)}
          isPending={summary.isPending}
          emptyTitle="No data-quality checks ran in this range"
          columns={[
            { key: "s", header: "Source", render: (r) => r.source_key },
            { key: "p", header: "Pass", render: (r) => formatNumber(r.pass) },
            { key: "w", header: "Warn", render: (r) => formatNumber(r.warn) },
            { key: "f", header: "Fail", render: (r) => formatNumber(r.fail) },
          ]}
        />
      </Card>
      <Card title="Latest warnings and failures">
        <DataTable
          rows={summary.data?.latest_failures}
          rowKey={(r) => `${r.batch_id}-${r.check_name}`}
          isPending={summary.isPending}
          emptyTitle="No warnings or failures in this range"
          columns={[
            {
              key: "b",
              header: "Batch",
              render: (r) => (
                <Link className="text-accent" to={`/ingestion/batches/${r.batch_id}`}>
                  {shortId(r.batch_id)}
                </Link>
              ),
            },
            { key: "c", header: "Check", render: (r) => r.check_name },
            { key: "s", header: "Status", render: (r) => <StatusBadge status={r.status} /> },
            { key: "v", header: "Value", render: (r) => formatNumber(r.metric_value, 3) },
            { key: "t", header: "Checked", render: (r) => formatTime(r.checked_at) },
          ]}
        />
      </Card>
    </div>
  );
}

// --- settings --------------------------------------------------------------------------------------

function UsersTab() {
  const users = usePaged<User>("/users", { limit: 200 });
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState("viewer");
  const create = useApiMutation<Record<string, string>>("POST", "/users", ["/users"]);
  const update = useApiMutation<{ user_id: string; role?: string; is_active?: boolean }>(
    "PATCH",
    (b) => `/users/${b.user_id}`,
    ["/users"],
    without("user_id"),
  );
  const submit = (e: FormEvent) => {
    e.preventDefault();
    create.mutate(
      { username, password, role },
      {
        onSuccess: () => {
          setUsername("");
          setPassword("");
        },
      },
    );
  };
  return (
    <div className="space-y-3">
      <form onSubmit={submit} className="flex flex-wrap items-end gap-2" aria-label="Create user">
        <Field label="Username">
          <input
            className={inputClass}
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
        </Field>
        <Field label="Password (12+ characters)">
          <input
            type="password"
            autoComplete="new-password"
            className={inputClass}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </Field>
        <Field label="Role">
          <select className={inputClass} value={role} onChange={(e) => setRole(e.target.value)}>
            <option>viewer</option>
            <option>analyst</option>
            <option>admin</option>
          </select>
        </Field>
        <Button
          type="submit"
          variant="primary"
          disabled={!username || !password || create.isPending}
        >
          Create user
        </Button>
      </form>
      <MutationError error={create.error ?? update.error} />
      <DataTable
        rows={users.data?.pages.flatMap((p) => p.items)}
        rowKey={(u) => u.user_id}
        isPending={users.isPending}
        error={users.error}
        columns={[
          { key: "u", header: "Username", render: (u) => u.username },
          {
            key: "r",
            header: "Role",
            render: (u) => (
              <select
                aria-label={`Role for ${u.username}`}
                className={inputClass}
                value={u.role}
                onChange={(e) => update.mutate({ user_id: u.user_id, role: e.target.value })}
              >
                <option>viewer</option>
                <option>analyst</option>
                <option>admin</option>
              </select>
            ),
          },
          { key: "a", header: "Active", render: (u) => (u.is_active ? "yes" : "no") },
          { key: "l", header: "Last login", render: (u) => formatTime(u.last_login_at) },
          {
            key: "x",
            header: "",
            render: (u) => (
              <Button
                onClick={() => update.mutate({ user_id: u.user_id, is_active: !u.is_active })}
              >
                {u.is_active ? "Deactivate" : "Reactivate"}
              </Button>
            ),
          },
        ]}
      />
    </div>
  );
}

function SourcesTab({ isAdmin }: { isAdmin: boolean }) {
  const sources = useApi<Source[]>("/sources");
  const update = useApiMutation<{ source_id: number; default_timezone: string | null }>(
    "PATCH",
    (b) => `/sources/${b.source_id}`,
    ["/sources"],
    without("source_id"),
  );
  const [editing, setEditing] = useState<Record<number, string>>({});
  return (
    <div className="space-y-3">
      <Notice>
        The default timezone is applied only to timestamps that carry no offset; it is recorded on
        each batch as an assumption.
      </Notice>
      <MutationError error={update.error} />
      <DataTable
        rows={sources.data}
        rowKey={(s) => String(s.source_id)}
        isPending={sources.isPending}
        error={sources.error}
        columns={[
          { key: "k", header: "Source", render: (s) => `${s.name} (${s.source_key})` },
          { key: "t", header: "Type", render: (s) => s.source_type },
          { key: "a", header: "Default adapter", render: (s) => s.default_adapter ?? "—" },
          {
            key: "tz",
            header: "Default timezone",
            render: (s) =>
              isAdmin ? (
                <span className="flex gap-1">
                  <input
                    aria-label={`Timezone for ${s.source_key}`}
                    className={`${inputClass} w-40`}
                    value={editing[s.source_id] ?? s.default_timezone ?? ""}
                    onChange={(e) => setEditing({ ...editing, [s.source_id]: e.target.value })}
                  />
                  <Button
                    onClick={() =>
                      update.mutate({
                        source_id: s.source_id,
                        default_timezone:
                          (editing[s.source_id] ?? s.default_timezone ?? "") || null,
                      })
                    }
                  >
                    Save
                  </Button>
                </span>
              ) : (
                (s.default_timezone ?? "none")
              ),
          },
          { key: "r", header: "Reliability", render: (s) => s.reliability },
          {
            key: "d",
            header: "Description",
            render: (s) => <SafeText value={s.description} max={80} />,
          },
        ]}
      />
    </div>
  );
}

interface Rule {
  rule_key: string;
  version: number;
  name: string;
  description: string;
  enabled: boolean;
  base_severity: string;
  definition: Record<string, unknown>;
}

function RulesTab({ isAdmin, isAnalyst }: { isAdmin: boolean; isAnalyst: boolean }) {
  const rules = useApi<Rule[]>("/correlation/rules");
  const toggle = useApiMutation<{ rule_key: string; enabled: boolean }>(
    "PATCH",
    (b) => `/correlation/rules/${b.rule_key}`,
    ["/correlation"],
    without("rule_key"),
  );
  const [editKey, setEditKey] = useState<string | null>(null);
  const [text, setText] = useState("");
  const [jsonError, setJsonError] = useState("");
  const save = useApiMutation<{ rule_key: string; body: unknown }>(
    "PUT",
    (b) => `/correlation/rules/${b.rule_key}`,
    ["/correlation"],
    (b) => b.body,
  );
  const { range } = useTimeRange();
  const run = useApiMutation<Record<string, string>, { job_id: string }>(
    "POST",
    "/correlation/runs",
    ["/alerts"],
  );
  return (
    <div className="space-y-3">
      {isAnalyst && (
        <p className="flex items-center gap-2 text-sm">
          <Button
            onClick={() => run.mutate({ from: range.from, to: range.to })}
            disabled={run.isPending}
          >
            Run correlation for the selected range
          </Button>
          {run.data && (
            <span>Job {shortId(run.data.job_id)} queued — see Alerts when it finishes.</span>
          )}
        </p>
      )}
      <MutationError error={toggle.error ?? save.error ?? run.error} />
      <DataTable
        rows={rules.data}
        rowKey={(r) => r.rule_key}
        isPending={rules.isPending}
        error={rules.error}
        emptyTitle="No correlation rules"
        emptyHint="Run `cti seed-reference` to load the default rules."
        columns={[
          { key: "k", header: "Rule", render: (r) => `${r.name} (${r.rule_key} v${r.version})` },
          { key: "s", header: "Base severity", render: (r) => r.base_severity },
          {
            key: "d",
            header: "Description",
            render: (r) => <SafeText value={r.description} max={100} />,
          },
          {
            key: "e",
            header: "Enabled",
            render: (r) =>
              isAdmin ? (
                <span className="flex gap-1">
                  <Button
                    onClick={() => toggle.mutate({ rule_key: r.rule_key, enabled: !r.enabled })}
                  >
                    {r.enabled ? "Disable" : "Enable"}
                  </Button>
                  <Button
                    onClick={() => {
                      setEditKey(r.rule_key);
                      setText(
                        JSON.stringify(
                          {
                            name: r.name,
                            description: r.description,
                            base_severity: r.base_severity,
                            ...r.definition,
                          },
                          null,
                          2,
                        ),
                      );
                    }}
                  >
                    Edit
                  </Button>
                </span>
              ) : r.enabled ? (
                "yes"
              ) : (
                "no"
              ),
          },
        ]}
      />
      {editKey && (
        <Card title={`New version of ${editKey}`}>
          <p className="mb-2 text-sm text-muted">
            Saving creates a new rule version; the API validates fields and filters against an
            allow-list.
          </p>
          <textarea
            aria-label="Rule definition (JSON)"
            className={`${inputClass} h-64 w-full font-mono text-xs`}
            value={text}
            onChange={(e) => setText(e.target.value)}
          />
          <div className="mt-2 flex gap-2">
            <Button
              variant="primary"
              onClick={() => {
                let body: unknown;
                try {
                  body = JSON.parse(text);
                } catch {
                  setJsonError("The rule is not valid JSON.");
                  return;
                }
                setJsonError("");
                save.mutate({ rule_key: editKey, body }, { onSuccess: () => setEditKey(null) });
              }}
            >
              Save new version
            </Button>
            <Button onClick={() => setEditKey(null)}>Cancel</Button>
          </div>
          {jsonError && (
            <p role="alert" className="text-sm text-danger">
              {jsonError}
            </p>
          )}
        </Card>
      )}
    </div>
  );
}

function FeedsAdminTab() {
  const feeds = useApi<Feed[]>("/threat-intel/feeds");
  const [key, setKey] = useState("");
  const [name, setName] = useState("");
  const [reliability, setReliability] = useState("F");
  const create = useApiMutation<Record<string, string>>("POST", "/threat-intel/feeds", [
    "/threat-intel",
  ]);
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-end gap-2">
        <Field label="Feed key">
          <input className={inputClass} value={key} onChange={(e) => setKey(e.target.value)} />
        </Field>
        <Field label="Name">
          <input className={inputClass} value={name} onChange={(e) => setName(e.target.value)} />
        </Field>
        <Field label="Reliability">
          <select
            className={inputClass}
            value={reliability}
            onChange={(e) => setReliability(e.target.value)}
          >
            {["A", "B", "C", "D", "E", "F"].map((r) => (
              <option key={r}>{r}</option>
            ))}
          </select>
        </Field>
        <Button
          variant="primary"
          disabled={!key || !name || create.isPending}
          onClick={() => create.mutate({ feed_key: key, name, feed_type: "csv_file", reliability })}
        >
          Add file feed
        </Button>
      </div>
      <p className="text-xs text-muted">
        Remote TAXII polling is not implemented yet (planned for Phase 8).
      </p>
      <MutationError error={create.error} />
      <CodeBlockText
        value={
          feeds.data?.map((f) => ({
            feed_key: f.feed_key,
            type: f.feed_type,
            enabled: f.enabled,
          })) ?? []
        }
      />
    </div>
  );
}

function AssetsTab({ isAdmin }: { isAdmin: boolean }) {
  const assets = usePaged<{
    asset_id: string;
    hostname: string | null;
    ip_address: string | null;
    criticality: string;
    owner?: string | null;
  }>("/assets", { limit: 100 });
  const [file, setFile] = useState<File | null>(null);
  const upload = useApiMutation<
    FormData,
    { created: number; updated: number; unchanged: number; rejected: unknown[] }
  >("POST", "/assets/import", ["/assets"]);
  return (
    <div className="space-y-3">
      {isAdmin && (
        <div className="flex items-end gap-2">
          <Field label="Asset inventory CSV">
            <input
              type="file"
              accept=".csv"
              onChange={(e) => setFile(e.target.files?.[0] ?? null)}
            />
          </Field>
          <Button
            disabled={!file || upload.isPending}
            onClick={() => {
              if (!file) return;
              const form = new FormData();
              form.append("file", file);
              upload.mutate(form);
            }}
          >
            Import assets
          </Button>
        </div>
      )}
      <MutationError error={upload.error} />
      {upload.data && (
        <p className="text-sm">
          Created {upload.data.created}, updated {upload.data.updated}, unchanged{" "}
          {upload.data.unchanged}, rejected {upload.data.rejected.length}.
        </p>
      )}
      <DataTable
        rows={assets.data?.pages.flatMap((p) => p.items)}
        rowKey={(a) => a.asset_id}
        isPending={assets.isPending}
        error={assets.error}
        emptyTitle="No assets imported"
        hasMore={assets.hasNextPage}
        onLoadMore={() => void assets.fetchNextPage()}
        columns={[
          { key: "id", header: "Asset", render: (a) => a.asset_id },
          { key: "h", header: "Hostname", render: (a) => a.hostname ?? "—" },
          { key: "ip", header: "IP", render: (a) => a.ip_address ?? "—" },
          { key: "c", header: "Criticality", render: (a) => a.criticality },
        ]}
      />
    </div>
  );
}

export function SettingsPage() {
  const session = useSession();
  const user = session.data?.user;
  const isAdmin = hasRole(user, "admin");
  const isAnalyst = hasRole(user, "analyst");
  const [tab, setTab] = useSearchParam("tab", isAdmin ? "users" : "sources");
  const tabs = [
    ...(isAdmin ? [{ key: "users", label: "Users" }] : []),
    { key: "sources", label: "Sources" },
    ...(isAdmin ? [{ key: "feeds", label: "Feeds" }] : []),
    { key: "rules", label: "Correlation rules" },
    { key: "assets", label: "Assets" },
  ];
  return (
    <div>
      <PageHeader title="Settings">{tab === "rules" && <TimeRangePicker />}</PageHeader>
      <Tabs tabs={tabs} active={tab} onChange={setTab} />
      {tab === "users" && isAdmin && <UsersTab />}
      {tab === "sources" && <SourcesTab isAdmin={isAdmin} />}
      {tab === "feeds" && isAdmin && <FeedsAdminTab />}
      {tab === "rules" && <RulesTab isAdmin={isAdmin} isAnalyst={isAnalyst} />}
      {tab === "assets" && <AssetsTab isAdmin={isAdmin} />}
    </div>
  );
}

// --- audit history ---------------------------------------------------------------------------------

interface AuditRecord {
  audit_id: number;
  occurred_at: string;
  actor_type: string;
  actor: string | null;
  action: string;
  target_type: string | null;
  target_id: string | null;
  outcome: string;
  request_id: string | null;
  ip_address: string | null;
  details: Record<string, unknown>;
}

export function AuditPage() {
  const { range } = useTimeRange();
  const [action, setAction] = useSearchParam("action", "");
  const [outcome, setOutcome] = useSearchParam("outcome", "");
  const [targetType, setTargetType] = useSearchParam("target_type", "");
  const records = usePaged<AuditRecord>("/audit-records", {
    from: range.from,
    to: range.to,
    action: action || undefined,
    outcome: outcome || undefined,
    target_type: targetType || undefined,
    limit: 100,
  });
  const first = records.data?.pages[0] as { known_actions?: string[] } | undefined;
  return (
    <div className="space-y-4">
      <PageHeader title="Audit history">
        <TimeRangePicker />
      </PageHeader>
      <Notice>Read-only. Audit records cannot be edited or deleted from the application.</Notice>
      <div className="flex flex-wrap gap-2">
        <Field label="Action">
          <select className={inputClass} value={action} onChange={(e) => setAction(e.target.value)}>
            <option value="">Any</option>
            {first?.known_actions?.map((a) => (
              <option key={a}>{a}</option>
            ))}
          </select>
        </Field>
        <Field label="Outcome">
          <select
            className={inputClass}
            value={outcome}
            onChange={(e) => setOutcome(e.target.value)}
          >
            <option value="">Any</option>
            <option value="success">success</option>
            <option value="denied">denied</option>
            <option value="error">error</option>
          </select>
        </Field>
        <Field label="Target type">
          <input
            className={inputClass}
            value={targetType}
            onChange={(e) => setTargetType(e.target.value)}
          />
        </Field>
      </div>
      <Card>
        <DataTable
          caption="Audit records"
          rows={records.data?.pages.flatMap((p) => p.items)}
          rowKey={(r) => String(r.audit_id)}
          isPending={records.isPending}
          error={records.error}
          onRetry={() => void records.refetch()}
          emptyTitle="No audit records match"
          hasMore={records.hasNextPage}
          onLoadMore={() => void records.fetchNextPage()}
          loadingMore={records.isFetchingNextPage}
          columns={[
            { key: "t", header: "Time (UTC)", render: (r) => formatTime(r.occurred_at) },
            { key: "a", header: "Actor", render: (r) => `${r.actor ?? "—"} (${r.actor_type})` },
            { key: "act", header: "Action", render: (r) => r.action },
            {
              key: "tg",
              header: "Target",
              render: (r) => (r.target_type ? `${r.target_type} ${r.target_id ?? ""}` : "—"),
            },
            {
              key: "o",
              header: "Outcome",
              render: (r) => (
                <Badge
                  tone={r.outcome === "success" ? "ok" : r.outcome === "denied" ? "warn" : "danger"}
                >
                  {r.outcome}
                </Badge>
              ),
            },
            {
              key: "r",
              header: "Request ID",
              render: (r) => <code className="text-xs">{r.request_id ?? "—"}</code>,
            },
            {
              key: "d",
              header: "Details",
              render: (r) => <SafeText value={JSON.stringify(r.details)} max={80} />,
            },
          ]}
        />
      </Card>
    </div>
  );
}
