import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router";

import { useApi, useApiMutation, usePaged } from "../api/hooks";
import { ConfirmButton } from "../components/ConfirmDialog";
import { DataTable } from "../components/DataTable";
import { ErrorState, LoadingSkeleton } from "../components/States";
import {
  Button,
  Card,
  Field,
  inputClass,
  KeyValue,
  MutationError,
  Notice,
  PageHeader,
  ProvenanceTag,
  RiskBadge,
  SafeText,
  SeverityBadge,
  StatusBadge,
  TimeRangePicker,
} from "../components/ui";
import { hasRole, useSession } from "../hooks/useSession";
import { formatNumber, formatTime, shortId } from "../lib/format";
import { useSearchParam, useTimeRange } from "../lib/timeRange";
import { FeedbackForm } from "./FeedbackForm";

interface AlertRow {
  alert_id: string;
  status: string;
  title: string;
  primary_entity_type: string;
  primary_entity_value: string;
  risk_score: number;
  severity: string | null;
  first_event_time: string;
  last_event_time: string;
  evidence_count: number;
  case_id: string | null;
  related_alert_id: string | null;
  dismiss_reason: string | null;
  rule?: { rule_key: string; version: number; name: string; description: string };
}

interface RiskComponent {
  value: number;
  max: number;
  inputs: Record<string, unknown> | null;
}

interface AlertDetail extends AlertRow {
  risk_breakdown: {
    components: Record<string, RiskComponent>;
    base: number;
    asset_multiplier: number;
    asset: { asset_id: string | null; criticality: string };
    score: number;
    risk_model_version: string;
    note: string;
  };
  evidence: {
    evidence_type: string;
    category: string;
    evidence_ref: string;
    event_time: string | null;
    step_id: string | null;
    contribution: Record<string, unknown>;
    event_id?: string;
  }[];
  feedback: { feedback_id: number; verdict: string; comment: string | null; created_at: string }[];
}

const HYPOTHESIS = "Alerts are hypotheses for review, not confirmed incidents.";
const ENTITY_PARAM: Record<string, string> = {
  account: "user_name",
  src_ip: "ip",
  dst_ip: "ip",
  host: "host_name",
};

export function AlertsPage() {
  const { range } = useTimeRange();
  const [status, setStatus] = useSearchParam("status", "");
  const [sort, setSort] = useSearchParam("sort", "risk_score");
  const alerts = usePaged<AlertRow>("/alerts", {
    from: range.from,
    to: range.to,
    status: status || undefined,
    sort,
    limit: 100,
  });
  return (
    <div className="space-y-4">
      <PageHeader title="Alerts">
        <TimeRangePicker />
      </PageHeader>
      <Notice tone="warn">{HYPOTHESIS}</Notice>
      <div className="flex flex-wrap gap-2">
        <Field label="Status">
          <select className={inputClass} value={status} onChange={(e) => setStatus(e.target.value)}>
            <option value="">Any</option>
            {["new", "acknowledged", "in_review", "escalated", "dismissed", "closed"].map((s) => (
              <option key={s} value={s}>
                {s.replace("_", " ")}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Sort">
          <select className={inputClass} value={sort} onChange={(e) => setSort(e.target.value)}>
            <option value="risk_score">Risk score</option>
            <option value="last_event_time">Most recent</option>
          </select>
        </Field>
      </div>
      <Card>
        <DataTable
          caption="Alerts"
          rows={alerts.data?.pages.flatMap((p) => p.items)}
          rowKey={(a) => a.alert_id}
          isPending={alerts.isPending}
          error={alerts.error}
          emptyTitle="No alerts in this range"
          emptyHint="Run correlation (`cti correlate` or POST /correlation/runs) after ingesting data."
          hasMore={alerts.hasNextPage}
          onLoadMore={() => void alerts.fetchNextPage()}
          columns={[
            {
              key: "risk",
              header: "Risk",
              render: (a) => <RiskBadge score={a.risk_score} severity={a.severity} />,
            },
            {
              key: "title",
              header: "Alert",
              render: (a) => (
                <Link className="text-accent" to={`/alerts/${a.alert_id}`}>
                  <SafeText value={a.title} max={90} />
                </Link>
              ),
            },
            {
              key: "rule",
              header: "Rule",
              render: (a) => (a.rule ? `${a.rule.rule_key} v${a.rule.version}` : "—"),
            },
            { key: "status", header: "Status", render: (a) => <StatusBadge status={a.status} /> },
            { key: "evidence", header: "Evidence", render: (a) => formatNumber(a.evidence_count) },
            {
              key: "last",
              header: "Last event",
              render: (a) => formatTime(a.last_event_time),
            },
          ]}
        />
      </Card>
    </div>
  );
}

function AlertActions({ alert }: { alert: AlertDetail }) {
  const navigate = useNavigate();
  const [reason, setReason] = useState("");
  const [caseTitle, setCaseTitle] = useState(alert.title.slice(0, 300));
  const [severity, setSeverity] = useState(alert.severity ?? "medium");
  const invalidate = ["/alerts", "/cases", "/dashboard", "/events"];
  const patch = useApiMutation<Record<string, string>>(
    "PATCH",
    `/alerts/${alert.alert_id}`,
    invalidate,
  );
  const escalate = useApiMutation<Record<string, unknown>, { case: { case_id: string } }>(
    "POST",
    `/alerts/${alert.alert_id}/escalate`,
    invalidate,
  );
  const s = alert.status;
  return (
    <Card title="Actions">
      <div className="flex flex-wrap items-center gap-2">
        {s === "new" && (
          <Button onClick={() => patch.mutate({ status: "acknowledged" })}>Acknowledge</Button>
        )}
        {s === "acknowledged" && (
          <Button onClick={() => patch.mutate({ status: "in_review" })}>Start review</Button>
        )}
        {["new", "acknowledged", "in_review"].includes(s) && (
          <ConfirmButton
            label="Dismiss"
            variant="danger"
            title="Dismiss this alert?"
            description="Dismissal needs a reason and is recorded as analyst feedback (false positive)."
            confirmDisabled={reason.trim().length < 3}
            onConfirm={() => patch.mutate({ status: "dismissed", dismiss_reason: reason.trim() })}
          >
            <Field label="Reason">
              <input
                className={inputClass}
                value={reason}
                onChange={(e) => setReason(e.target.value)}
              />
            </Field>
          </ConfirmButton>
        )}
        {["acknowledged", "in_review"].includes(s) && (
          <ConfirmButton
            label="Escalate to new case"
            variant="primary"
            title="Open a case from this alert?"
            description="The alert and its evidence are linked to a new case timeline."
            confirmDisabled={caseTitle.trim().length < 3}
            onConfirm={() =>
              escalate.mutate(
                { new_case: { title: caseTitle.trim(), severity } },
                { onSuccess: (data) => void navigate(`/cases/${data.case.case_id}`) },
              )
            }
          >
            <Field label="Case title">
              <input
                className={inputClass}
                value={caseTitle}
                onChange={(e) => setCaseTitle(e.target.value)}
              />
            </Field>
            <Field label="Severity">
              <select
                className={inputClass}
                value={severity}
                onChange={(e) => setSeverity(e.target.value)}
              >
                {["low", "medium", "high", "critical"].map((v) => (
                  <option key={v}>{v}</option>
                ))}
              </select>
            </Field>
          </ConfirmButton>
        )}
        {["escalated", "dismissed", "closed"].includes(s) && (
          <p className="text-sm text-muted">No further status actions for a {s} alert.</p>
        )}
      </div>
      <div className="mt-2">
        <MutationError error={patch.error ?? escalate.error} />
      </div>
    </Card>
  );
}

export function AlertDetailPage() {
  const { alertId = "" } = useParams();
  const session = useSession();
  const isAnalyst = hasRole(session.data?.user, "analyst");
  const alert = useApi<AlertDetail>(`/alerts/${alertId}`);
  if (alert.isPending) return <LoadingSkeleton label="Loading alert" />;
  if (alert.error) return <ErrorState error={alert.error} onRetry={() => void alert.refetch()} />;
  const a = alert.data;
  const rb = a.risk_breakdown;
  const pivot = ENTITY_PARAM[a.primary_entity_type];
  return (
    <div className="space-y-4">
      <PageHeader title="Alert">
        <ProvenanceTag kind="hypothesis" />
      </PageHeader>
      <Notice tone="warn">{HYPOTHESIS}</Notice>
      <Card title={a.title}>
        <KeyValue
          rows={[
            ["Status", <StatusBadge key="s" status={a.status} />],
            ["Risk", <RiskBadge key="r" score={a.risk_score} severity={a.severity} />],
            ["Rule", a.rule ? `${a.rule.name} (${a.rule.rule_key} v${a.rule.version})` : "—"],
            ["Rule description", a.rule?.description],
            [
              "Entity",
              pivot ? (
                <Link
                  key="e"
                  className="text-accent"
                  to={`/events?${pivot}=${encodeURIComponent(a.primary_entity_value)}`}
                >
                  {a.primary_entity_type} {a.primary_entity_value}
                </Link>
              ) : (
                `${a.primary_entity_type} ${a.primary_entity_value}`
              ),
            ],
            ["Event span", `${formatTime(a.first_event_time)} – ${formatTime(a.last_event_time)}`],
            ["Evidence items", formatNumber(a.evidence_count)],
            [
              "Case",
              a.case_id ? (
                <Link key="c" className="text-accent" to={`/cases/${a.case_id}`}>
                  {shortId(a.case_id)}
                </Link>
              ) : null,
            ],
            [
              "Earlier alert",
              a.related_alert_id ? (
                <Link key="p" className="text-accent" to={`/alerts/${a.related_alert_id}`}>
                  {shortId(a.related_alert_id)}
                </Link>
              ) : null,
            ],
            ["Dismiss reason", <SafeText key="d" value={a.dismiss_reason} />],
          ]}
        />
      </Card>
      {isAnalyst && <AlertActions alert={a} />}
      <Card title={`Risk breakdown (${rb.risk_model_version})`}>
        <p className="mb-2 text-sm text-muted">{rb.note}</p>
        <DataTable
          rows={Object.entries(rb.components)}
          rowKey={([k]) => k}
          columns={[
            { key: "c", header: "Component", render: ([k]) => k.replace("_", " ") },
            { key: "v", header: "Value", render: ([, c]) => formatNumber(c.value, 2) },
            { key: "m", header: "Max", render: ([, c]) => c.max },
            {
              key: "i",
              header: "Inputs",
              render: ([, c]) => (
                <SafeText value={c.inputs ? JSON.stringify(c.inputs) : "none"} max={120} />
              ),
            },
          ]}
        />
        <p className="mt-2 text-sm">
          Base {formatNumber(rb.base, 2)} × asset multiplier {rb.asset_multiplier} (criticality{" "}
          {rb.asset.criticality}) = <strong>{rb.score}</strong> (capped at 100).
        </p>
      </Card>
      <Card title="Evidence timeline">
        <DataTable
          rows={a.evidence}
          rowKey={(e) => `${e.evidence_type}-${e.evidence_ref}`}
          columns={[
            { key: "t", header: "Time", render: (e) => formatTime(e.event_time) },
            { key: "cat", header: "Category", render: (e) => <ProvenanceTag kind={e.category} /> },
            { key: "step", header: "Rule step", render: (e) => e.step_id ?? "—" },
            {
              key: "ref",
              header: "Reference",
              render: (e) =>
                e.evidence_type === "anomaly_result" ? (
                  <Link className="text-accent" to={`/anomalies/${e.evidence_ref}`}>
                    anomaly {e.evidence_ref}
                  </Link>
                ) : e.event_id ? (
                  <Link className="text-accent" to={`/events/${e.event_id}`}>
                    event {e.event_id}
                  </Link>
                ) : (
                  `${e.evidence_type} ${e.evidence_ref}`
                ),
            },
            {
              key: "d",
              header: "Detail",
              render: (e) => <SafeText value={JSON.stringify(e.contribution)} max={100} />,
            },
          ]}
        />
        {a.evidence_count > a.evidence.length && (
          <p className="mt-2 text-xs text-muted">
            Showing the first {a.evidence.length} of {formatNumber(a.evidence_count)} evidence
            items.
          </p>
        )}
      </Card>
      <Card title="Analyst feedback" actions={<ProvenanceTag kind="analyst" />}>
        {a.feedback.length === 0 ? (
          <p className="text-sm text-muted">No feedback yet.</p>
        ) : (
          <ul className="space-y-1 text-sm">
            {a.feedback.map((f) => (
              <li key={f.feedback_id}>
                <strong>{f.verdict.replaceAll("_", " ")}</strong> {formatTime(f.created_at)} —{" "}
                <SafeText value={f.comment} />
              </li>
            ))}
          </ul>
        )}
        {isAnalyst && (
          <div className="mt-3">
            <FeedbackForm
              targetType="alert"
              targetId={a.alert_id}
              invalidate={[`/alerts/${a.alert_id}`]}
            />
          </div>
        )}
      </Card>
    </div>
  );
}

// --- cases -----------------------------------------------------------------------------------------

interface CaseRow {
  case_id: string;
  title: string;
  status: string;
  disposition: string | null;
  severity: string;
  assigned_to: string | null;
  summary: string | null;
  opened_at: string;
  closed_at: string | null;
  confirmed_incident: boolean;
}

interface CaseDetail extends CaseRow {
  alerts: AlertRow[];
}

interface TimelineEntry {
  entry_id: number;
  entry_time: string;
  entry_type: string;
  body: string;
  ref: Record<string, unknown>;
}

const DISPOSITIONS = [
  "confirmed_incident",
  "false_positive",
  "benign_true_positive",
  "inconclusive",
];

export function CasesPage() {
  const [status, setStatus] = useSearchParam("status", "");
  const session = useSession();
  const cases = useApi<CaseRow[]>("/cases", { status: status || undefined, limit: 200 });
  const [title, setTitle] = useState("");
  const [severity, setSeverity] = useState("medium");
  const create = useApiMutation<{ title: string; severity: string }>("POST", "/cases", ["/cases"]);
  return (
    <div className="space-y-4">
      <PageHeader title="Cases" />
      <div className="flex flex-wrap items-end gap-2">
        <Field label="Status">
          <select className={inputClass} value={status} onChange={(e) => setStatus(e.target.value)}>
            <option value="">Any</option>
            <option value="open">open</option>
            <option value="investigating">investigating</option>
            <option value="closed">closed</option>
          </select>
        </Field>
        {hasRole(session.data?.user, "analyst") && (
          <>
            <Field label="New case title">
              <input
                className={inputClass}
                value={title}
                onChange={(e) => setTitle(e.target.value)}
              />
            </Field>
            <Field label="Severity">
              <select
                className={inputClass}
                value={severity}
                onChange={(e) => setSeverity(e.target.value)}
              >
                {["low", "medium", "high", "critical"].map((v) => (
                  <option key={v}>{v}</option>
                ))}
              </select>
            </Field>
            <Button
              disabled={title.trim().length < 3 || create.isPending}
              onClick={() =>
                create.mutate({ title: title.trim(), severity }, { onSuccess: () => setTitle("") })
              }
            >
              Create case
            </Button>
          </>
        )}
      </div>
      <MutationError error={create.error} />
      <Card>
        <DataTable
          rows={cases.data}
          rowKey={(c) => c.case_id}
          isPending={cases.isPending}
          error={cases.error}
          emptyTitle="No cases"
          emptyHint="Escalate an alert or create a case."
          columns={[
            {
              key: "title",
              header: "Case",
              render: (c) => (
                <Link className="text-accent" to={`/cases/${c.case_id}`}>
                  <SafeText value={c.title} max={80} />
                </Link>
              ),
            },
            {
              key: "sev",
              header: "Severity",
              render: (c) => <SeverityBadge severity={c.severity} />,
            },
            { key: "status", header: "Status", render: (c) => <StatusBadge status={c.status} /> },
            {
              key: "disp",
              header: "Disposition",
              render: (c) => c.disposition?.replaceAll("_", " ") ?? "—",
            },
            { key: "opened", header: "Opened", render: (c) => formatTime(c.opened_at) },
          ]}
        />
      </Card>
    </div>
  );
}

export function CaseDetailPage() {
  const { caseId = "" } = useParams();
  const session = useSession();
  const isAnalyst = hasRole(session.data?.user, "analyst");
  const detail = useApi<CaseDetail>(`/cases/${caseId}`);
  const timeline = useApi<TimelineEntry[]>(`/cases/${caseId}/timeline`);
  const [note, setNote] = useState("");
  const [disposition, setDisposition] = useState("confirmed_incident");
  const invalidate = ["/cases", "/alerts", "/dashboard"];
  const addNote = useApiMutation<{ body: string }>("POST", `/cases/${caseId}/notes`, invalidate);
  const patch = useApiMutation<Record<string, string>>("PATCH", `/cases/${caseId}`, invalidate);
  if (detail.isPending) return <LoadingSkeleton label="Loading case" />;
  if (detail.error)
    return <ErrorState error={detail.error} onRetry={() => void detail.refetch()} />;
  const c = detail.data;
  const open = c.status !== "closed";
  return (
    <div className="space-y-4">
      <PageHeader title={c.title}>
        {isAnalyst && c.status === "open" && (
          <Button onClick={() => patch.mutate({ status: "investigating" })}>
            Start investigating
          </Button>
        )}
        {isAnalyst && open && (
          <ConfirmButton
            label="Close case"
            variant="danger"
            title="Close this case?"
            description="Closing requires a disposition. Closed cases cannot be modified; escalated alerts are closed too."
            onConfirm={() => patch.mutate({ status: "closed", disposition })}
          >
            <Field label="Disposition">
              <select
                className={inputClass}
                value={disposition}
                onChange={(e) => setDisposition(e.target.value)}
              >
                {DISPOSITIONS.map((d) => (
                  <option key={d} value={d}>
                    {d.replaceAll("_", " ")}
                  </option>
                ))}
              </select>
            </Field>
          </ConfirmButton>
        )}
      </PageHeader>
      <MutationError error={patch.error} />
      <Card title="Case">
        <KeyValue
          rows={[
            ["Status", <StatusBadge key="s" status={c.status} />],
            ["Severity", <SeverityBadge key="v" severity={c.severity} />],
            [
              "Disposition",
              c.disposition
                ? `${c.disposition.replaceAll("_", " ")}${c.confirmed_incident ? " (analyst-confirmed incident)" : ""}`
                : "not closed",
            ],
            ["Opened / closed", `${formatTime(c.opened_at)} / ${formatTime(c.closed_at)}`],
            ["Summary", <SafeText key="m" value={c.summary} />],
          ]}
        />
      </Card>
      <Card title="Linked alerts">
        <DataTable
          rows={c.alerts}
          rowKey={(a) => a.alert_id}
          emptyTitle="No alerts linked"
          columns={[
            {
              key: "t",
              header: "Alert",
              render: (a) => (
                <Link className="text-accent" to={`/alerts/${a.alert_id}`}>
                  <SafeText value={a.title} max={90} />
                </Link>
              ),
            },
            {
              key: "r",
              header: "Risk",
              render: (a) => <RiskBadge score={a.risk_score} severity={a.severity} />,
            },
            { key: "s", header: "Status", render: (a) => <StatusBadge status={a.status} /> },
          ]}
        />
      </Card>
      <Card title="Timeline">
        {isAnalyst && open && (
          <div className="mb-3 flex items-end gap-2">
            <Field label="Add a note (plain text)">
              <textarea
                className={`${inputClass} w-[32rem]`}
                maxLength={10000}
                value={note}
                onChange={(e) => setNote(e.target.value)}
              />
            </Field>
            <Button
              disabled={!note.trim() || addNote.isPending}
              onClick={() =>
                addNote.mutate({ body: note.trim() }, { onSuccess: () => setNote("") })
              }
            >
              Add note
            </Button>
          </div>
        )}
        <MutationError error={addNote.error} />
        <DataTable
          rows={timeline.data}
          rowKey={(e) => String(e.entry_id)}
          isPending={timeline.isPending}
          error={timeline.error}
          emptyTitle="No timeline entries"
          columns={[
            { key: "t", header: "Time", render: (e) => formatTime(e.entry_time) },
            { key: "type", header: "Type", render: (e) => e.entry_type.replaceAll("_", " ") },
            { key: "b", header: "Entry", render: (e) => <SafeText value={e.body} max={200} /> },
          ]}
        />
      </Card>
    </div>
  );
}
