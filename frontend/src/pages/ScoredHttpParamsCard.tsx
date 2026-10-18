import { useState } from "react";
import { Link } from "react-router";

import { useApiMutation, usePaged } from "../api/hooks";
import { DataTable } from "../components/DataTable";
import { JobProgress } from "../components/JobProgress";
import { EmptyState } from "../components/States";
import {
  Badge,
  Button,
  Card,
  Field,
  inputClass,
  MutationError,
  Notice,
  SafeText,
} from "../components/ui";
import { formatScore, formatTime } from "../lib/format";

interface ScoredParam {
  result_id: number;
  event_id: string;
  event_time: string;
  param_name: string;
  param_value: string | null;
  predicted_class: string;
  is_attack_like: boolean;
  score: number;
  src_ip: string | null;
  url: string | null;
}

interface Accepted {
  id: string;
  job_id: string | null;
}

/** Stored web payload predictions for the query parameters of imported HTTP events. */
export function ScoredHttpParamsCard({
  range,
  canScore,
}: {
  range: { from: string; to: string };
  canScore: boolean;
}) {
  const [attackOnly, setAttackOnly] = useState("true");
  const results = usePaged<ScoredParam>("/web-payloads/results", {
    from: range.from,
    to: range.to,
    attack_like_only: attackOnly,
  });
  const score = useApiMutation<{ from: string; to: string }, Accepted>(
    "POST",
    "/web-payloads/scoring-runs",
    ["/web-payloads"],
  );
  const noModel = results.error?.status === 404;
  return (
    <Card title="HTTP query parameters scored by the web payload model">
      <Notice>
        Each row is a prediction about one decoded query-parameter value of a stored HTTP event (for
        example from an Nginx/Apache access log). It is not a confirmed attack, the request itself
        was not analysed, and scores are not probabilities.
      </Notice>
      <div className="mt-3 flex flex-wrap items-end gap-3">
        <Field label="Show">
          <select
            className={inputClass}
            value={attackOnly}
            onChange={(e) => setAttackOnly(e.target.value)}
          >
            <option value="true">Attack-like values only</option>
            <option value="false">All scored values</option>
          </select>
        </Field>
        {canScore && !noModel && (
          <Button
            disabled={score.isPending}
            onClick={() => score.mutate({ from: range.from, to: range.to })}
          >
            Score HTTP events in this range
          </Button>
        )}
      </div>
      <div className="mt-2">
        <MutationError error={score.error} />
        {score.data?.job_id && (
          <div className="space-y-1">
            <JobProgress jobId={score.data.job_id} />
            <Button onClick={() => void results.refetch()}>Refresh results</Button>
          </div>
        )}
      </div>
      <div className="mt-3">
        {noModel ? (
          <EmptyState title="No active web payload model">
            Train one with <code>cti train web-payload</code> and promote it in the model registry.
          </EmptyState>
        ) : (
          <DataTable
            caption="Scored HTTP parameters"
            rows={results.data?.pages.flatMap((p) => p.items)}
            rowKey={(r) => String(r.result_id)}
            isPending={results.isPending}
            error={results.error}
            emptyTitle="No scored parameters in this range"
            emptyHint="Import HTTP access logs, then score them here or with `cti score web-payload`."
            hasMore={results.hasNextPage}
            onLoadMore={() => void results.fetchNextPage()}
            columns={[
              { key: "t", header: "Time", render: (r) => formatTime(r.event_time) },
              { key: "ip", header: "Client", render: (r) => r.src_ip ?? "—" },
              {
                key: "n",
                header: "Parameter",
                render: (r) => <SafeText value={r.param_name} max={40} />,
              },
              {
                key: "v",
                header: "Value (observed)",
                render: (r) => <SafeText value={r.param_value} max={80} />,
              },
              {
                key: "c",
                header: "Predicted class (model output)",
                render: (r) => (
                  <Badge tone={r.is_attack_like ? "warn" : "ok"}>{r.predicted_class}</Badge>
                ),
              },
              { key: "s", header: "Score", render: (r) => formatScore(r.score) },
              {
                key: "e",
                header: "Event",
                render: (r) => (
                  <Link className="text-accent" to={`/events/${r.event_id}`}>
                    open
                  </Link>
                ),
              },
            ]}
          />
        )}
      </div>
    </Card>
  );
}
