import { useState } from "react";

import { useApiMutation } from "../api/hooks";
import { DataTable } from "../components/DataTable";
import { Badge, Button, Card, inputClass, MutationError, Notice, SafeText } from "../components/ui";
import { formatScore } from "../lib/format";

interface WebPayloadResult {
  index: number;
  predicted_class: string;
  is_attack_like: boolean;
  score: number;
  score_kind: string;
  empty_input: boolean;
  truncated: boolean;
}

interface ClassifyResponse {
  model: { name: string; version: number; status: string; algorithm: string };
  results: WebPayloadResult[];
  note: string;
}

/** Classifies individual HTTP parameter values with the web payload model (analyst). */
export function WebPayloadCard() {
  const [text, setText] = useState("");
  const classify = useApiMutation<{ payloads: string[] }, ClassifyResponse>(
    "POST",
    "/web-payloads/classify",
  );
  const payloads = text
    .split("\n")
    .filter((line) => line.length > 0)
    .slice(0, 100);
  const noModel = classify.error?.status === 404;
  return (
    <Card title="Web payload classifier (HTTP parameter values)">
      <Notice>
        Classifies single parameter values (for example a query-string value) as benign, SQL
        injection, XSS, path traversal, or command injection. It does not analyse full requests,
        sessions, or logs, and it never blocks anything. Scores are not probabilities.
      </Notice>
      <textarea
        aria-label="Parameter values, one per line"
        className={`${inputClass} mt-3 h-28 w-full font-mono text-xs`}
        placeholder="One value per line (max 100)"
        value={text}
        onChange={(e) => setText(e.target.value)}
      />
      <div className="mt-2">
        <Button
          variant="primary"
          disabled={payloads.length === 0 || classify.isPending}
          onClick={() => classify.mutate({ payloads })}
        >
          Classify
        </Button>
      </div>
      {noModel ? (
        <p className="mt-2 text-sm text-muted">
          No active web payload model. Train one with <code>cti train web-payload</code> and promote
          it in the model registry.
        </p>
      ) : (
        <div className="mt-2">
          <MutationError error={classify.error} />
        </div>
      )}
      {classify.data && (
        <div className="mt-3">
          <p className="mb-2 text-xs text-muted">
            Model {classify.data.model.name} v{classify.data.model.version} (
            {classify.data.model.algorithm}).
          </p>
          <DataTable
            caption="Payload classifications"
            rows={classify.data.results}
            rowKey={(r) => String(r.index)}
            columns={[
              {
                key: "v",
                header: "Value",
                render: (r) => <SafeText value={payloads[r.index]} max={80} />,
              },
              {
                key: "c",
                header: "Predicted class (model output)",
                render: (r) => (
                  <Badge tone={r.is_attack_like ? "warn" : "ok"}>{r.predicted_class}</Badge>
                ),
              },
              { key: "s", header: "Score", render: (r) => formatScore(r.score) },
            ]}
          />
        </div>
      )}
    </Card>
  );
}
