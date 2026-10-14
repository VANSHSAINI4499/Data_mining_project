import { useState, type FormEvent } from "react";

import { useApiMutation } from "../api/hooks";
import { Button, Field, inputClass, MutationError } from "../components/ui";

const VERDICTS = ["true_positive", "false_positive", "benign_unusual", "needs_more_info"] as const;

/** Append-only analyst feedback on an event, model output, match, or alert. */
export function FeedbackForm({
  targetType,
  targetId,
  invalidate,
}: {
  targetType: "event" | "classification_result" | "anomaly_result" | "indicator_match" | "alert";
  targetId: string;
  invalidate: string[];
}) {
  const [verdict, setVerdict] = useState<string>(VERDICTS[0]);
  const [comment, setComment] = useState("");
  const save = useApiMutation<Record<string, string>>("POST", "/feedback", [
    "/feedback",
    ...invalidate,
  ]);
  const submit = (e: FormEvent) => {
    e.preventDefault();
    save.mutate(
      { target_type: targetType, target_id: targetId, verdict, ...(comment ? { comment } : {}) },
      { onSuccess: () => setComment("") },
    );
  };
  return (
    <form onSubmit={submit} className="space-y-2" aria-label="Add feedback">
      <div className="flex flex-wrap items-end gap-2">
        <Field label="Verdict">
          <select
            className={inputClass}
            value={verdict}
            onChange={(e) => setVerdict(e.target.value)}
          >
            {VERDICTS.map((v) => (
              <option key={v} value={v}>
                {v.replaceAll("_", " ")}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Comment">
          <input
            className={`${inputClass} w-64`}
            value={comment}
            maxLength={10000}
            onChange={(e) => setComment(e.target.value)}
          />
        </Field>
        <Button type="submit" disabled={save.isPending}>
          Add feedback
        </Button>
      </div>
      <MutationError error={save.error} />
      {save.isSuccess && <p className="text-xs text-ok">Feedback recorded.</p>}
    </form>
  );
}
