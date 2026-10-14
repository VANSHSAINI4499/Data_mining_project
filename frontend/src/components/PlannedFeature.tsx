import type { NavItem } from "../lib/navigation";

/**
 * Honest "not yet available" state for pages scheduled in a later roadmap milestone.
 * It deliberately shows no numbers, charts, or sample data (FRONTEND_SPECIFICATION.md §1).
 */
export function PlannedFeature({ item }: { item: NavItem }) {
  return (
    <section aria-labelledby="planned-title" data-testid="planned-feature">
      <h1 id="planned-title" className="text-xl font-semibold">
        {item.label}
      </h1>
      <div className="mt-4 rounded border border-dashed border-line bg-surface p-6">
        <p className="font-medium">This page is not available yet.</p>
        <p className="mt-2 text-sm text-muted">{item.summary}</p>
        <p className="mt-2 text-sm text-muted">
          It is delivered in roadmap milestone {item.milestone}. Until then no data is shown here,
          because the backend endpoints it needs do not exist yet.
        </p>
      </div>
    </section>
  );
}
