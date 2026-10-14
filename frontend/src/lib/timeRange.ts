import { useSearchParams } from "react-router";

/** Global time range stored in the URL (`range` preset or absolute `from`/`to`). */
export const PRESETS = [
  { key: "24h", label: "Last 24 hours", hours: 24 },
  { key: "7d", label: "Last 7 days", hours: 24 * 7 },
  { key: "30d", label: "Last 30 days", hours: 24 * 30 },
  { key: "90d", label: "Last 90 days", hours: 24 * 90 },
  { key: "365d", label: "Last 365 days", hours: 24 * 365 },
] as const;

export const DEFAULT_PRESET = "365d";

export interface TimeRange {
  from: string;
  to: string;
  preset: string | null;
}

function iso(date: Date): string {
  // Whole minutes keep query keys stable between renders.
  const copy = new Date(date);
  copy.setUTCSeconds(0, 0);
  return copy.toISOString().replace(".000Z", "Z");
}

export function resolveRange(search: URLSearchParams, now: Date = new Date()): TimeRange {
  const from = search.get("from");
  const to = search.get("to");
  if (from && to && !Number.isNaN(Date.parse(from)) && !Number.isNaN(Date.parse(to))) {
    return { from, to, preset: null };
  }
  const key = search.get("range") ?? DEFAULT_PRESET;
  const preset = PRESETS.find((p) => p.key === key) ?? PRESETS[4];
  const end = new Date(now);
  end.setUTCMinutes(end.getUTCMinutes() + 1);
  return {
    from: iso(new Date(end.getTime() - preset.hours * 3600 * 1000)),
    to: iso(end),
    preset: preset.key,
  };
}

export function useTimeRange() {
  const [search, setSearch] = useSearchParams();
  const range = resolveRange(search);
  const setPreset = (key: string) =>
    setSearch((prev) => {
      const next = new URLSearchParams(prev);
      next.delete("from");
      next.delete("to");
      next.set("range", key);
      return next;
    });
  const setAbsolute = (from: string, to: string) =>
    setSearch((prev) => {
      const next = new URLSearchParams(prev);
      next.delete("range");
      next.set("from", from);
      next.set("to", to);
      return next;
    });
  return { range, setPreset, setAbsolute };
}

/** Read/write a single URL search parameter (filters, tabs). */
export function useSearchParam(name: string, fallback = "") {
  const [search, setSearch] = useSearchParams();
  const value = search.get(name) ?? fallback;
  const set = (next: string) =>
    setSearch((prev) => {
      const params = new URLSearchParams(prev);
      if (next) params.set(name, next);
      else params.delete(name);
      return params;
    });
  return [value, set] as const;
}
