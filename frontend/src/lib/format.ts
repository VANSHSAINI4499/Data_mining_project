/** Display helpers. Times are shown in UTC (FRONTEND_SPECIFICATION.md §7). */

export type TimeDisplay = "utc" | "local";

const TIME_DISPLAY_KEY = "cti.timeDisplay";
const timeListeners = new Set<() => void>();

function readTimeDisplay(): TimeDisplay {
  try {
    return globalThis.localStorage?.getItem(TIME_DISPLAY_KEY) === "local" ? "local" : "utc";
  } catch {
    return "utc"; // storage blocked: fall back to the default
  }
}

let timeDisplay: TimeDisplay = readTimeDisplay();

/** Display preference only; the API always exchanges UTC timestamps. */
export function getTimeDisplay(): TimeDisplay {
  return timeDisplay;
}

export function setTimeDisplay(value: TimeDisplay): void {
  timeDisplay = value;
  try {
    globalThis.localStorage?.setItem(TIME_DISPLAY_KEY, value);
  } catch {
    // per-viewer convenience only; ignore storage failures
  }
  timeListeners.forEach((listener) => listener());
}

export function subscribeTimeDisplay(listener: () => void): () => void {
  timeListeners.add(listener);
  return () => timeListeners.delete(listener);
}

function pad(n: number): string {
  return String(n).padStart(2, "0");
}

function localOffset(date: Date): string {
  const minutes = -date.getTimezoneOffset();
  const sign = minutes >= 0 ? "+" : "-";
  const abs = Math.abs(minutes);
  return `UTC${sign}${pad(Math.floor(abs / 60))}:${pad(abs % 60)}`;
}

export function formatTime(value: string | null | undefined): string {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  if (timeDisplay === "local") {
    const day = `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`;
    const time = `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
    return `${day} ${time} ${localOffset(date)}`;
  }
  return `${date.toISOString().slice(0, 19).replace("T", " ")} UTC`;
}

export function formatNumber(value: number | null | undefined, digits = 0): string {
  if (value === null || value === undefined || Number.isNaN(value)) return "—";
  return value.toLocaleString("en-US", {
    minimumFractionDigits: digits,
    maximumFractionDigits: digits,
  });
}

export function formatScore(value: number | null | undefined): string {
  return formatNumber(value, 3);
}

export function formatPercent(value: number | null | undefined, digits = 1): string {
  if (value === null || value === undefined) return "—";
  return `${formatNumber(value * 100, digits)}%`;
}

export function formatBytes(value: number | null | undefined): string {
  if (value === null || value === undefined) return "—";
  const units = ["B", "KB", "MB", "GB"];
  let size = value;
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit += 1;
  }
  return `${formatNumber(size, unit === 0 ? 0 : 1)} ${units[unit]}`;
}

export function shortId(value: string | null | undefined): string {
  return value ? value.slice(0, 8) : "—";
}
