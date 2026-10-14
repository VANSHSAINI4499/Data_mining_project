/** Display helpers. Times are shown in UTC (FRONTEND_SPECIFICATION.md §7). */

export function formatTime(value: string | null | undefined): string {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
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
