/** A per-viewer "Live" toggle. When on, key lists poll on a timer so the dashboard follows
 * live ingestion (e.g. the demo); off by default, so normal use makes one request per view. */

const KEY = "cti.liveMode";
export const LIVE_INTERVAL_MS = 10_000;

const listeners = new Set<() => void>();

function read(): boolean {
  try {
    return globalThis.localStorage?.getItem(KEY) === "on";
  } catch {
    return false;
  }
}

let live = read();

export function getLiveMode(): boolean {
  return live;
}

export function setLiveMode(value: boolean): void {
  live = value;
  try {
    globalThis.localStorage?.setItem(KEY, value ? "on" : "off");
  } catch {
    // per-viewer convenience only
  }
  listeners.forEach((l) => l());
}

export function subscribeLiveMode(listener: () => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

/** `refetchInterval` value for a live-updating list: the interval when live, else no polling. */
export function liveInterval(): number | false {
  return live ? LIVE_INTERVAL_MS : false;
}
