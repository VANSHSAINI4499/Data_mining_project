import { afterEach, describe, expect, it } from "vitest";

import {
  getLiveMode,
  LIVE_INTERVAL_MS,
  liveInterval,
  setLiveMode,
  subscribeLiveMode,
} from "./liveMode";

describe("live mode", () => {
  afterEach(() => setLiveMode(false));

  it("is off by default, so lists do not poll", () => {
    expect(getLiveMode()).toBe(false);
    expect(liveInterval()).toBe(false);
  });

  it("enables polling and notifies subscribers when turned on", () => {
    let calls = 0;
    const unsubscribe = subscribeLiveMode(() => {
      calls += 1;
    });
    setLiveMode(true);
    unsubscribe();
    expect(calls).toBe(1);
    expect(getLiveMode()).toBe(true);
    expect(liveInterval()).toBe(LIVE_INTERVAL_MS);
  });
});
