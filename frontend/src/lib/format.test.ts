import { afterEach, describe, expect, it } from "vitest";

import { formatTime, getTimeDisplay, setTimeDisplay, subscribeTimeDisplay } from "./format";

describe("time display preference", () => {
  afterEach(() => setTimeDisplay("utc"));

  it("defaults to UTC and labels it", () => {
    expect(getTimeDisplay()).toBe("utc");
    expect(formatTime("2026-10-15T10:02:10Z")).toBe("2026-10-15 10:02:10 UTC");
  });

  it("shows local time with an explicit offset and notifies subscribers", () => {
    let calls = 0;
    const unsubscribe = subscribeTimeDisplay(() => {
      calls += 1;
    });
    setTimeDisplay("local");
    unsubscribe();
    expect(calls).toBe(1);
    const text = formatTime("2026-10-15T10:02:10Z");
    expect(text).toMatch(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC[+-]\d{2}:\d{2}$/);
    // Same instant: the local rendering converts back to the original timestamp.
    const [day, time, offset = ""] = text.split(" ");
    const iso = `${day}T${time}${offset.slice(3)}`;
    expect(new Date(iso).toISOString()).toBe("2026-10-15T10:02:10.000Z");
  });

  it("keeps invalid and empty values honest", () => {
    setTimeDisplay("local");
    expect(formatTime(null)).toBe("—");
    expect(formatTime("not a time")).toBe("not a time");
  });
});
