import { describe, expect, it } from "vitest";

import { since } from "./time.ts";

describe("since", () => {
  const now = new Date("2026-11-06T12:00:00Z");
  it("reads briefly at each scale", () => {
    expect(since("2026-11-06T11:59:40Z", now)).toBe("just now");
    expect(since("2026-11-06T11:55:00Z", now)).toBe("5 min");
    expect(since("2026-11-06T09:00:00Z", now)).toBe("3 h");
    expect(since("2026-11-05T11:00:00Z", now)).toBe("1 day");
    expect(since("2026-11-02T12:00:00Z", now)).toBe("4 days");
  });
});
