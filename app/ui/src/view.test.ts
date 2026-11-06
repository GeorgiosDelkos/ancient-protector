import { describe, expect, it } from "vitest";

import type { Open, Target } from "./overview.ts";
import { counts, newest, statusLine } from "./view.ts";

const open = (key: string, severity: Open["severity"]): Open => ({
  key,
  severity,
  title: `title ${key}`,
  fix: "upgrade",
});

const target = (name: string, entries: Open[], dismissed = 0): Target => ({
  target: name,
  swept: "2026-11-06T10:00:00Z",
  open: entries,
  dismissed,
});

describe("counts", () => {
  it("says when a target was never swept or has nothing open", () => {
    expect(counts({ ...target("mac", []), swept: null })).toBe("not swept yet");
    expect(counts(target("mac", []))).toBe("nothing open");
    expect(counts(target("mac", [], 2))).toBe("nothing open, 2 dismissed");
  });

  it("counts by severity, worst first, skipping severities with none", () => {
    const entries = [open("a", "low"), open("b", "critical"), open("c", "low")];
    expect(counts(target("mac", entries))).toBe("1 critical, 2 low");
  });
});

describe("newest", () => {
  it("lists the most severe first across targets, up to the limit", () => {
    const targets = [
      target("mac", [open("a", "low"), open("b", "high")]),
      target("github:o/r", [open("c", "critical"), open("d", "medium")]),
    ];
    expect(newest(targets, 3).map((o) => [o.target, o.key])).toEqual([
      ["github:o/r", "c"],
      ["mac", "b"],
      ["github:o/r", "d"],
    ]);
  });
});

describe("statusLine", () => {
  it("names each state", () => {
    expect(statusLine({ state: "idle" })).toBe("Idle");
    expect(statusLine({ state: "sweeping", step: "sweeping mac" })).toBe("Sweeping: sweeping mac");
    expect(statusLine({ state: "failed", error: "mac: agent" })).toBe(
      "Last sweep failed: mac: agent",
    );
  });
});
