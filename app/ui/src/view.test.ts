import { describe, expect, it } from "vitest";

import type { Open, Target } from "./overview.ts";
import {
  bySeverity,
  headline,
  lastSwept,
  needsYou,
  ranked,
  since,
  targetKind,
  targetLabel,
} from "./view.ts";

const open = (key: string, severity: Open["severity"], extra: Partial<Open> = {}): Open => ({
  key,
  severity,
  title: `title ${key}`,
  name: key,
  version: "1.0",
  advisories: [`CVE-${key}`],
  place: "macOS",
  known_exploited: false,
  explanation: "",
  fix: "upgrade",
  commands: [],
  first_seen: "2026-11-01T00:00:00Z",
  new: false,
  ...extra,
});

const target = (name: string, entries: Open[], swept: string | null = "2026-11-06T10:00:00Z") => ({
  target: name,
  swept,
  components: 10,
  open: entries,
  dismissed: 0,
});

describe("needsYou", () => {
  it("is critical or high, or exploited in the wild", () => {
    expect(needsYou(open("a", "critical"))).toBe(true);
    expect(needsYou(open("a", "high"))).toBe(true);
    expect(needsYou(open("a", "medium"))).toBe(false);
    expect(needsYou(open("a", "low", { known_exploited: true }))).toBe(true);
  });
});

describe("ranked", () => {
  it("puts exploited first, then severity, then the newest", () => {
    const targets: Target[] = [
      target("mac", [open("old", "high"), open("kev", "medium", { known_exploited: true })]),
      target("server:web", [
        open("crit", "critical"),
        open("new", "high", { first_seen: "2026-11-05T00:00:00Z" }),
      ]),
    ];
    expect(ranked(targets).map((o) => [o.target, o.key])).toEqual([
      ["mac", "kev"],
      ["server:web", "crit"],
      ["server:web", "new"],
      ["mac", "old"],
    ]);
  });
});

describe("headline", () => {
  it("counts what needs the user, then what is open, then says all clear", () => {
    expect(headline([open("a", "high")])).toBe("1 finding needs you");
    expect(headline([open("a", "high"), open("b", "critical")])).toBe("2 findings need you");
    expect(headline([open("a", "low")])).toBe("1 open, none urgent");
    expect(headline([open("a", "low"), open("b", "medium")])).toBe("2 open, none urgent");
    expect(headline([])).toBe("All clear");
  });
});

describe("bySeverity", () => {
  it("counts each severity", () => {
    const counts = bySeverity([open("a", "low"), open("b", "low"), open("c", "critical")]);
    expect(counts).toEqual({ critical: 1, high: 0, medium: 0, low: 2 });
  });
});

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

describe("targets", () => {
  it("finds the newest sweep and names each target", () => {
    expect(lastSwept([target("mac", [], null)])).toBeNull();
    const two = [target("mac", [], "2026-11-05T00:00:00Z"), target("server:web", [])];
    expect(lastSwept(two)).toBe("2026-11-06T10:00:00Z");
    expect(targetLabel("mac")).toBe("This Mac");
    expect(targetLabel("github:shop/web")).toBe("shop/web");
    expect(targetLabel("server:web")).toBe("web");
    expect(targetKind("github:o/r")).toBe("repo");
    expect(targetKind("server:web")).toBe("server");
    expect(targetKind("mac")).toBe("mac");
  });
});
