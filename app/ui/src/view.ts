import type { Open, Severity, Target } from "./overview.ts";

/** A finding with the target it belongs to. */
export type Listed = Open & { readonly target: string };

const RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 };

export const SEVERITIES: readonly Severity[] = ["critical", "high", "medium", "low"];

/** Whether a finding needs the user now: critical or high, or exploited in the wild. */
export function needsYou(open: Open): boolean {
  return open.known_exploited || open.severity === "critical" || open.severity === "high";
}

/** Every open finding across targets, ranked by risk: exploited first, then by severity,
 * then the newest first. */
export function ranked(targets: readonly Target[]): Listed[] {
  return targets
    .flatMap((t) => t.open.map((o) => ({ ...o, target: t.target })))
    .toSorted(
      (a, b) =>
        Number(b.known_exploited) - Number(a.known_exploited) ||
        RANK[a.severity] - RANK[b.severity] ||
        (b.first_seen ?? "").localeCompare(a.first_seen ?? ""),
    );
}

/** How many open findings there are of each severity. */
export function bySeverity(listed: readonly Open[]): Record<Severity, number> {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const o of listed) {
    counts[o.severity] += 1;
  }
  return counts;
}

/** The popover's top line. */
export function headline(listed: readonly Open[]): string {
  const urgent = listed.filter(needsYou).length;
  if (urgent === 1) {
    return "1 finding needs you";
  }
  if (urgent > 1) {
    return `${urgent} findings need you`;
  }
  if (listed.length === 0) {
    return "All clear";
  }
  return listed.length === 1 ? "1 open, none urgent" : `${listed.length} open, none urgent`;
}

/** How long ago `then` was, briefly: "just now", "5 min", "3 h", "4 days". */
export function since(then: string, now: Date): string {
  const minutes = Math.floor((now.getTime() - new Date(then).getTime()) / 60_000);
  if (minutes < 1) {
    return "just now";
  }
  if (minutes < 60) {
    return `${minutes} min`;
  }
  const hours = Math.floor(minutes / 60);
  if (hours < 24) {
    return `${hours} h`;
  }
  const days = Math.floor(hours / 24);
  return days === 1 ? "1 day" : `${days} days`;
}

/** The newest sweep time across targets, or `null` when none was swept. */
export function lastSwept(targets: readonly Target[]): string | null {
  const times = targets.flatMap((t) => (t.swept === null ? [] : [t.swept]));
  return times.length === 0 ? null : (times.toSorted().at(-1) ?? null);
}

/** A target's name as shown: `github:o/r` reads `o/r`, `server:web` reads `web`. */
export function targetLabel(target: string): string {
  if (target === "mac") {
    return "This Mac";
  }
  return target.replace(/^(github|server):/, "");
}

/** What kind of target it is, for its icon. */
export function targetKind(target: string): "mac" | "repo" | "server" {
  if (target.startsWith("github:")) {
    return "repo";
  }
  return target.startsWith("server:") ? "server" : "mac";
}
