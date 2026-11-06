import type { Open, Severity, Status, Target } from "./overview.ts";

/** How many open findings a target has, by severity, as the popover's summary line. */
export function counts(target: Target): string {
  if (target.swept === null) {
    return "not swept yet";
  }
  if (target.open.length === 0) {
    return target.dismissed === 0 ? "nothing open" : `nothing open, ${target.dismissed} dismissed`;
  }
  const order: readonly Severity[] = ["critical", "high", "medium", "low"];
  const bySeverity = new Map<Severity, number>();
  for (const open of target.open) {
    bySeverity.set(open.severity, (bySeverity.get(open.severity) ?? 0) + 1);
  }
  const parts = order.flatMap((s) => {
    const n = bySeverity.get(s);
    return n === undefined ? [] : [`${n} ${s}`];
  });
  return parts.join(", ");
}

/** The newest findings to list: the most severe first, at most `limit`. */
export function newest(targets: readonly Target[], limit: number): (Open & { target: string })[] {
  const rank: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 };
  return targets
    .flatMap((t) => t.open.map((o) => ({ ...o, target: t.target })))
    .toSorted((a, b) => rank[a.severity] - rank[b.severity])
    .slice(0, limit);
}

/** The status line under the title. */
export function statusLine(status: Status): string {
  switch (status.state) {
    case "idle":
      return "Idle";
    case "sweeping":
      return `Sweeping: ${status.step}`;
    case "failed":
      return `Last sweep failed: ${status.error}`;
  }
}
