// The shape of what the app's `overview` command returns (app/src-tauri/src/main.rs).

export type Severity = "critical" | "high" | "medium" | "low";

export type Status =
  | { readonly state: "idle" }
  | { readonly state: "sweeping"; readonly step: string }
  | { readonly state: "failed"; readonly error: string };

export type Open = {
  readonly key: string;
  readonly severity: Severity;
  readonly title: string;
  readonly fix: string;
};

export type Target = {
  readonly target: string;
  readonly swept: string | null;
  readonly open: readonly Open[];
  readonly dismissed: number;
};

export type Overview = {
  readonly status: Status;
  readonly targets: readonly Target[];
  readonly agent: string | null;
  readonly schedule: string;
  readonly config: string;
  readonly problem: string | null;
};
