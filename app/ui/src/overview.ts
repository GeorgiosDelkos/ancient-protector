// The shapes the app's commands return (app/src-tauri/src/main.rs and runner.rs).

export type Severity = "critical" | "high" | "medium" | "low";

export type Status =
  | { readonly state: "idle" }
  | {
      readonly state: "sweeping";
      readonly step: string;
      readonly current: string | null;
      readonly done: readonly string[];
      readonly pending: readonly string[];
      readonly started: string;
    }
  | { readonly state: "fixing"; readonly title: string }
  | { readonly state: "failed"; readonly error: string };

export type Open = {
  readonly key: string;
  readonly severity: Severity;
  readonly title: string;
  readonly name: string;
  readonly version: string | null;
  readonly advisories: readonly string[];
  readonly place: string;
  readonly known_exploited: boolean;
  readonly explanation: string;
  readonly fix: string;
  readonly commands: readonly string[];
  readonly first_seen: string | null;
  readonly new: boolean;
};

export type Target = {
  readonly target: string;
  readonly swept: string | null;
  readonly components: number;
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

export type FixPreview = {
  readonly destination: string;
  readonly found: string;
  readonly summary: string;
  readonly steps: readonly string[];
  readonly commands: readonly string[];
  readonly agent: string;
};

export type FixDone = {
  readonly key: string;
  readonly outcome: string;
  readonly summary: string;
  readonly pull_request: string | null;
};
