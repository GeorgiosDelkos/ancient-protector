// What the settings commands take and return (app/src-tauri/src/settings.rs and the core's
// settings_view.rs and settings.rs). Everything here is worked out in Rust; the UI only lays
// it out.

export type Section = "agent" | "schedule" | "mac" | "github" | "servers" | "nvd";

export type SectionLine = {
  readonly id: Section;
  readonly title: string;
  readonly summary: string;
  readonly attention: boolean;
};

export type SettingsView = {
  readonly headline: string;
  readonly ready: boolean;
  readonly groups: readonly {
    readonly title: string;
    readonly sections: readonly SectionLine[];
  }[];
  readonly agents: readonly {
    readonly agent: string;
    readonly name: string;
    readonly path: string | null;
    readonly available: boolean;
    readonly chosen: boolean;
  }[];
  readonly schedule: {
    readonly automatic: boolean;
    readonly hours: number;
    readonly all_history: boolean;
    readonly since: string;
  };
  readonly folders: readonly { readonly value: string; readonly chosen: boolean }[];
  readonly tools: readonly { readonly name: string; readonly path: string | null }[];
  readonly gh_login: string | null;
  readonly repos: readonly {
    readonly repo: string;
    readonly private: boolean | null;
    readonly chosen: boolean;
  }[];
  readonly servers: readonly {
    readonly name: string;
    readonly reach: string;
    readonly dirs: readonly string[];
  }[];
  readonly hosts: readonly {
    readonly alias: string;
    readonly host_name: string | null;
    readonly addable: boolean;
  }[];
  readonly nvd_key: boolean;
};

export type Setting =
  | { readonly kind: "agent"; readonly agent: string | null }
  | { readonly kind: "schedule"; readonly every_hours: number | null }
  | { readonly kind: "history"; readonly since: string }
  | { readonly kind: "add_folder"; readonly dir: string }
  | { readonly kind: "remove_folder"; readonly dir: string }
  | { readonly kind: "add_repo"; readonly repo: string }
  | { readonly kind: "remove_repo"; readonly repo: string }
  | { readonly kind: "add_server"; readonly ssh: string }
  | { readonly kind: "remove_server"; readonly name: string };
