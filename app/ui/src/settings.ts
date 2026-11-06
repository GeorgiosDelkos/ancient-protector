// What the app's settings commands take and return (app/src-tauri/src/settings.rs and the
// core's `Setting`).

export type Found = { readonly name: string; readonly path: string | null };

export type RepoInfo = {
  readonly nameWithOwner: string;
  readonly isPrivate: boolean;
  readonly pushedAt: string | null;
};

export type SshHost = { readonly alias: string; readonly host_name: string | null };

export type Detected = {
  readonly agents: readonly Found[];
  readonly tools: readonly Found[];
  readonly gh_login: string | null;
  readonly repos: readonly RepoInfo[];
  readonly ssh_hosts: readonly SshHost[];
  readonly folders: readonly string[];
  readonly nvd_key: boolean;
};

export type ServerView = {
  readonly name: string;
  readonly reach: string;
  readonly dirs: readonly string[];
};

export type Current = {
  readonly agent: string | null;
  readonly every_hours: number | null;
  readonly since: string;
  readonly project_dirs: readonly string[];
  readonly repos: readonly string[];
  readonly servers: readonly ServerView[];
};

export type SettingsData = {
  readonly detected: Detected;
  readonly config: Current | null;
  readonly problem: string | null;
  readonly path: string;
};

export type Setting =
  | { readonly kind: "agent"; readonly agent: string | null }
  | { readonly kind: "schedule"; readonly every_hours: number | null }
  | { readonly kind: "history"; readonly since: string }
  | { readonly kind: "project_dirs"; readonly dirs: readonly string[] }
  | { readonly kind: "repos"; readonly repos: readonly string[] }
  | {
      readonly kind: "add_server";
      readonly name: string;
      readonly ssh: string;
      readonly dirs: readonly string[];
    }
  | { readonly kind: "remove_server"; readonly name: string };

/** The agents' names as people know them. */
export const AGENT_NAMES: Readonly<Record<string, string>> = {
  claude: "Claude Code",
  grok: "Grok",
  gemini: "Gemini CLI",
  opencode: "opencode",
  codex: "Codex",
};

/** `/Users/me/code` as `~/code`, the way people write their own folders. */
export function tilde(path: string, home: string | null): string {
  return home !== null && (path === home || path.startsWith(`${home}/`))
    ? `~${path.slice(home.length)}`
    : path;
}

/** The home folder, read from the config file's path (`<home>/Library/...`). */
export function homeOf(configPath: string): string | null {
  const at = configPath.indexOf("/Library/");
  return at > 0 ? configPath.slice(0, at) : null;
}

/** Toggles `item` in `list`, keeping the order of the rest and adding at the end. */
export function toggled(list: readonly string[], item: string): string[] {
  return list.includes(item) ? list.filter((x) => x !== item) : [...list, item];
}

/** A server name for an ssh alias: the alias, when it is a valid name. */
export function serverName(alias: string): string {
  return /^[A-Za-z0-9._-]{1,64}$/.test(alias) && alias !== "." && alias !== ".." ? alias : "";
}
