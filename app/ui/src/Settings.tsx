import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import { For, Match, Show, Switch, createMemo, createResource, createSignal } from "solid-js";

import {
  AGENT_NAMES,
  homeOf,
  serverName,
  tilde,
  toggled,
  type Current,
  type SettingsData,
  type Setting,
} from "./settings.ts";

type Section = "agent" | "schedule" | "mac" | "github" | "servers" | "nvd";

const SECTIONS: readonly [Section, string][] = [
  ["agent", "Agent"],
  ["schedule", "Schedule"],
  ["mac", "This Mac"],
  ["github", "GitHub"],
  ["servers", "Servers"],
  ["nvd", "NVD key"],
];

const TOOL_NAMES: Readonly<Record<string, string>> = {
  brew: "Homebrew",
  npm: "npm",
  node: "Node",
  uv: "uv",
  pipx: "pipx",
  cargo: "cargo",
  rustup: "rustup",
  python3: "Python",
  gh: "gh",
  ssh: "ssh",
};

export function Settings() {
  const [data, { refetch }] = createResource(() => invoke<SettingsData>("settings_data"));
  const [section, setSection] = createSignal<Section>("agent");
  const [error, setError] = createSignal<string | null>(null);
  const [saved, setSaved] = createSignal(false);

  const save = (setting: Setting) => {
    setError(null);
    setSaved(false);
    invoke("save", { setting })
      .then(() => {
        setSaved(true);
        return refetch();
      })
      .catch((e: unknown) => setError(String(e)));
  };

  return (
    <div class="settings">
      <nav class="sidebar" aria-label="Sections">
        <div class="drag" data-tauri-drag-region />
        <For each={SECTIONS}>
          {([id, label]) => (
            <button
              type="button"
              class={section() === id ? "on" : ""}
              aria-current={section() === id ? "page" : undefined}
              onClick={() => setSection(id)}
            >
              <span class={`sicon ${id}`} aria-hidden="true">
                {label.slice(0, 1)}
              </span>
              {label}
              <Show when={data()}>{(d) => <Badge section={id} data={d()} />}</Show>
            </button>
          )}
        </For>
      </nav>
      <main class="pane">
        <div class="drag" data-tauri-drag-region />
        <Show when={error()}>{(e) => <p class="banner bad">{e()}</p>}</Show>
        <Show when={data()} fallback={<p class="quiet">Looking at what this Mac has…</p>}>
          {(d) => (
            <Show
              when={d().config}
              fallback={
                <p class="banner bad">
                  {d().problem} Fix config.toml by hand, or delete it to start from the default.
                </p>
              }
            >
              {(config) => (
                <Switch>
                  <Match when={section() === "agent"}>
                    <Agent data={d()} config={config()} save={save} />
                  </Match>
                  <Match when={section() === "schedule"}>
                    <ScheduleSection config={config()} save={save} />
                  </Match>
                  <Match when={section() === "mac"}>
                    <Mac data={d()} config={config()} save={save} onError={setError} />
                  </Match>
                  <Match when={section() === "github"}>
                    <GitHub data={d()} config={config()} save={save} />
                  </Match>
                  <Match when={section() === "servers"}>
                    <Servers data={d()} config={config()} save={save} />
                  </Match>
                  <Match when={section() === "nvd"}>
                    <Nvd data={d()} onSaved={() => void refetch()} onError={setError} />
                  </Match>
                </Switch>
              )}
            </Show>
          )}
        </Show>
        <footer class="sfoot">
          <span class="path">{data()?.path ?? ""}</span>
          <Show when={saved()}>
            <span class="savedtag">Saved</span>
          </Show>
          <button type="button" class="btn small" onClick={() => void invoke("open_config")}>
            Open config.toml
          </button>
        </footer>
      </main>
    </div>
  );
}

function Badge(props: { section: Section; data: SettingsData }) {
  const config = () => props.data.config;
  const count = (): number | null => {
    switch (props.section) {
      case "mac":
        return config()?.project_dirs.length ?? null;
      case "github":
        return config()?.repos.length ?? null;
      case "servers":
        return config()?.servers.length ?? null;
      default:
        return null;
    }
  };
  if (props.section === "agent") {
    return <span class={`sdot ${config()?.agent ? "ok" : "warn"}`} />;
  }
  if (props.section === "nvd") {
    return <span class={`sdot ${props.data.detected.nvd_key ? "ok" : "warn"}`} />;
  }
  return <Show when={count()}>{(n) => <span class="count">{n()}</span>}</Show>;
}

type Props = { data: SettingsData; config: Current; save: (setting: Setting) => void };

function Agent(props: Props) {
  return (
    <section class="section">
      <h1>
        Agent <small>runs sweeps and, after you confirm, fixes</small>
      </h1>
      <div class="group">
        <For each={props.data.detected.agents}>
          {(agent) => {
            const chosen = () => props.config.agent === agent.name;
            return (
              <button
                type="button"
                class="srow"
                disabled={agent.path === null}
                aria-pressed={chosen()}
                onClick={() => props.save({ kind: "agent", agent: agent.name })}
              >
                <span class={`radio ${chosen() ? "on" : ""}`} />
                <span class="what">
                  <span class="t">{AGENT_NAMES[agent.name] ?? agent.name}</span>
                  <span class="s">
                    {agent.path === null ? "not on your login shell's PATH" : agent.path}
                  </span>
                </span>
                <span class={`state ${agent.path === null ? "no" : "ok"}`}>
                  {agent.path === null ? "Not found" : "Found"}
                </span>
              </button>
            );
          }}
        </For>
      </div>
      <p class="note">Found through your login shell, the same way a sweep starts the agent.</p>
    </section>
  );
}

function ScheduleSection(props: { config: Current; save: (setting: Setting) => void }) {
  const [hours, setHours] = createSignal(props.config.every_hours ?? 6);
  const [since, setSince] = createSignal(
    props.config.since === "all" ? "2025-01-01" : props.config.since,
  );
  const auto = () => props.config.every_hours !== null;
  const all = () => props.config.since === "all";
  return (
    <section class="section">
      <h1>Schedule</h1>
      <div class="line">
        <span class="seg">
          <button
            type="button"
            class={auto() ? "" : "on"}
            onClick={() => props.save({ kind: "schedule", every_hours: null })}
          >
            Manual
          </button>
          <button
            type="button"
            class={auto() ? "on" : ""}
            onClick={() => props.save({ kind: "schedule", every_hours: hours() })}
          >
            Every
          </button>
        </span>
        <input
          id="hours"
          class="field num"
          type="number"
          min="1"
          max="168"
          value={hours()}
          disabled={!auto()}
          onChange={(e) => {
            const n = Number(e.currentTarget.value);
            setHours(n);
            props.save({ kind: "schedule", every_hours: n });
          }}
        />
        <span class="dim">hours</span>
      </div>
      <h2>History</h2>
      <p class="note">How far back the first advisory download goes; later sweeps fetch changes.</p>
      <div class="line">
        <span class="seg">
          <button
            type="button"
            class={all() ? "on" : ""}
            onClick={() => props.save({ kind: "history", since: "all" })}
          >
            All
          </button>
          <button
            type="button"
            class={all() ? "" : "on"}
            onClick={() => props.save({ kind: "history", since: since() })}
          >
            Since
          </button>
        </span>
        <input
          id="since"
          class="field"
          type="date"
          value={since()}
          disabled={all()}
          onChange={(e) => {
            setSince(e.currentTarget.value);
            props.save({ kind: "history", since: e.currentTarget.value });
          }}
        />
      </div>
    </section>
  );
}

function Mac(props: Props & { onError: (e: string) => void }) {
  const home = () => homeOf(props.data.path);
  const dirs = () => props.config.project_dirs.map((d) => tilde(d, home()));
  const suggested = () =>
    props.data.detected.folders.map((f) => tilde(f, home())).filter((f) => !dirs().includes(f));
  const setDirs = (next: string[]) => props.save({ kind: "project_dirs", dirs: next });
  const pick = () => {
    open({ directory: true, multiple: false })
      .then((picked) => {
        if (typeof picked === "string") {
          setDirs(toggled(dirs(), tilde(picked, home())));
        }
      })
      .catch((e: unknown) => props.onError(String(e)));
  };
  return (
    <section class="section">
      <h1>
        This Mac <small>folders searched for lockfiles</small>
      </h1>
      <Show when={dirs().length > 0 || suggested().length > 0}>
        <div class="group">
          <For each={dirs()}>
            {(dir) => (
              <div class="srow static">
                <span class="chk on" />
                <span class="what">
                  <span class="t">{dir}</span>
                </span>
                <button
                  type="button"
                  class="btn small"
                  onClick={() => setDirs(toggled(dirs(), dir))}
                >
                  Remove
                </button>
              </div>
            )}
          </For>
          <For each={suggested()}>
            {(dir) => (
              <button type="button" class="srow" onClick={() => setDirs(toggled(dirs(), dir))}>
                <span class="chk" />
                <span class="what">
                  <span class="t">{dir}</span>
                </span>
                <span class="state sugg">Add</span>
              </button>
            )}
          </For>
        </div>
      </Show>
      <div class="line">
        <button type="button" class="btn" onClick={pick}>
          Add folder…
        </button>
      </div>
      <h2>Tools a Mac sweep reads</h2>
      <div class="tools">
        <For each={props.data.detected.tools}>
          {(tool) => (
            <span class={`tool ${tool.path === null ? "no" : ""}`} title={tool.path ?? "not found"}>
              <i />
              {TOOL_NAMES[tool.name] ?? tool.name}
            </span>
          )}
        </For>
      </div>
      <p class="note">The ones not installed are skipped.</p>
    </section>
  );
}

function GitHub(props: Props) {
  const [typed, setTyped] = createSignal("");
  const repos = () => props.config.repos;
  const known = createMemo(() => new Set(props.data.detected.repos.map((r) => r.nameWithOwner)));
  const extra = () => repos().filter((r) => !known().has(r));
  const setRepos = (next: string[]) => props.save({ kind: "repos", repos: next });
  return (
    <section class="section">
      <h1>
        GitHub
        <Show
          when={props.data.detected.gh_login}
          fallback={<span class="state warn right">gh not logged in</span>}
        >
          {(login) => <small>gh as {login()}</small>}
        </Show>
      </h1>
      <div class="group scroll">
        <For each={extra()}>
          {(repo) => (
            <button type="button" class="srow" onClick={() => setRepos(toggled(repos(), repo))}>
              <span class="chk on" />
              <span class="what">
                <span class="t">{repo}</span>
              </span>
              <span class="state ok">Swept</span>
            </button>
          )}
        </For>
        <For each={props.data.detected.repos}>
          {(repo) => {
            const on = () => repos().includes(repo.nameWithOwner);
            return (
              <button
                type="button"
                class="srow"
                onClick={() => setRepos(toggled(repos(), repo.nameWithOwner))}
              >
                <span class={`chk ${on() ? "on" : ""}`} />
                <span class="what">
                  <span class="t">{repo.nameWithOwner}</span>
                  <span class="s">{repo.isPrivate ? "private" : "public"}</span>
                </span>
                <span class={`state ${on() ? "ok" : "no"}`}>{on() ? "Swept" : "Not swept"}</span>
              </button>
            );
          }}
        </For>
      </div>
      <form
        class="line"
        onSubmit={(e) => {
          e.preventDefault();
          const repo = typed().trim();
          if (repo !== "" && !repos().includes(repo)) {
            setRepos([...repos(), repo]);
          }
          setTyped("");
        }}
      >
        <input
          id="repo"
          class="field grow"
          placeholder="owner/name"
          value={typed()}
          onInput={(e) => setTyped(e.currentTarget.value)}
        />
        <button type="submit" class="btn">
          Add
        </button>
      </form>
    </section>
  );
}

function Servers(props: Props) {
  const configured = () => new Set(props.config.servers.map((s) => s.reach));
  const hosts = () => props.data.detected.ssh_hosts.filter((h) => !configured().has(h.alias));
  return (
    <section class="section">
      <h1>
        Servers <small>read over SSH with a fixed, read-only script</small>
      </h1>
      <div class="group scroll">
        <For each={props.config.servers}>
          {(server) => (
            <div class="srow static">
              <span class="chk on" />
              <span class="what">
                <span class="t">{server.name}</span>
                <span class="s">
                  ssh {server.reach}
                  <Show when={server.dirs.length > 0}> · {server.dirs.join(", ")}</Show>
                </span>
              </span>
              <button
                type="button"
                class="btn small"
                onClick={() => props.save({ kind: "remove_server", name: server.name })}
              >
                Remove
              </button>
            </div>
          )}
        </For>
        <For each={hosts()}>
          {(host) => (
            <button
              type="button"
              class="srow"
              disabled={serverName(host.alias) === ""}
              onClick={() =>
                props.save({
                  kind: "add_server",
                  name: serverName(host.alias),
                  ssh: host.alias,
                  dirs: [],
                })
              }
            >
              <span class="chk" />
              <span class="what">
                <span class="t">{host.alias}</span>
                <span class="s">
                  from ~/.ssh/config{host.host_name ? ` · ${host.host_name}` : ""}
                </span>
              </span>
              <span class="state sugg">Add</span>
            </button>
          )}
        </For>
      </div>
      <Show when={props.config.servers.length === 0 && hosts().length === 0}>
        <p class="quiet">No hosts in ~/.ssh/config. Add one there, or edit config.toml.</p>
      </Show>
      <p class="note">
        A host needs its key in ~/.ssh/known_hosts and a login that does not prompt. Folders to
        search for lockfiles are set in config.toml.
      </p>
    </section>
  );
}

function Nvd(props: { data: SettingsData; onSaved: () => void; onError: (e: string) => void }) {
  const [key, setKey] = createSignal("");
  return (
    <section class="section">
      <h1>
        NVD API key <small>optional</small>
        <span class={`state right ${props.data.detected.nvd_key ? "ok" : "warn"}`}>
          {props.data.detected.nvd_key ? "In Keychain" : "Not set"}
        </span>
      </h1>
      <p class="lead">
        Without a key, NVD allows 5 requests per 30 seconds, so a first sweep of a Mac with many
        Homebrew formulae takes several minutes. A free key from nvd.nist.gov raises that to 50.
      </p>
      <form
        class="line"
        onSubmit={(e) => {
          e.preventDefault();
          invoke("set_nvd_key", { key: key() })
            .then(() => {
              setKey("");
              props.onSaved();
            })
            .catch((err: unknown) => props.onError(String(err)));
        }}
      >
        <input
          id="nvd-key"
          class="field grow mono"
          type="password"
          autocomplete="off"
          placeholder={props.data.detected.nvd_key ? "Replace the stored key" : "Paste your key"}
          value={key()}
          onInput={(e) => setKey(e.currentTarget.value)}
        />
        <button type="submit" class="btn primary" disabled={key().trim() === ""}>
          Save to Keychain
        </button>
      </form>
      <p class="note">
        Stored in your Keychain (service ancient-protector), never in config.toml or a report.
      </p>
    </section>
  );
}
