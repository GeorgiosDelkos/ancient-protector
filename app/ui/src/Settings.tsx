import { invoke } from "@tauri-apps/api/core";
import { For, Match, Show, Switch, createResource, createSignal } from "solid-js";

import { Icon } from "./icons.tsx";
import type { Section, Setting, SettingsView } from "./settings.ts";

/** Settings inside the popover: a list of sections, each opening on its own with Back. Every
 * value and choice comes from Rust; a change returns the settings as they now are. */
export function Settings(props: { start: Section | null; onClose: () => void }) {
  const [view, { mutate }] = createResource(() => invoke<SettingsView>("settings_data"));
  const [section, setSection] = createSignal<Section | null>(props.start);
  const [error, setError] = createSignal<string | null>(null);
  const [saved, setSaved] = createSignal(false);
  const [looking, setLooking] = createSignal(false);

  /** Runs a command that returns the new settings, and shows them. */
  const update = (command: Promise<SettingsView | null>) => {
    setError(null);
    setSaved(false);
    command
      .then((next) => {
        if (next !== null) {
          mutate(next);
          setSaved(true);
        }
      })
      .catch((e: unknown) => setError(String(e)));
  };
  const save = (setting: Setting) => update(invoke<SettingsView>("save", { setting }));
  const lookAgain = () => {
    setLooking(true);
    setError(null);
    invoke<SettingsView>("detect_again")
      .then(mutate)
      .catch((e: unknown) => setError(String(e)))
      .finally(() => setLooking(false));
  };
  // Reading an errored resource throws, so the title checks first.
  const title = () =>
    (view.error === undefined ? view() : undefined)?.sections.find((s) => s.id === section())
      ?.title ?? "Settings";

  return (
    <section class="settings-view">
      <div class="nav">
        <button
          type="button"
          class="back"
          onClick={() => (section() === null ? props.onClose() : setSection(null))}
        >
          <Icon name="chev" />
          {section() === null ? "Done" : "Settings"}
        </button>
        <span class="navtitle">{title()}</span>
        <Show when={saved()} fallback={<span class="navside" />}>
          <span class="navside savedtag">Saved</span>
        </Show>
      </div>
      <Show when={error() ?? (view.error === undefined ? null : String(view.error))}>
        {(e) => (
          <p class="banner bad">
            {e()}{" "}
            <button type="button" class="link" onClick={() => void invoke("open_config")}>
              Open config.toml
            </button>
          </p>
        )}
      </Show>
      <Show
        when={view.error === undefined ? view() : undefined}
        fallback={
          <Show when={view.loading}>
            <p class="quiet">Looking at what this Mac has…</p>
          </Show>
        }
      >
        {(v) => (
          <Switch>
            <Match when={section() === null}>
              <div class="group list">
                <For each={v().sections}>
                  {(s) => (
                    <button type="button" class="srow nav-row" onClick={() => setSection(s.id)}>
                      <span class={`sicon ${s.id}`} aria-hidden="true">
                        {s.title.slice(0, 1)}
                      </span>
                      <span class="t">{s.title}</span>
                      <span class="sum">
                        <span class={s.attention ? "warn" : ""}>{s.summary}</span>
                        <Icon name="chev" />
                      </span>
                    </button>
                  )}
                </For>
              </div>
              <p class="note">
                Saved to config.toml as you change it.{" "}
                <button type="button" class="link" onClick={() => void invoke("open_config")}>
                  Open config.toml
                </button>{" "}
                ·{" "}
                <button type="button" class="link" disabled={looking()} onClick={lookAgain}>
                  {looking() ? "Looking…" : "Look again"}
                </button>
              </p>
            </Match>
            <Match when={section() === "agent"}>
              <Agent view={v()} save={save} />
            </Match>
            <Match when={section() === "schedule"}>
              <ScheduleSection view={v()} save={save} />
            </Match>
            <Match when={section() === "mac"}>
              <Mac
                view={v()}
                save={save}
                onAdd={() => update(invoke<SettingsView | null>("add_folder"))}
              />
            </Match>
            <Match when={section() === "github"}>
              <GitHub view={v()} save={save} />
            </Match>
            <Match when={section() === "servers"}>
              <Servers view={v()} save={save} />
            </Match>
            <Match when={section() === "nvd"}>
              <Nvd
                view={v()}
                onSave={(key) => update(invoke<SettingsView>("set_nvd_key", { key }))}
              />
            </Match>
          </Switch>
        )}
      </Show>
    </section>
  );
}

type Props = { view: SettingsView; save: (setting: Setting) => void };

function Agent(props: Props) {
  return (
    <section class="section">
      <p class="lead">runs sweeps and, after you confirm, fixes</p>
      <div class="group">
        <For each={props.view.agents}>
          {(agent) => (
            <button
              type="button"
              class="srow"
              disabled={!agent.available}
              aria-pressed={agent.chosen}
              onClick={() => props.save({ kind: "agent", agent: agent.agent })}
            >
              <span class={`radio ${agent.chosen ? "on" : ""}`} />
              <span class="what">
                <span class="t">{agent.name}</span>
                <span class="s">{agent.path ?? "not on your login shell's PATH"}</span>
              </span>
              <span class={`state ${agent.path === null ? "no" : "ok"}`}>
                {agent.path === null ? "Not found" : "Found"}
              </span>
            </button>
          )}
        </For>
      </div>
      <p class="note">Found through your login shell, the same way a sweep starts the agent.</p>
    </section>
  );
}

function ScheduleSection(props: Props) {
  const s = () => props.view.schedule;
  return (
    <section class="section">
      <div class="line">
        <span class="seg">
          <button
            type="button"
            class={s().automatic ? "" : "on"}
            onClick={() => props.save({ kind: "schedule", every_hours: null })}
          >
            Manual
          </button>
          <button
            type="button"
            class={s().automatic ? "on" : ""}
            onClick={() => props.save({ kind: "schedule", every_hours: s().hours })}
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
          value={s().hours}
          disabled={!s().automatic}
          onChange={(e) =>
            props.save({ kind: "schedule", every_hours: Number(e.currentTarget.value) })
          }
        />
        <span class="dim">hours</span>
      </div>
      <h2>History</h2>
      <p class="note">How far back the first advisory download goes; later sweeps fetch changes.</p>
      <div class="line">
        <span class="seg">
          <button
            type="button"
            class={s().all_history ? "on" : ""}
            onClick={() => props.save({ kind: "history", since: "all" })}
          >
            All
          </button>
          <button
            type="button"
            class={s().all_history ? "" : "on"}
            onClick={() => props.save({ kind: "history", since: s().since })}
          >
            Since
          </button>
        </span>
        <input
          id="since"
          class="field"
          type="date"
          value={s().since}
          disabled={s().all_history}
          onChange={(e) => props.save({ kind: "history", since: e.currentTarget.value })}
        />
      </div>
    </section>
  );
}

function Mac(props: Props & { onAdd: () => void }) {
  return (
    <section class="section">
      <p class="lead">folders searched for lockfiles</p>
      <Show when={props.view.folders.length > 0}>
        <div class="group">
          <For each={props.view.folders}>
            {(dir) => (
              <Show
                when={dir.chosen}
                fallback={
                  <button
                    type="button"
                    class="srow"
                    onClick={() => props.save({ kind: "add_folder", dir: dir.value })}
                  >
                    <span class="chk" />
                    <span class="what">
                      <span class="t">{dir.value}</span>
                    </span>
                    <span class="state sugg">Add</span>
                  </button>
                }
              >
                <div class="srow static">
                  <span class="chk on" />
                  <span class="what">
                    <span class="t">{dir.value}</span>
                  </span>
                  <button
                    type="button"
                    class="btn small"
                    onClick={() => props.save({ kind: "remove_folder", dir: dir.value })}
                  >
                    Remove
                  </button>
                </div>
              </Show>
            )}
          </For>
        </div>
      </Show>
      <div class="line">
        <button type="button" class="btn" onClick={() => props.onAdd()}>
          Add folder…
        </button>
      </div>
      <h2>Tools a Mac sweep reads</h2>
      <div class="tools">
        <For each={props.view.tools}>
          {(tool) => (
            <span class={`tool ${tool.path === null ? "no" : ""}`} title={tool.path ?? "not found"}>
              <i />
              {tool.name}
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
  return (
    <section class="section">
      <div class="status-line">
        <Show
          when={props.view.gh_login}
          fallback={
            <>
              <span class="lead">Run gh auth login in a terminal to list your repositories.</span>
              <span class="state warn right">gh not logged in</span>
            </>
          }
        >
          {(login) => (
            <>
              <span class="lead">Your repositories, with your gh login {login()}.</span>
              <span class="state ok right">gh ready</span>
            </>
          )}
        </Show>
      </div>
      <div class="group scroll">
        <For each={props.view.repos}>
          {(repo) => (
            <button
              type="button"
              class="srow"
              aria-pressed={repo.chosen}
              onClick={() =>
                props.save({ kind: repo.chosen ? "remove_repo" : "add_repo", repo: repo.repo })
              }
            >
              <span class={`chk ${repo.chosen ? "on" : ""}`} />
              <span class="what">
                <span class="t">{repo.repo}</span>
                <Show when={repo.private !== null}>
                  <span class="s">{repo.private === true ? "private" : "public"}</span>
                </Show>
              </span>
              <span class={`state ${repo.chosen ? "ok" : "no"}`}>
                {repo.chosen ? "Swept" : "Not swept"}
              </span>
            </button>
          )}
        </For>
      </div>
      <form
        class="line"
        onSubmit={(e) => {
          e.preventDefault();
          props.save({ kind: "add_repo", repo: typed() });
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
        <button type="submit" class="btn" disabled={typed().trim() === ""}>
          Add
        </button>
      </form>
    </section>
  );
}

function Servers(props: Props) {
  return (
    <section class="section">
      <p class="lead">read over SSH with a fixed, read-only script</p>
      <div class="group scroll">
        <For each={props.view.servers}>
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
        <For each={props.view.hosts}>
          {(host) => (
            <button
              type="button"
              class="srow"
              disabled={!host.addable}
              onClick={() => props.save({ kind: "add_server", ssh: host.alias })}
            >
              <span class="chk" />
              <span class="what">
                <span class="t">{host.alias}</span>
                <span class="s">
                  from ~/.ssh/config{host.host_name === null ? "" : ` · ${host.host_name}`}
                </span>
              </span>
              <span class="state sugg">Add</span>
            </button>
          )}
        </For>
      </div>
      <Show when={props.view.servers.length === 0 && props.view.hosts.length === 0}>
        <p class="quiet">No hosts in ~/.ssh/config. Add one there, or edit config.toml.</p>
      </Show>
      <p class="note">
        A host needs its key in ~/.ssh/known_hosts and a login that does not prompt. Folders to
        search for lockfiles are set in config.toml.
      </p>
    </section>
  );
}

function Nvd(props: { view: SettingsView; onSave: (key: string) => void }) {
  const [key, setKey] = createSignal("");
  return (
    <section class="section">
      <div class="status-line">
        <span class="lead">Optional, and free from nvd.nist.gov.</span>
        <span class={`state right ${props.view.nvd_key ? "ok" : "warn"}`}>
          {props.view.nvd_key ? "In Keychain" : "Not set"}
        </span>
      </div>
      <p class="lead">
        Without a key, NVD allows 5 requests per 30 seconds, so a first sweep of a Mac with many
        Homebrew formulae takes several minutes. A key raises that to 50.
      </p>
      <form
        class="line"
        onSubmit={(e) => {
          e.preventDefault();
          props.onSave(key());
          setKey("");
        }}
      >
        <input
          id="nvd-key"
          class="field grow mono"
          type="password"
          autocomplete="off"
          placeholder={props.view.nvd_key ? "Replace the stored key" : "Paste your key"}
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
