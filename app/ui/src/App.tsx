import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { disable, enable, isEnabled } from "@tauri-apps/plugin-autostart";
import { For, Show, createResource, createSignal, onCleanup, onMount } from "solid-js";

import type { Overview } from "./overview.ts";
import { counts, newest, statusLine } from "./view.ts";

/** How many findings the popover lists. Arbitrary: what fits without scrolling. */
const LISTED = 6;

export function App() {
  const [overview, { refetch }] = createResource(() => invoke<Overview>("overview"));
  const [login, setLogin] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);

  onMount(async () => {
    const unlisten = await listen("changed", () => void refetch());
    onCleanup(unlisten);
    setLogin(await isEnabled());
  });

  const act = (run: () => Promise<unknown>) => async () => {
    setError(null);
    try {
      await run();
    } catch (e) {
      setError(String(e));
    }
  };

  const toggleLogin = act(async () => {
    await (login() ? disable() : enable());
    setLogin(await isEnabled());
  });

  return (
    <main>
      <header>
        <h1>Ancient Protector</h1>
        <Show when={overview()}>{(o) => <p class="status">{statusLine(o().status)}</p>}</Show>
      </header>
      <Show when={overview()?.problem}>{(problem) => <p class="problem">{problem()}</p>}</Show>
      <Show when={overview()}>
        {(o) => (
          <>
            <ul class="targets">
              <For each={o().targets}>
                {(t) => (
                  <li>
                    <span class="target">{t.target}</span> <span>{counts(t)}</span>
                  </li>
                )}
              </For>
            </ul>
            <ul class="findings">
              <For each={newest(o().targets, LISTED)}>
                {(f) => (
                  <li class={f.severity} title={`fix: ${f.fix}\nkey: ${f.key}`}>
                    <span class="severity">{f.severity}</span> {f.title}
                    <small>{f.target}</small>
                  </li>
                )}
              </For>
            </ul>
            <p class="settings">
              Agent: {o().agent ?? "none chosen"}. Schedule: {o().schedule}.
            </p>
          </>
        )}
      </Show>
      <Show when={error()}>{(e) => <p class="problem">{e()}</p>}</Show>
      <footer>
        <button
          type="button"
          disabled={overview()?.status.state === "sweeping"}
          onClick={act(() => invoke("sweep_now"))}
        >
          Sweep now
        </button>
        <button type="button" onClick={act(() => invoke("open_config"))}>
          Edit settings
        </button>
        <label>
          <input type="checkbox" checked={login()} onChange={toggleLogin} /> Launch at login
        </label>
        <button type="button" onClick={act(() => invoke("quit"))}>
          Quit
        </button>
      </footer>
    </main>
  );
}
