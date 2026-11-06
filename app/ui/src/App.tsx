import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { disable, enable, isEnabled } from "@tauri-apps/plugin-autostart";
import {
  For,
  Match,
  Show,
  Switch,
  createMemo,
  createResource,
  createSignal,
  onCleanup,
  onMount,
} from "solid-js";

import type { FixDone, FixPreview, Overview, Status, Target } from "./overview.ts";
import { Glyph, Icon } from "./icons.tsx";
import {
  SEVERITIES,
  bySeverity,
  headline,
  lastSwept,
  needsYou,
  ranked,
  since,
  targetKind,
  targetLabel,
  type Listed,
} from "./view.ts";

type Tab = "needs" | "targets" | "all";

export function App() {
  const [overview, { refetch }] = createResource(() => invoke<Overview>("overview"));
  const [now, setNow] = createSignal(new Date());
  const [tab, setTab] = createSignal<Tab>("needs");
  const [selected, setSelected] = createSignal<string | null>(null);
  const [done, setDone] = createSignal<FixDone | null>(null);
  const [error, setError] = createSignal<string | null>(null);

  // Registered synchronously, so Solid runs the cleanups; the listeners resolve later.
  const unlisten: Promise<() => void>[] = [
    listen("changed", () => {
      setNow(new Date());
      void refetch();
    }),
    listen<FixDone>("fix-done", (event) => {
      setDone(event.payload);
      setSelected(null);
    }),
  ];
  onCleanup(() => {
    for (const u of unlisten) {
      void u.then((stop) => stop());
    }
  });
  const tick = setInterval(() => setNow(new Date()), 30_000);
  onCleanup(() => clearInterval(tick));

  const listed = createMemo(() => ranked(overview()?.targets ?? []));
  const chosen = createMemo(() => listed().find((o) => o.key === selected()) ?? null);

  const run = (action: () => Promise<unknown>) => {
    setError(null);
    action().catch((e: unknown) => setError(String(e)));
  };

  return (
    <main class="pop">
      <Show when={error()}>{(e) => <p class="banner bad">{e()}</p>}</Show>
      <Show when={done()}>
        {(d) => (
          <p class={`banner ${d().outcome === "fixed" ? "good" : "bad"}`}>
            <b>{d().outcome === "fixed" ? "Fixed" : `Fix ${d().outcome}`}:</b> {d().summary}
            <button type="button" class="ghost x" aria-label="Close" onClick={() => setDone(null)}>
              ×
            </button>
          </p>
        )}
      </Show>
      <Show when={overview()} fallback={<p class="quiet">Reading the last sweep…</p>}>
        {(o) => (
          <Switch>
            <Match when={chosen()}>
              {(item) => (
                <Detail
                  item={item()}
                  now={now()}
                  busy={o().status.state !== "idle" && o().status.state !== "failed"}
                  onBack={() => setSelected(null)}
                  onError={setError}
                />
              )}
            </Match>
            <Match when={o().status.state === "sweeping" || o().status.state === "fixing"}>
              <Busy status={o().status} now={now()} />
            </Match>
            <Match when={o().problem !== null && o().targets.length === 0}>
              <Problem text={o().problem ?? ""} onEdit={() => run(() => invoke("open_config"))} />
            </Match>
            <Match when={listed().length === 0 && lastSwept(o().targets) !== null}>
              <AllClear overview={o()} now={now()} />
            </Match>
            <Match when={true}>
              <Summary
                overview={o()}
                listed={listed()}
                now={now()}
                onSweep={() => run(() => invoke("sweep_now"))}
              />
              <Tabs tab={tab()} onTab={setTab} listed={listed()} targets={o().targets.length} />
              <Switch>
                <Match when={tab() === "needs"}>
                  <Rows
                    items={listed().filter(needsYou)}
                    now={now()}
                    empty="Nothing critical, high or exploited is open."
                    onOpen={setSelected}
                  />
                </Match>
                <Match when={tab() === "targets"}>
                  <Targets targets={o().targets} now={now()} />
                </Match>
                <Match when={tab() === "all"}>
                  <Rows
                    items={listed()}
                    now={now()}
                    empty="Nothing is open."
                    onOpen={setSelected}
                  />
                </Match>
              </Switch>
            </Match>
          </Switch>
        )}
      </Show>
      <Footer overview={overview()} now={now()} onError={setError} />
    </main>
  );
}

function Summary(props: {
  overview: Overview;
  listed: readonly Listed[];
  now: Date;
  onSweep: () => void;
}) {
  const counts = () => bySeverity(props.listed);
  const exploited = () => props.listed.filter((o) => o.known_exploited).length;
  const swept = () => lastSwept(props.overview.targets);
  const failed = () => (props.overview.status.state === "failed" ? props.overview.status : null);
  return (
    <section class="summary">
      <div class="headline">
        <div>
          <h1>{headline(props.listed)}</h1>
          <p class="sub">
            <Show when={exploited() > 0}>
              <span class="kev-text">{exploited()} exploited in the wild</span> ·{" "}
            </Show>
            {swept() === null ? "not swept yet" : `swept ${since(swept() ?? "", props.now)} ago`}
          </p>
        </div>
        <button type="button" class="pill" onClick={() => props.onSweep()}>
          <Icon name="sweep" />
          Sweep
        </button>
      </div>
      <Show when={failed()}>{(f) => <p class="banner bad">Last sweep: {f().error}</p>}</Show>
      <Show when={props.listed.length > 0}>
        <div
          class="bar"
          role="img"
          aria-label={SEVERITIES.map((s) => `${counts()[s]} ${s}`).join(", ")}
        >
          <For each={SEVERITIES.filter((s) => counts()[s] > 0)}>
            {(s) => <i class={s} style={{ "flex-grow": counts()[s] }} />}
          </For>
        </div>
        <div class="legend">
          <For each={SEVERITIES}>
            {(s) => (
              <span class={counts()[s] === 0 ? "none" : ""}>
                <Glyph severity={s} />
                <b>{counts()[s]}</b> {s}
              </span>
            )}
          </For>
        </div>
      </Show>
    </section>
  );
}

function Tabs(props: {
  tab: Tab;
  onTab: (tab: Tab) => void;
  listed: readonly Listed[];
  targets: number;
}) {
  const tabs = (): [Tab, string, number][] => [
    ["needs", "Needs you", props.listed.filter(needsYou).length],
    ["targets", "Targets", props.targets],
    ["all", "All open", props.listed.length],
  ];
  return (
    <div class="seg" role="tablist" aria-label="View">
      <For each={tabs()}>
        {([id, label, n]) => (
          <button
            type="button"
            role="tab"
            aria-selected={props.tab === id}
            onClick={() => props.onTab(id)}
          >
            {label} <span class="n">{n}</span>
          </button>
        )}
      </For>
    </div>
  );
}

function Rows(props: {
  items: readonly Listed[];
  now: Date;
  empty: string;
  onOpen: (key: string) => void;
}) {
  return (
    <Show when={props.items.length > 0} fallback={<p class="quiet">{props.empty}</p>}>
      <div class="group list">
        <For each={props.items}>
          {(item) => (
            <button type="button" class="row" onClick={() => props.onOpen(item.key)}>
              <Glyph severity={item.severity} />
              <span class="what">
                <span class="t">
                  {item.name}
                  <Show when={item.version}>{(v) => <span class="ver">{v()}</span>}</Show>
                </span>
                <Show when={item.advisories.length > 0}>
                  <span class="id">{item.advisories.join(" · ")}</span>
                </Show>
                <span class="where">
                  {targetLabel(item.target)}
                  <Show when={item.place}> · {item.place}</Show>
                </span>
                <span class="fix">
                  <Icon name="wrench" />
                  {item.fix}
                </span>
              </span>
              <span class="side">
                <Show when={item.known_exploited}>
                  <span class="tag kev">Exploited</span>
                </Show>
                <Show when={item.new && !item.known_exploited}>
                  <span class="tag new">New</span>
                </Show>
                <Show when={item.first_seen}>
                  {(seen) => <span class="age">{since(seen(), props.now)}</span>}
                </Show>
              </span>
            </button>
          )}
        </For>
      </div>
    </Show>
  );
}

function Targets(props: { targets: readonly Target[]; now: Date }) {
  return (
    <div class="group list">
      <For each={props.targets}>
        {(t) => {
          const counts = () => bySeverity(t.open);
          return (
            <div class="row static">
              <span class="ticon">
                <Icon name={targetKind(t.target)} />
              </span>
              <span class="what">
                <span class="t">{targetLabel(t.target)}</span>
                <span class="where">
                  {t.swept === null
                    ? "not swept yet"
                    : `${t.components} checked · swept ${since(t.swept, props.now)} ago`}
                  <Show when={t.dismissed > 0}> · {t.dismissed} dismissed</Show>
                </span>
              </span>
              <span class="mini" aria-label={`${t.open.length} open`}>
                <For each={SEVERITIES}>
                  {(s) => (
                    <For each={Array.from({ length: Math.min(counts()[s], 4) })}>
                      {() => <i class={s} />}
                    </For>
                  )}
                </For>
                <Show when={t.open.length === 0 && t.swept !== null}>
                  <Icon name="done" />
                </Show>
              </span>
            </div>
          );
        }}
      </For>
    </div>
  );
}

function Detail(props: {
  item: Listed;
  now: Date;
  busy: boolean;
  onBack: () => void;
  onError: (error: string) => void;
}) {
  const [preview, setPreview] = createSignal<FixPreview | null>(null);
  const [dismissing, setDismissing] = createSignal(false);
  const [reason, setReason] = createSignal("");
  const back = (event: KeyboardEvent) => {
    if (event.key === "Escape") {
      props.onBack();
    }
  };
  onMount(() => window.addEventListener("keydown", back));
  onCleanup(() => window.removeEventListener("keydown", back));

  const askFix = () => {
    invoke<FixPreview>("fix_preview", { key: props.item.key })
      .then(setPreview)
      .catch((e: unknown) => props.onError(String(e)));
  };
  const runFix = () => {
    invoke("fix", { key: props.item.key, title: props.item.title }).catch((e: unknown) =>
      props.onError(String(e)),
    );
  };
  const dismiss = (event: SubmitEvent) => {
    event.preventDefault();
    invoke("dismiss", { key: props.item.key, reason: reason() })
      .then(() => props.onBack())
      .catch((e: unknown) => props.onError(String(e)));
  };

  return (
    <section class="detail-view">
      <div class="nav">
        <button type="button" class="back" onClick={() => props.onBack()}>
          <Icon name="chev" />
          Back
        </button>
        <kbd>esc</kbd>
      </div>
      <div class="group detail">
        <div class="dhead">
          <Glyph severity={props.item.severity} />
          <div class="dtitle">
            <h2>
              {props.item.name}
              <Show when={props.item.version}>{(v) => <span class="ver"> {v()}</span>}</Show>
            </h2>
            <Show when={props.item.advisories.length > 0}>
              <span class="id">{props.item.advisories.join(" · ")}</span>
            </Show>
          </div>
          <Show when={props.item.known_exploited}>
            <span class="tag kev">Exploited</span>
          </Show>
        </div>
        <dl class="meta">
          <dt>Severity</dt>
          <dd>
            {props.item.severity}
            <Show when={props.item.known_exploited}>, exploited in the wild (CISA KEV)</Show>
          </dd>
          <dt>Where</dt>
          <dd>
            {targetLabel(props.item.target)}
            <Show when={props.item.place}> · {props.item.place}</Show>
          </dd>
          <Show when={props.item.first_seen}>
            {(seen) => (
              <>
                <dt>Found</dt>
                <dd>{since(seen(), props.now)} ago</dd>
              </>
            )}
          </Show>
          <dt>Key</dt>
          <dd class="mono">{props.item.key}</dd>
        </dl>
        <Show when={props.item.explanation}>
          <p class="why">{props.item.explanation}</p>
        </Show>
        <p class="fixline">
          <Icon name="wrench" />
          {props.item.fix}
        </p>
        <Show when={props.item.commands.length > 0}>
          <pre class="cmd">
            <For each={props.item.commands}>
              {(c) => (
                <span>
                  <span class="p">$ </span>
                  {c}
                  {"\n"}
                </span>
              )}
            </For>
          </pre>
        </Show>
        <Switch>
          <Match when={preview()}>
            {(p) => (
              <div class="confirm">
                <p>
                  Run this fix on <b>{p().destination}</b> with {p().agent}, with full access?
                </p>
                <div class="dacts">
                  <button type="button" class="btn primary" disabled={props.busy} onClick={runFix}>
                    Run fix
                  </button>
                  <button type="button" class="btn" onClick={() => setPreview(null)}>
                    Cancel
                  </button>
                </div>
              </div>
            )}
          </Match>
          <Match when={dismissing()}>
            <form class="confirm" onSubmit={dismiss}>
              <label for="reason">Why does this not apply?</label>
              <input
                id="reason"
                value={reason()}
                onInput={(e) => setReason(e.currentTarget.value)}
                placeholder="Not reachable: we never parse untrusted images"
                required
              />
              <div class="dacts">
                <button type="submit" class="btn primary">
                  Dismiss
                </button>
                <button type="button" class="btn" onClick={() => setDismissing(false)}>
                  Cancel
                </button>
              </div>
            </form>
          </Match>
          <Match when={true}>
            <div class="dacts">
              <button type="button" class="btn primary" disabled={props.busy} onClick={askFix}>
                Fix…
              </button>
              <button type="button" class="btn" onClick={() => setDismissing(true)}>
                Dismiss…
              </button>
            </div>
          </Match>
        </Switch>
      </div>
      <p class="hint">A fix runs only after you confirm it, with full access, and is recorded.</p>
    </section>
  );
}

function Busy(props: { status: Status; now: Date }) {
  return (
    <Switch>
      <Match when={props.status.state === "sweeping" ? props.status : null}>
        {(s) => (
          <section class="summary">
            <div class="headline">
              <div>
                <h1>Sweeping {s().current === null ? "" : targetLabel(s().current ?? "")}</h1>
                <p class="sub">
                  target {s().done.length + (s().current === null ? 0 : 1)} of{" "}
                  {s().done.length + s().pending.length + (s().current === null ? 0 : 1)} · started{" "}
                  {since(s().started, props.now)} ago
                </p>
              </div>
              <span class="spin" aria-label="Sweeping" />
            </div>
            <div class="group steps">
              <For each={s().done}>
                {(t) => (
                  <div class="step done">
                    <Icon name="done" />
                    <span>{targetLabel(t)}</span>
                    <span class="st">done</span>
                  </div>
                )}
              </For>
              <Show when={s().current}>
                <div class="step now">
                  <span class="spin" />
                  <span>{s().step}</span>
                </div>
              </Show>
              <For each={s().pending}>
                {(t) => (
                  <div class="step next">
                    <Icon name="wait" />
                    <span>{targetLabel(t)}</span>
                    <span class="st">next</span>
                  </div>
                )}
              </For>
            </div>
            <p class="hint">You can close this; a notification tells you what it finds.</p>
          </section>
        )}
      </Match>
      <Match when={props.status.state === "fixing" ? props.status : null}>
        {(f) => (
          <section class="summary">
            <div class="headline">
              <div>
                <h1>Fixing</h1>
                <p class="sub">{f().title}</p>
              </div>
              <span class="spin" aria-label="Fixing" />
            </div>
            <p class="hint">The agent is working with full access; this shows how it ends.</p>
          </section>
        )}
      </Match>
    </Switch>
  );
}

function AllClear(props: { overview: Overview; now: Date }) {
  const swept = () => lastSwept(props.overview.targets);
  const dismissed = () => props.overview.targets.reduce((n, t) => n + t.dismissed, 0);
  return (
    <section class="clear">
      <div class="seal">
        <Icon name="check" />
      </div>
      <h1>All clear</h1>
      <p>
        {props.overview.targets.length} targets swept {since(swept() ?? "", props.now)} ago. Nothing
        open
        <Show when={dismissed() > 0}>; {dismissed()} dismissed</Show>.
      </p>
      <Targets targets={props.overview.targets} now={props.now} />
    </section>
  );
}

function Problem(props: { text: string; onEdit: () => void }) {
  return (
    <section class="clear">
      <h1>Settings need a look</h1>
      <p>{props.text}</p>
      <button type="button" class="btn primary" onClick={() => props.onEdit()}>
        Edit settings
      </button>
    </section>
  );
}

function Footer(props: {
  overview: Overview | undefined;
  now: Date;
  onError: (error: string) => void;
}) {
  const [login, setLogin] = createSignal(false);
  const [menu, setMenu] = createSignal(false);
  onMount(() => {
    isEnabled()
      .then(setLogin)
      .catch(() => setLogin(false));
  });
  const toggleLogin = (event: Event & { currentTarget: HTMLInputElement }) => {
    const box = event.currentTarget;
    (login() ? disable() : enable())
      .catch((e: unknown) => props.onError(String(e)))
      .finally(() => {
        // The box shows what is set, even when changing it failed.
        isEnabled()
          .then((on) => {
            setLogin(on);
            box.checked = on;
          })
          .catch(() => undefined);
      });
  };
  return (
    <footer class="foot">
      <span class="agent">
        <span class={`live ${props.overview?.agent ? "" : "off"}`} />
        {props.overview?.agent ?? "no agent"} · {props.overview?.schedule ?? ""}
      </span>
      <span class="spacer" />
      <div class="menu-wrap">
        <button
          type="button"
          class="ghost"
          aria-label="Settings"
          aria-expanded={menu()}
          onClick={() => setMenu(!menu())}
        >
          <Icon name="gear" />
        </button>
        <Show when={menu()}>
          <div class="menu" role="menu">
            <button
              type="button"
              role="menuitem"
              onClick={() => {
                setMenu(false);
                invoke("open_config").catch((e: unknown) => props.onError(String(e)));
              }}
            >
              Edit settings…
            </button>
            <label class="menuitem">
              <input id="login" type="checkbox" checked={login()} onChange={toggleLogin} />
              Launch at login
            </label>
            <hr />
            <button type="button" role="menuitem" onClick={() => void invoke("quit")}>
              Quit Ancient Protector
            </button>
          </div>
        </Show>
      </div>
    </footer>
  );
}
