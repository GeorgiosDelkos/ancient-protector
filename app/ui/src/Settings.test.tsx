import { cleanup, fireEvent, render, screen, within } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { Settings } from "./Settings.tsx";
import { settingsView } from "./fixtures.ts";
import type { Section, SettingsView } from "./settings.ts";

const invoke = vi.hoisted(() => vi.fn());
vi.mock("@tauri-apps/api/core", () => ({ invoke }));

/** Answers each command with what `answers` gives for it. */
function answer(answers: Record<string, (args?: unknown) => unknown>) {
  invoke.mockImplementation((command: string, args?: unknown) => {
    const reply = answers[command];
    return reply === undefined
      ? Promise.reject(new Error(`unexpected ${command}`))
      : Promise.resolve().then(() => reply(args));
  });
}

/** The settings row holding `name`. */
async function row(name: string): Promise<HTMLElement> {
  return (await screen.findByText(name)).closest("button") as HTMLElement;
}

/** Whether the switch in the row holding `name` is on. */
async function on(name: string): Promise<string | null> {
  return (await row(name)).getAttribute("aria-checked");
}

/** The class of NVD's rate line labelled `label`. */
async function rate(label: string): Promise<string | undefined> {
  return (await screen.findByText(label)).closest(".rate")?.className;
}

function pressed(): string | null | undefined {
  return screen.getByText("Claude Code").closest("button")?.ariaPressed;
}

function open(start: Section | null = null) {
  const onClose = vi.fn();
  render(() => <Settings start={start} onClose={onClose} />);
  return onClose;
}

beforeEach(() => {
  invoke.mockReset();
});
afterEach(cleanup);

describe("the section list", () => {
  it("shows each section with the summary Rust gave it, and closes with Done", async () => {
    answer({ settings_data: () => settingsView() });
    const onClose = open();
    expect(screen.getByText("Looking at what this Mac has…")).toBeTruthy();
    expect(await screen.findByText("Choose one")).toBeTruthy();
    expect(document.querySelector(".banner")).toBeNull();
    expect(screen.getByText("Choose one").className).toBe("warn");
    expect(screen.getByText("1 folder").className).toBe("");
    fireEvent.click(screen.getByText("Done"));
    expect(onClose).toHaveBeenCalledOnce();
  });

  it("opens with Rust's headline and the sections in Rust's groups", async () => {
    answer({ settings_data: () => settingsView() });
    open();
    const headline = await screen.findByText("2 settings need you");
    expect(headline.closest(".hero")?.className).toBe("hero needs");
    const labels = screen.getAllByRole("heading").map((h) => h.textContent);
    expect(labels).toEqual(["Sweeps", "Targets", "Advisories"]);
    cleanup();
    answer({ settings_data: () => settingsView({ headline: "Ready to sweep", ready: true }) });
    open();
    const ready = await screen.findByText("Ready to sweep");
    expect(ready.closest(".hero")?.className).toBe("hero ready");
  });

  it("marks a suggested folder, off until added", async () => {
    answer({ settings_data: () => settingsView() });
    open("mac");
    expect(await on("~/code")).toBe("true");
    expect(await on("~/src")).toBe("false");
    expect(within(await row("~/src")).getByText("suggested")).toBeTruthy();
    expect((await row("~/code")).querySelector(".s")).toBeNull();
  });

  it("highlights the NVD rate that applies", async () => {
    answer({ settings_data: () => settingsView() });
    open("nvd");
    expect(await rate("Without a key")).toBe("rate on");
    expect(await rate("With a key")).toBe("rate ");
    cleanup();
    answer({ settings_data: () => settingsView({ nvd_key: true }) });
    open("nvd");
    expect(await rate("With a key")).toBe("rate on");
  });

  it("opens a section and goes back to the list", async () => {
    answer({ settings_data: () => settingsView() });
    open();
    fireEvent.click(await screen.findByText("This Mac"));
    expect(screen.getByText("Folders searched for lockfiles")).toBeTruthy();
    fireEvent.click(screen.getByText("Settings"));
    expect(screen.getByText("Choose one")).toBeTruthy();
  });

  it("looks again only when asked, and shows what it finds", async () => {
    let looked = 0;
    answer({
      settings_data: () => settingsView(),
      detect_again: () => {
        looked += 1;
        return settingsView({ nvd_key: true });
      },
    });
    open();
    fireEvent.click(await screen.findByText("Look again"));
    expect(screen.getByText("Looking…")).toBeTruthy();
    expect(await screen.findByText("Look again")).toBeTruthy();
    expect(looked).toBe(1);
  });

  it("shows why the config cannot be read, with a way to open it", async () => {
    invoke.mockImplementation((command: string) =>
      command === "settings_data"
        ? Promise.reject("config.toml line 2: expected a value")
        : Promise.resolve(),
    );
    open();
    expect(await screen.findByText(/line 2: expected a value/)).toBeTruthy();
    fireEvent.click(screen.getByText("Open config.toml"));
    expect(invoke).toHaveBeenCalledWith("open_config");
  });
});

describe("a change", () => {
  it("sends one setting and shows the view Rust returns, without detecting again", async () => {
    const chosen: SettingsView = settingsView({
      agents: [
        {
          agent: "claude",
          name: "Claude Code",
          path: "/bin/claude",
          available: true,
          chosen: true,
        },
        { agent: "codex", name: "Codex", path: null, available: false, chosen: false },
      ],
    });
    answer({ settings_data: () => settingsView(), save: () => chosen });
    open("agent");
    fireEvent.click(await screen.findByText("Claude Code"));
    expect(pressed()).toBe("false");
    expect(await screen.findByText("Saved")).toBeTruthy();
    expect(pressed()).toBe("true");
    expect(invoke).toHaveBeenCalledWith("save", { setting: { kind: "agent", agent: "claude" } });
    expect(invoke.mock.calls.filter(([c]) => c === "settings_data")).toHaveLength(1);
    expect(screen.getByText("Codex").closest("button")?.disabled).toBe(true);
  });

  it("shows a refused change and keeps the settings as they were", async () => {
    answer({ settings_data: () => settingsView() });
    invoke.mockImplementationOnce(() => Promise.resolve(settingsView()));
    invoke.mockImplementationOnce(() =>
      Promise.reject("mac.project_dirs[1]: use an absolute path"),
    );
    open("mac");
    fireEvent.click(await screen.findByText("~/code"));
    expect(await screen.findByText(/use an absolute path/)).toBeTruthy();
    expect(screen.queryByText("Saved")).toBeNull();
    expect(screen.getByText("~/code")).toBeTruthy();
  });

  it.each([
    ["mac", "~/code", { kind: "remove_folder", dir: "~/code" }],
    ["mac", "~/src", { kind: "add_folder", dir: "~/src" }],
    ["github", "me/app", { kind: "remove_repo", repo: "me/app" }],
    ["github", "me/site", { kind: "add_repo", repo: "me/site" }],
    ["servers", "web", { kind: "add_server", ssh: "web" }],
    ["schedule", "Every", { kind: "schedule", every_hours: 6 }],
    ["schedule", "Since", { kind: "history", since: "2025-01-01" }],
  ] as const)("in %s, clicking %s saves %o", async (section, text, setting) => {
    answer({ settings_data: () => settingsView(), save: () => settingsView() });
    open(section);
    fireEvent.click(await screen.findByText(text));
    await screen.findByText("Saved");
    expect(invoke).toHaveBeenCalledWith("save", { setting });
  });

  it("does not offer a host whose alias cannot be a server name", async () => {
    answer({ settings_data: () => settingsView() });
    open("servers");
    const bad = await screen.findByText("bad host");
    expect(bad.closest("button")?.disabled).toBe(true);
  });

  it("adds a typed repository as typed; Rust trims and checks it", async () => {
    answer({ settings_data: () => settingsView(), save: () => settingsView() });
    open("github");
    const input = (await screen.findByPlaceholderText("owner/name")) as HTMLInputElement;
    const add = screen.getByText("Add") as HTMLButtonElement;
    expect(add.disabled).toBe(true);
    fireEvent.input(input, { target: { value: " other/lib " } });
    expect(add.disabled).toBe(false);
    fireEvent.submit(input.form as HTMLFormElement);
    await screen.findByText("Saved");
    expect(invoke).toHaveBeenCalledWith("save", {
      setting: { kind: "add_repo", repo: " other/lib " },
    });
    expect(input.value).toBe("");
  });

  it("adds a picked folder, and does nothing when the picker is cancelled", async () => {
    let picked: SettingsView | null = null;
    answer({ settings_data: () => settingsView(), add_folder: () => picked });
    open("mac");
    fireEvent.click(await screen.findByText("Add folder…"));
    await vi.waitFor(() => expect(invoke).toHaveBeenCalledWith("add_folder"));
    await new Promise((resolve) => setTimeout(resolve, 10));
    expect(screen.queryByText("Saved")).toBeNull();
    picked = settingsView({ folders: [{ value: "/opt/work", chosen: true }] });
    fireEvent.click(screen.getByText("Add folder…"));
    expect(await screen.findByText("/opt/work")).toBeTruthy();
  });

  it("stores an NVD key and clears the field", async () => {
    answer({
      settings_data: () => settingsView(),
      set_nvd_key: () => settingsView({ nvd_key: true }),
    });
    open("nvd");
    const input = (await screen.findByPlaceholderText("Paste your key")) as HTMLInputElement;
    const save = screen.getByText("Save to Keychain") as HTMLButtonElement;
    expect(save.disabled).toBe(true);
    fireEvent.input(input, { target: { value: "abc-123" } });
    expect(save.disabled).toBe(false);
    fireEvent.submit(input.form as HTMLFormElement);
    expect(await screen.findByText("In Keychain")).toBeTruthy();
    expect(invoke).toHaveBeenCalledWith("set_nvd_key", { key: "abc-123" });
    expect(input.value).toBe("");
  });
});

describe("each section shows what Rust found", () => {
  it("names the open section in the title, and starts without Saved", async () => {
    answer({ settings_data: () => settingsView() });
    open("github");
    expect(await screen.findByText("GitHub", { selector: ".navtitle" })).toBeTruthy();
    expect(screen.queryByText("Saved")).toBeNull();
    fireEvent.click(screen.getByText("Settings"));
    expect(screen.getByText("Settings", { selector: ".navtitle" })).toBeTruthy();
  });

  it("marks agents found or not, with where", async () => {
    answer({ settings_data: () => settingsView() });
    open("agent");
    const claude = (await screen.findByText("Claude Code")).closest("button") as HTMLElement;
    expect(within(claude).getByText("/bin/claude")).toBeTruthy();
    expect(within(claude).getByText("Found").className).toBe("state ok");
    const codex = screen.getByText("Codex").closest("button") as HTMLElement;
    expect(within(codex).getByText("not on your login shell's PATH")).toBeTruthy();
    expect(within(codex).getByText("Not found").className).toBe("state no");
  });

  it("marks tools found or not", async () => {
    answer({
      settings_data: () =>
        settingsView({
          tools: [
            { name: "Homebrew", path: "/opt/homebrew/bin/brew" },
            { name: "uv", path: null },
          ],
        }),
    });
    open("mac");
    const brew = await screen.findByText("Homebrew");
    expect(brew.className).toBe("tool ");
    expect(brew.title).toBe("/opt/homebrew/bin/brew");
    expect(screen.getByText("uv").className).toBe("tool no");
    expect(screen.getByText("uv").title).toBe("not found");
  });

  it("shows a repository as private, public, or neither when typed", async () => {
    answer({
      settings_data: () =>
        settingsView({
          repos: [
            { repo: "me/app", private: true, chosen: true },
            { repo: "me/site", private: false, chosen: false },
            { repo: "other/lib", private: null, chosen: true },
          ],
        }),
    });
    open("github");
    expect(within(await row("me/app")).getByText("private")).toBeTruthy();
    expect(await on("me/app")).toBe("true");
    expect(within(await row("me/site")).getByText("public")).toBeTruthy();
    expect(await on("me/site")).toBe("false");
    expect((await row("other/lib")).querySelector(".s")).toBeNull();
  });

  it("asks for a gh login when there is none", async () => {
    answer({ settings_data: () => settingsView({ gh_login: null, repos: [] }) });
    open("github");
    expect(await screen.findByText("gh not logged in")).toBeTruthy();
  });

  it("lists swept servers with their folders, and removes one", async () => {
    answer({
      settings_data: () =>
        settingsView({
          servers: [
            { name: "web", reach: "web", dirs: ["/srv/app", "/srv/api"] },
            { name: "box", reach: "ops@10.0.0.9:2222", dirs: [] },
          ],
          hosts: [],
        }),
      save: () => settingsView(),
    });
    open("servers");
    expect(await screen.findByText("ssh web · /srv/app, /srv/api")).toBeTruthy();
    expect(screen.getByText("ssh ops@10.0.0.9:2222")).toBeTruthy();
    expect(screen.queryByText(/No hosts/)).toBeNull();
    expect(await on("web")).toBe("true");
    fireEvent.click(screen.getByText("box"));
    await screen.findByText("Saved");
    expect(invoke).toHaveBeenCalledWith("save", {
      setting: { kind: "remove_server", name: "box" },
    });
  });

  it("shows a host's name beside its alias, and says when there are none", async () => {
    answer({ settings_data: () => settingsView() });
    open("servers");
    expect(await screen.findByText("from ~/.ssh/config · 10.0.0.5")).toBeTruthy();
    expect(screen.getByText("from ~/.ssh/config")).toBeTruthy();
    expect(screen.queryByText(/No hosts/)).toBeNull();
    cleanup();
    answer({ settings_data: () => settingsView({ servers: [], hosts: [] }) });
    open("servers");
    expect(await screen.findByText(/No hosts in ~\/.ssh\/config/)).toBeTruthy();
  });

  it("shows no folder list when there are none", async () => {
    answer({ settings_data: () => settingsView({ folders: [] }) });
    open("mac");
    await screen.findByText("Add folder…");
    expect(document.querySelector(".section .group")).toBeNull();
  });
});

describe("the schedule", () => {
  it("switches to manual and changes the hours and the date as typed", async () => {
    const automatic = settingsView({
      schedule: { automatic: true, hours: 4, all_history: false, since: "2026-01-01" },
    });
    answer({ settings_data: () => automatic, save: () => automatic });
    open("schedule");
    const hours = (await screen.findByDisplayValue("4")) as HTMLInputElement;
    expect(hours.disabled).toBe(false);
    fireEvent.change(hours, { target: { value: "12" } });
    await screen.findByText("Saved");
    expect(invoke).toHaveBeenLastCalledWith("save", {
      setting: { kind: "schedule", every_hours: 12 },
    });
    const since = screen.getByDisplayValue("2026-01-01") as HTMLInputElement;
    expect(since.disabled).toBe(false);
    fireEvent.change(since, { target: { value: "2026-02-01" } });
    await vi.waitFor(() =>
      expect(invoke).toHaveBeenLastCalledWith("save", {
        setting: { kind: "history", since: "2026-02-01" },
      }),
    );
    fireEvent.click(screen.getByText("Manual"));
    await vi.waitFor(() =>
      expect(invoke).toHaveBeenLastCalledWith("save", {
        setting: { kind: "schedule", every_hours: null },
      }),
    );
    fireEvent.click(screen.getByText("All"));
    await vi.waitFor(() =>
      expect(invoke).toHaveBeenLastCalledWith("save", {
        setting: { kind: "history", since: "all" },
      }),
    );
  });

  it("disables the fields that do not apply", async () => {
    answer({ settings_data: () => settingsView() });
    open("schedule");
    expect(((await screen.findByDisplayValue("6")) as HTMLInputElement).disabled).toBe(true);
    expect((screen.getByDisplayValue("2025-01-01") as HTMLInputElement).disabled).toBe(true);
    expect(screen.getByText("Manual").className).toBe("on");
    expect(screen.getByText("Every").className).toBe("");
  });
});

describe("errors", () => {
  it("clear on the next change, and Saved shows only after one succeeds", async () => {
    answer({ settings_data: () => settingsView() });
    invoke.mockImplementationOnce(() => Promise.resolve(settingsView()));
    invoke.mockImplementationOnce(() => Promise.reject("refused"));
    invoke.mockImplementationOnce(() => Promise.resolve(settingsView()));
    open("mac");
    fireEvent.click(await screen.findByText("~/code"));
    expect(await screen.findByText(/refused/)).toBeTruthy();
    fireEvent.click(screen.getByText("~/code"));
    expect(await screen.findByText("Saved")).toBeTruthy();
    expect(screen.queryByText(/refused/)).toBeNull();
  });

  it("show when looking again fails, and clear on the next try", async () => {
    answer({ settings_data: () => settingsView() });
    invoke.mockImplementationOnce(() => Promise.resolve(settingsView()));
    invoke.mockImplementationOnce(() => Promise.reject("gh failed"));
    invoke.mockImplementationOnce(() => Promise.resolve(settingsView()));
    open();
    fireEvent.click(await screen.findByText("Look again"));
    expect(await screen.findByText(/gh failed/)).toBeTruthy();
    fireEvent.click(await screen.findByText("Look again"));
    await vi.waitFor(() => expect(screen.queryByText(/gh failed/)).toBeNull());
  });

  it("open config.toml from the section list", async () => {
    answer({ settings_data: () => settingsView(), open_config: () => null });
    open();
    fireEvent.click(await screen.findByText("Open config.toml"));
    expect(invoke).toHaveBeenCalledWith("open_config");
  });
});

describe("inputs", () => {
  it("do not send spaces alone", async () => {
    answer({ settings_data: () => settingsView() });
    open("github");
    fireEvent.input(await screen.findByPlaceholderText("owner/name"), {
      target: { value: "   " },
    });
    expect((screen.getByText("Add") as HTMLButtonElement).disabled).toBe(true);
    cleanup();
    open("nvd");
    fireEvent.input(await screen.findByPlaceholderText("Paste your key"), {
      target: { value: "  " },
    });
    expect((screen.getByText("Save to Keychain") as HTMLButtonElement).disabled).toBe(true);
  });

  it("offer to replace an NVD key already stored", async () => {
    answer({ settings_data: () => settingsView({ nvd_key: true }) });
    open("nvd");
    expect(await screen.findByPlaceholderText("Replace the stored key")).toBeTruthy();
    expect(screen.getByText("In Keychain").className).toBe("state ok");
  });
});

describe("quick changes", () => {
  it("show the reply to the newest one, even when an older reply comes later", async () => {
    const replies: ((view: SettingsView) => void)[] = [];
    invoke.mockImplementation((command: string) =>
      command === "settings_data"
        ? Promise.resolve(settingsView())
        : new Promise<SettingsView>((resolve) => replies.push(resolve)),
    );
    open("github");
    fireEvent.click(await screen.findByText("me/site"));
    fireEvent.click(screen.getByText("me/app"));
    const newer = settingsView({
      repos: [
        { repo: "me/app", private: true, chosen: false },
        { repo: "me/site", private: false, chosen: true },
      ],
    });
    replies[1]?.(newer);
    await screen.findByText("Saved");
    replies[0]?.(settingsView());
    await new Promise((resolve) => setTimeout(resolve, 10));
    expect(await on("me/app")).toBe("false");
    expect(await on("me/site")).toBe("true");
  });
});
