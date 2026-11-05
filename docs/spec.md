# Ancient Protector: spec and implementation plan

## Context

New CVEs land daily across every stack. We want a small macOS menu-bar app that, on demand
or on a schedule, pulls the newest advisories and has a coding agent (Claude Code, Grok,
Codex, Gemini, opencode) decide whether this Mac, the user's declared GitHub repos, and the
user's declared servers are affected, then fixes approved findings. The repo is an empty
`cargo new` skeleton (`Cargo.toml`, `src/main.rs`, `.gitignore`), so everything is new.

Done means: one click (or the schedule) runs a sweep over all declared targets, findings
appear in the tray with severity and explanation, critical/high ones raise a notification,
and the user can approve a fix the agent then performs.

## Decisions taken with the user

| Area | Decision |
|---|---|
| Outcome | Report, and fix on per-finding approval |
| Who decides "affected" | The agent. The app only narrows input |
| Sources | OSV.dev (includes GitHub reviewed advisories and malicious-package reports), NVD + CISA KEV |
| Feed flow | App fetches into a local cache; agent reads files |
| History window | User-chosen (`since` date or `all`); then deltas |
| Pre-filter | App keeps advisories whose package name is in the inventory, plus OS/kernel and all KEV entries |
| Agents | Auto-detect claude, grok, codex, gemini, opencode; user picks one default |
| Agent permissions | Full access (agent CLI's bypass mode) |
| Mac inventory | App collects: macOS + Homebrew, global toolchains, lockfiles in declared folders |
| GitHub | Explicit repo list added on demand; deps, Dependabot/code/secret alerts, Actions workflows, account/org settings; auth via `gh` login |
| Servers | Agent inspects over SSH; declared as `~/.ssh/config` alias or host/user/port/key fields |
| Fix | Agent performs it per target; plan shown first, user confirms each fix |
| Schedule | Manual plus optional interval |
| Surfacing | Tray icon state, macOS notification on new critical/high, JSON + Markdown report per sweep |
| Lifecycle | Dismiss with reason, diff vs last sweep, fix history |
| Concurrency | One agent run per target, sequential |
| UI | Tauri 2 + SolidJS/TS; popover + details/settings window; follows system light/dark |
| Storage | Files in `~/Library/Application Support/ancient-protector/` |
| CLI | Yes, thin CLI over the same core |
| Distribution | Personal build first; signed + notarized DMG later; launch at login |
| v1 | All three targets |

## Architecture

Cargo workspace (root `Cargo.toml` becomes the workspace manifest; `src/main.rs` is deleted):

```
crates/core/        ancient-protector-core   all logic, no UI
crates/cli/         ancient-protector        bin: sweep, findings, dismiss, fix
app/src-tauri/      tray app (Tauri 2), calls core
app/ui/             SolidJS + TS frontend (ts-style)
prompts/            default prompt templates, copied to the data dir on first run
```

Core modules (one concept each):

- `config`: `config.toml` load/validate (`serde`, `deny_unknown_fields`).
- `paths`: data dir layout.
- `feeds::{osv, nvd, kev, ghsa}`: sync with cursor per source; `feeds::index` name index.
- `inventory::{homebrew, toolchains, lockfiles}`: Mac collectors producing `Vec<Component>`;
  GitHub collectors join them in step 5.
- `agent`: `AgentKind` enum, detection, command construction, run with output capture.
- `sweep`: orchestrates targets sequentially, emits progress events.
- `findings`: schema, validation, store, dismissals, diff.
- `fix`: plan, confirm, execute, history.
- `report`: JSON + Markdown writers.

### Data layout

```
~/Library/Application Support/ancient-protector/
  config.toml
  prompts/{sweep,server-inventory,fix-plan,fix-exec}.md
  feeds/osv/<id>.json, feeds/nvd/<product>.json
  state/dismissals.json, fixes.jsonl
  sweeps/<utc-timestamp>/<target>/{bundle/, findings.json, agent.log}
  sweeps/<utc-timestamp>/report.{json,md}, diff.json
```

### Key types (sketch, final shapes decided at the call site)

```rust
enum Target { Mac, GitHub { repo: RepoSlug }, Server { name: String, conn: SshConn } }
enum SshConn { Alias(String), Fields { host: String, user: String, port: u16, identity: Option<PathBuf> } }
enum AgentKind { Claude, Grok, Codex, Gemini, Opencode }
struct Component { ecosystem: Ecosystem, name: String, version: String, origin: PathBuf }
enum Severity { Critical, High, Medium, Low, Unknown }
struct Finding { key: FindingKey, target: TargetId, advisory_ids: Vec<String>, component: Component,
                 severity: Severity, kev: bool, evidence: String, explanation: String,
                 fix: Option<FixPlan> }
```

`FindingKey` = hash of target + primary advisory id + component name, stable across sweeps
(drives diff and dismissals). A dismissal resurfaces if the advisory's `modified` time changes.

### Mac inventory

Decided 2026-11-05. Each source is collected on its own; a failing one is reported and the
rest still count. A tool that is not installed is skipped, not an error.

| Source | Command or file | Looked up as |
|---|---|---|
| macOS | `sw_vers -productVersion` | NVD product `apple:macos` |
| Homebrew formulae and casks, dependencies included | `brew info --json=v2 --installed` | NVD product: name without `@version`, through a small alias table checked against NVD (`node` -> `node.js`, `gh` -> `github:cli`); a name that is not a valid product is reported |
| Rust toolchains | `rustup toolchain list`, `rustup run <toolchain> rustc --version` | NVD product `rust` |
| Cargo-installed binaries | `cargo install --list` | OSV `crates.io` |
| Node.js | `node --version` | NVD product `node.js` |
| Global npm packages | `npm ls -g --json --depth=0` | OSV `npm` |
| Python | `python3 --version` | NVD product `python` |
| uv and pipx tools | `uv tool list`, `pipx list --json` | OSV `PyPI` |
| Project lockfiles under `mac.project_dirs` | `Cargo.lock`, `package-lock.json` and `npm-shrinkwrap.json` (v2/v3), `uv.lock`, `poetry.lock` | OSV by ecosystem |

The folder walk skips `node_modules`, `target`, `.git`, `vendor`, `.venv`, `dist`, `build` and
every hidden folder, follows no symlinks, and only reads lockfiles: it never runs project code.
Workspace members and local path packages (no registry source) are left out of lockfile results.

Commands run from `/` with stdin closed and a one-minute limit, so a project file in the
caller's folder (`rust-toolchain.toml`, `.nvmrc`) cannot change which tool answers. Tools that
are not installed are listed, so an inventory taken with a bare `PATH` shows what it skipped.

Known gaps, accepted for now:

- Only the `node`, `npm` and `python3` first on `PATH` are read; other versions kept by nvm,
  fnm, volta, asdf or pyenv, and their global packages, are not.
- `pnpm-lock.yaml`, `yarn.lock`, `bun.lock` and `Pipfile.lock` are not read.
- A Homebrew name that is a valid CPE name but the wrong product gets no CVEs and no warning.
  Step 4 checks each product with no CVEs against NVD's CPE dictionary once and reports
  the ones NVD does not know.
- An app started by launchd gets `/usr/bin:/bin:/usr/sbin:/sbin`; step 9 runs the inventory
  with the login shell's `PATH` (`$SHELL -lc`), as the agent adapters do.

### Sweep flow (per target, sequential)

1. Feeds: delta-sync all sources (skip a source that fails, record the error in the report).
2. Inventory:
   - Mac and GitHub: app collects.
   - Server: agent run 1 (`server-inventory` prompt) SSHes in and writes `inventory.json`
     against a schema. The app needs that inventory to pre-filter advisories.
3. Bundle: app writes `bundle/` = `inventory.json`, filtered `advisories.jsonl`,
   `findings.schema.json`, rendered prompt.
4. Agent run: headless CLI in `bundle/` as cwd; agent writes `findings.json`.
5. Validate with serde (strict). On failure, one retry with the error appended; then mark the
   target failed.
6. Merge, apply dismissals, diff against previous sweep, write report, update tray, notify on
   new critical/high.

### Fix flow

Fix click -> agent run with `fix-plan` prompt -> plan (steps + exact commands) shown in the
details window -> user confirms -> agent run with `fix-exec` prompt and the confirmed plan ->
result appended to `state/fixes.jsonl` -> targeted re-check of that finding.

### Agent adapters

One `match` on `AgentKind` builds the `Command` (headless flag, full-access flag, prompt as an
argument). Exact flags for each CLI are verified against current docs at implementation
time, not from memory. Detection: GUI apps launched at login get a minimal `PATH`, so resolve
binaries via the user's login shell (`$SHELL -lc 'command -v <bin>'`) at the start of each
sweep. An agent missing or logged out is a target error with a fix hint, never a silent skip.

Flags, checked 2026-11-05 against each CLI's `--help` (Codex against its source at
`openai/codex@49f0c60`, since it is not installed here). Every agent runs with the bundle folder
as its working directory:

| Agent | Headless call | Full access |
|---|---|---|
| `claude` | `claude -p <prompt>` | `--dangerously-skip-permissions` |
| `grok` | `grok -p <prompt> --cwd <bundle>` | `--always-approve` |
| `codex` | `codex exec -C <bundle> --skip-git-repo-check <prompt>` | `--dangerously-bypass-approvals-and-sandbox` |
| `gemini` | `gemini -p <prompt>` | `--yolo` |
| `opencode` | `opencode run --dir <bundle> <prompt>` | `--dangerously-skip-permissions` |

The prompt argument is one line pointing at `PROMPT.md` in the bundle, so the real prompt is a
file the user can read and edit (`prompts/sweep.md` in the data dir, copied from the built-in
default on first use). The agent's stdout and stderr go to `agent.log` beside the bundle.

### Bundle and findings (decided 2026-11-05)

Each target's bundle folder holds:

- `PROMPT.md`: the rendered sweep prompt.
- `inventory.jsonl`: one component per line with a short id (`c1`, `c2`, ...).
- `advisories.jsonl`: one compact line per advisory: id, source, aliases, summary, source
  severity (CVSS score and vector, or GHSA severity), affected ranges, `known_exploited`, the
  ids of the components it was fetched for, and `record`, the path of its full record.
- `records/<id>.json`: each advisory's full record as the source served it, opened on demand.
- `findings.schema.json`: the JSON Schema of `findings.json`.

The agent writes `findings.json`: only advisories it judges to affect an installed version.
Each finding names its advisory ids (which must be in `advisories.jsonl`), its component id
(which must be in `inventory.jsonl`), a severity (`critical`, `high`, `medium`, `low`), whether
it is known exploited, a confidence (`confirmed` or `likely`), the evidence, a plain-language
explanation, and a suggested fix (summary, steps and commands, never run during a sweep). The
agent sets severity from the source score and this machine's context and says why when it
differs; a known-exploited finding is raised to at least `high` by the app.

The app validates strictly (unknown fields, unknown ids and bad enums are errors) and retries
once with the errors appended to the prompt; a second failure marks the target failed. One
sweep runs at a time, held by a lock file in the data dir.

Homebrew products for which NVD returns no CVEs are checked once against NVD's CPE dictionary;
a product NVD does not know is reported in the sweep report, so a wrong guessed name is visible.

### Feeds

Decided 2026-11-05 after checking the live APIs: OSV already mirrors the GitHub Advisory
Database (GHSA IDs), so there is no separate GHSA client; OSV bulk files are large (npm alone
is 220 MB, mostly `MAL-` reports), so the app queries by name instead of mirroring; Homebrew is
not an OSV ecosystem, so formulae go through NVD.

- OSV: `POST /v1/querybatch` with the inventory's package names (no versions), which returns
  every advisory id and `modified` time for those packages, `MAL-` malicious-package reports
  included. Full records come from `GET /v1/vulns/{id}` and are cached by id; a record is
  fetched again only when its `modified` time changes. OSV sees the package names, never the
  versions.
- NVD: CVE API 2.0 queried per product with `virtualMatchString=cpe:2.3:*:<vendor>:<product>`
  (`*` for a product given without a vendor; `vendor:name` where the bare name is shared), all
  history on the first fetch, then `lastModStartDate`/`lastModEndDate` windows (120-day
  maximum; an older cache is fetched in full again). Requests are paced to the published
  limit: 5 per 30 s without a key, 50 per 30 s with an API key read from the macOS Keychain
  (service `ancient-protector`, account `nvd-api-key`).
- KEV: the full CISA JSON catalog each sweep (about 2 MB); marks advisories whose CVE is
  actively exploited.
- `history.since` drops advisories both published and last modified before that date (NVD keeps
  a CVE's original published date when it later adds a product); records without either date
  are kept.
- Advisory ids and product names come from the network and become cache file names, so they
  are checked against a safe character set first.

### UI (Tauri 2)

- `LSUIElement` (no Dock icon), tray icon states: idle-clean, findings (by worst severity),
  sweeping, error.
- Popover panel under the icon, hidden on blur: per-target counts, Sweep now, newest findings.
- Window: finding details (agent explanation, evidence, fix plan + confirm), targets
  (Mac folders, repos, servers), agent picker, schedule, history window, report history.
- Rust <-> UI: Tauri commands call core; sweep progress streams as Tauri events.
- Plugins: notification, autostart, positioner (versions looked up at implementation time).
- Scheduler: in-app interval timer; skip if a sweep is running; run once on wake if overdue.

### CLI

`ancient-protector sweep [--target <id>]`, `findings [--json]`, `dismiss <key> --reason <text>`,
`fix plan <key>`, `fix apply <key>` (needs the confirmed plan id). Same core, same files.

## Risks to keep visible

- Prompt injection: advisory text and repo/server content are untrusted, and the agent has
  full access. Prompts mark the bundle data as untrusted. Per-fix confirmation is the only
  hard gate. Revisit the permission level if this proves a problem.
- Sweep runs have no timeout and no transcript (user's choice). `agent.log` captures stdout and
  stderr only.
- Agent cost: sequential per-target runs; feed pre-filtering keeps context small.

## Implementation order

Each step is a feature branch + draft PR with a fresh-context review per the global rules.
Load `rust-style` (plus the async/concurrency topic files), `ts-style`, and `gh-actions-style`
before the first edit in each area; look up current crate versions (tauri, tokio, serde,
toml, reqwest, clap, zip) before adding them.

1. Workspace skeleton, lints, deny.toml, CI, `config` + `paths`.
2. Feeds: OSV query + record cache, NVD per-product cache, KEV, and an `advisories` CLI command.
3. Mac inventory collectors and an `inventory` CLI command.
4. Agent adapters + detection + sweep for the Mac target + findings schema/validation + report,
   and the `sweep` CLI command.
5. GitHub target (deps, alerts, workflows, settings via `gh`).
6. Server target (two-phase agent run).
7. Lifecycle: dismissals, diff, fix plan/confirm/exec, fix history.
8. CLI.
9. Tauri app: tray, popover, window, notifications, autostart, scheduler.
10. Later: signing + notarization in CI once an Apple Developer account is available.

## Verification

- Unit tests per module with fixture files (feed records, `brew info --json`, lockfiles, `gh`
  API responses).
- Property tests for config round-trip, feed parsing, and the name-index pre-filter.
- Fake agent: a test script on `PATH` that writes canned `findings.json` (valid, invalid,
  missing) to exercise the sweep, retry, and failure paths without a real agent.
- `cargo-mutants` over core logic; kill or explain survivors.
- End to end: `ancient-protector sweep` against this Mac with a real agent and a test repo;
  then `cargo tauri dev`, run a sweep from the tray, confirm icon state, notification,
  report files, and a fix plan + apply on a deliberately outdated Homebrew formula.
- Zero warnings: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, oxlint/tsc.
