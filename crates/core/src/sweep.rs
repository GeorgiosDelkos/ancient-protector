//! One sweep of this Mac: inventory, advisories, the agent's verdict, and the report.
//!
//! Flow (spec, "Sweep flow"): collect the inventory; fetch OSV advisories for its packages, NVD
//! CVEs for its products and the KEV catalog; link each advisory to the components whose query
//! returned it; write the bundle; run the chosen agent in it; validate `findings.json`, retrying
//! once with the problems appended; write `report.json` and `report.md`.
//!
//! A source that fails is recorded in the report and the sweep goes on with the rest. Only one
//! sweep runs at a time: the running sweep holds an advisory lock (`flock`) on `.lock` in the
//! sweeps folder, which the system releases when the process ends, however it ends.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::io::Write as _;
use std::path::Path;
use std::path::PathBuf;

use jiff::Timestamp;
use serde::Serialize;

use crate::agent::AgentError;
use crate::agent::AgentKind;
use crate::agent::Located;
use crate::agent::PROMPT_LINE;
use crate::bundle;
use crate::bundle::BundleError;
use crate::config::Config;
use crate::config::History;
use crate::feeds::Advisory;
use crate::feeds::Feeds;
use crate::feeds::NvdAccess;
use crate::feeds::OsvAdvisory;
use crate::feeds::Product;
use crate::findings;
use crate::findings::Finding;
use crate::findings::Known;
use crate::findings::Valid;
use crate::findings::is_forging;
use crate::inventory::Component;
use crate::inventory::FoundIn;
use crate::inventory::Inventory;
use crate::inventory::Lookup;
use crate::package::Package;
use crate::paths::DataDir;

/// The built-in sweep prompt, copied to `prompts/sweep.md` on first use so the user can edit it.
const DEFAULT_PROMPT: &str = include_str!("prompts/sweep.md");

/// How many sweep folders may share one start second before the sweep gives up. Arbitrary:
/// sweeps run one at a time and each takes seconds at least, so two is already rare.
const SAME_SECOND_LIMIT: u32 = 100;

/// What the sweep is doing, for a progress display.
#[derive(Debug)]
pub enum Progress<'a> {
    /// Listing what is installed.
    Inventory,
    /// Fetching advisories for this many packages and products.
    Advisories {
        /// OSV packages.
        packages: usize,
        /// NVD products, each its own paced request.
        products: usize,
    },
    /// Fetching NVD CVEs for one product.
    Product {
        /// Its position, from 1.
        done: usize,
        /// How many there are.
        total: usize,
        /// The product.
        product: &'a str,
    },
    /// The agent is running; `attempt` is 1, or 2 after rejected findings.
    Agent {
        /// The agent.
        agent: AgentKind,
        /// Which try this is.
        attempt: u8,
    },
}

/// The result of a sweep, as written to `report.json`.
#[derive(Debug, Serialize)]
pub struct Report {
    /// When the sweep started.
    pub started: Timestamp,
    /// When it finished.
    pub finished: Timestamp,
    /// What was swept (`mac`).
    pub target: String,
    /// The agent that judged the advisories.
    pub agent: AgentKind,
    /// How many components went into the bundle.
    pub components: usize,
    /// How many advisories went into the bundle.
    pub advisories: usize,
    /// The affected components, most severe first.
    pub findings: Vec<ReportFinding>,
    /// What could not be checked: failed sources, unknown products, tools not installed.
    pub problems: Vec<String>,
    /// Why the agent's verdict is missing, when it is.
    pub failure: Option<String>,
    /// The sweep's folder: bundle, agent logs and this report.
    pub dir: PathBuf,
}

/// A finding with the component it names spelled out.
#[derive(Debug, Serialize)]
pub struct ReportFinding {
    /// The agent's finding.
    #[serde(flatten)]
    pub finding: Finding,
    /// The affected component.
    pub installed: Component,
}

/// Sweeps this Mac with the agent named in `config`.
///
/// Blocks for the whole sweep: inventory commands, every feed request (NVD is paced, so the
/// first sweep of a Mac with a hundred Homebrew formulae takes over ten minutes without an API
/// key), and the agent, which has no time limit. Calls `progress` as it goes.
///
/// # Errors
///
/// Fails before the agent runs when no agent is configured or found, another sweep is running,
/// or the sweep folder, prompt or bundle cannot be read or written. Failures after that (the
/// agent, its findings, the report files) are recorded in the returned report instead.
pub fn sweep_mac(
    data_dir: &DataDir,
    config: &Config,
    progress: &mut dyn FnMut(Progress<'_>),
) -> Result<Report, SweepError> {
    let agent = config.agent.ok_or(SweepError::NoAgent)?;
    let located = agent.locate()?.ok_or(SweepError::AgentNotFound { agent })?;
    let sweeps = data_dir.sweeps_dir();
    let _lock = Lock::acquire(&sweeps)?;
    let started = Timestamp::now();
    let dir = create_sweep_dir(&sweeps, started)?.join("mac");

    progress(Progress::Inventory);
    let inventory = Inventory::collect_mac(&config.project_dirs);
    let mut problems: Vec<String> = inventory.problems.iter().map(error_chain).collect();
    if !inventory.not_installed.is_empty() {
        let tools = inventory.not_installed.join(", ");
        problems.push(format!("not installed, so not checked: {tools}"));
    }

    let feeds = Feeds::new(data_dir, nvd_access(&mut problems));
    let fetched = fetch(&feeds, &inventory, config.history, &mut problems, progress);
    let entries: Vec<_> = fetched
        .iter()
        .map(|(advisory, components)| bundle::Entry {
            advisory,
            components: components.clone(),
        })
        .collect();
    let kev = match feeds.kev() {
        Ok(kev) => Some(kev),
        Err(e) => {
            problems.push(format!(
                "CISA KEV catalog, so known_exploited is unknown: {}",
                error_chain(&e)
            ));
            None
        }
    };
    let prompt = prompt(data_dir, &target_name(&inventory))?;
    let known = bundle::write(
        &dir.join("bundle"),
        &prompt,
        &inventory.components,
        &entries,
        kev.as_ref(),
    )?;

    let (valid, failure) = match judge(agent, &located, &dir, &known, progress) {
        Ok(valid) => (valid, None),
        Err(failure) => (Vec::new(), Some(plain(&failure))),
    };
    let mut findings: Vec<ReportFinding> = valid
        .into_iter()
        .map(|Valid { finding, component }| ReportFinding {
            finding,
            installed: inventory.components[component].clone(),
        })
        .collect();
    findings.sort_by_key(|f| f.finding.severity);

    let mut report = Report {
        started,
        finished: Timestamp::now(),
        target: "mac".to_owned(),
        agent,
        components: inventory.components.len(),
        advisories: entries.len(),
        findings,
        problems: problems.iter().map(|p| plain(p)).collect(),
        failure,
        dir: dir.clone(),
    };
    save_report(&dir, &mut report);
    Ok(report)
}

/// Creates `<sweeps>/<start time>`, or `<start time>-2` and so on when an earlier sweep
/// started in the same second.
fn create_sweep_dir(sweeps: &Path, started: Timestamp) -> Result<PathBuf, SweepError> {
    let stamp = started.strftime("%Y%m%dT%H%M%SZ").to_string();
    let mut last = None;
    for n in 1..=SAME_SECOND_LIMIT {
        let name = if n == 1 {
            stamp.clone()
        } else {
            format!("{stamp}-{n}")
        };
        let path = sweeps.join(name);
        match fs::create_dir(&path) {
            Ok(()) => return Ok(path),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => last = Some((path, e)),
            Err(source) => return Err(SweepError::Write { path, source }),
        }
    }
    let (path, source) = last.expect("the loop runs at least once");
    Err(SweepError::Write { path, source })
}

/// The API key from the Keychain, or anonymous access with a note when it cannot be read. Read
/// on every sweep: a Mac inventory always has macOS itself, an NVD product.
fn nvd_access(problems: &mut Vec<String>) -> NvdAccess {
    NvdAccess::from_keychain().unwrap_or_else(|e| {
        problems.push(format!(
            "NVD API key, so NVD is queried without one: {}",
            error_chain(&e)
        ));
        NvdAccess::Anonymous
    })
}

/// Fetches every advisory for the inventory, each with the indexes of the components whose
/// lookup returned it.
fn fetch(
    feeds: &Feeds,
    inventory: &Inventory,
    history: History,
    problems: &mut Vec<String>,
    progress: &mut dyn FnMut(Progress<'_>),
) -> Vec<(Advisory, BTreeSet<usize>)> {
    let mut packages: BTreeMap<Package, Vec<usize>> = BTreeMap::new();
    let mut products: BTreeMap<String, (Product, Vec<usize>)> = BTreeMap::new();
    for (i, component) in inventory.components.iter().enumerate() {
        match &component.lookup {
            Lookup::Package(p) => packages.entry(p.clone()).or_default().push(i),
            Lookup::Product(p) => {
                let entry = products
                    .entry(p.to_string())
                    .or_insert_with(|| (p.clone(), Vec::new()));
                entry.1.push(i);
            }
        }
    }
    progress(Progress::Advisories {
        packages: packages.len(),
        products: products.len(),
    });

    let mut fetched = fetch_osv(feeds, &packages, history, problems);
    fetched.extend(fetch_nvd(feeds, &products, history, problems, progress));
    fetched
}

/// OSV advisories, linked by the queries that returned them. The record's own `affected`
/// names are not used: OSV matches names the way each ecosystem compares them (PyPI's
/// `Django` is `django`), and the query result already carries that match.
fn fetch_osv(
    feeds: &Feeds,
    packages: &BTreeMap<Package, Vec<usize>>,
    history: History,
    problems: &mut Vec<String>,
) -> Vec<(Advisory, BTreeSet<usize>)> {
    if packages.is_empty() {
        return Vec::new();
    }
    let list: Vec<Package> = packages.keys().cloned().collect();
    let osv = match feeds.osv(&list, history) {
        Ok(osv) => osv,
        Err(e) => {
            problems.push(format!("OSV: {}", error_chain(&e)));
            return Vec::new();
        }
    };
    for e in &osv.failures {
        problems.push(format!("OSV record: {}", error_chain(e)));
    }
    osv.advisories
        .into_iter()
        .map(
            |OsvAdvisory {
                 advisory,
                 packages: matched,
             }| {
                let components = matched
                    .iter()
                    .filter_map(|p| packages.get(p))
                    .flatten()
                    .copied()
                    .collect();
                (advisory, components)
            },
        )
        .collect()
}

/// NVD CVEs per product, merged by CVE id, and one note for every product NVD does not know.
fn fetch_nvd(
    feeds: &Feeds,
    products: &BTreeMap<String, (Product, Vec<usize>)>,
    history: History,
    problems: &mut Vec<String>,
    progress: &mut dyn FnMut(Progress<'_>),
) -> Vec<(Advisory, BTreeSet<usize>)> {
    let mut found: BTreeMap<String, (Advisory, BTreeSet<usize>)> = BTreeMap::new();
    let mut unknown = Vec::new();
    for (done, (name, (product, indexes))) in products.iter().enumerate() {
        progress(Progress::Product {
            done: done + 1,
            total: products.len(),
            product: name,
        });
        match feeds.nvd(product, history) {
            // No CVEs can mean a clean product or a name NVD does not know; tell them apart.
            Ok(advisories) if advisories.is_empty() => match feeds.nvd_product_known(product) {
                Ok(true) => {}
                Ok(false) => unknown.push(name.as_str()),
                Err(e) => problems.push(format!("NVD product check {name}: {}", error_chain(&e))),
            },
            Ok(advisories) => {
                for advisory in advisories {
                    let entry = found
                        .entry(advisory.id.clone())
                        .or_insert_with(|| (advisory, BTreeSet::new()));
                    entry.1.extend(indexes);
                }
            }
            Err(e) => problems.push(format!("NVD product {name}: {}", error_chain(&e))),
        }
    }
    if !unknown.is_empty() {
        problems.push(format!(
            "NVD knows no product named {}, so these were not checked",
            unknown.join(", ")
        ));
    }
    found.into_values().collect()
}

/// Runs the agent and validates its findings, once more with the problems if they are
/// rejected. Returns why there is no verdict otherwise.
///
/// A `findings.json` that passes counts even when the agent then exits non-zero: the verdict is
/// in the file. An agent that cannot start, or exits non-zero without a file, is not retried,
/// since the same command would fail the same way.
fn judge(
    agent: AgentKind,
    located: &Located,
    dir: &Path,
    known: &Known,
    progress: &mut dyn FnMut(Progress<'_>),
) -> Result<Vec<Valid>, String> {
    let bundle = dir.join("bundle");
    let findings_path = bundle.join("findings.json");
    let rejected_path = bundle.join("findings.rejected.json");
    let mut prompt = PROMPT_LINE.to_owned();
    let mut last = Vec::new();
    for attempt in 1..=2 {
        progress(Progress::Agent { agent, attempt });
        let log = dir.join(format!("agent-{attempt}.log"));
        let status = agent
            .run_sweep(located, &bundle, &prompt, &log)
            .map_err(|e| error_chain(&e))?;
        let (problems, previous) = match fs::read_to_string(&findings_path) {
            Ok(text) => match findings::validate(&text, known) {
                Ok(valid) => return Ok(valid),
                Err(problems) => (problems, "was rejected and moved to findings.rejected.json"),
            },
            Err(_) if !status.success() => {
                return Err(format!(
                    "{agent} exited with {status} without writing findings.json; see {} (is it \
                     logged in?)",
                    log.display()
                ));
            }
            Err(e) => (
                vec![format!("findings.json could not be read: {e}")],
                "is missing",
            ),
        };
        // Kept for the agent to correct, and so that it cannot pass for the next answer.
        if let Err(e) = fs::rename(&findings_path, &rejected_path)
            && e.kind() != io::ErrorKind::NotFound
        {
            return Err(format!("cannot set aside the rejected findings.json: {e}"));
        }
        prompt = format!(
            "{PROMPT_LINE} Your findings.json {previous}; fix these problems and write \
             findings.json again:\n- {}",
            problems
                .iter()
                .map(|p| plain(p))
                .collect::<Vec<_>>()
                .join("\n- ")
        );
        last = problems;
    }
    Err(format!(
        "{agent}'s findings were rejected twice: {}",
        last.join("; ")
    ))
}

/// `text` as one line: line breaks and tabs become spaces, and every other control or
/// invisible character ([`is_forging`]) becomes U+FFFD. For messages that quote the agent (a
/// rejected id, a serde error naming its field) and reach the terminal, `report.json` or the
/// agent's next prompt.
fn plain(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            '\n' | '\r' | '\t' => ' ',
            c if is_forging(c) => '\u{fffd}',
            c => c,
        })
        .collect()
}

/// "this Mac (macOS 27.2)", or "this Mac" when the version is unknown.
fn target_name(inventory: &Inventory) -> String {
    inventory
        .components
        .iter()
        .find(|c| matches!(c.found_in, FoundIn::MacOs))
        .map_or_else(
            || "this Mac".to_owned(),
            |c| format!("this Mac (macOS {})", c.version),
        )
}

/// The user's `prompts/sweep.md`, created from the built-in one on first use, with the target
/// filled in.
fn prompt(data_dir: &DataDir, target: &str) -> Result<String, SweepError> {
    let dir = data_dir.prompts_dir();
    let path = dir.join("sweep.md");
    let template = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            fs::create_dir_all(&dir)
                .and_then(|()| fs::write(&path, DEFAULT_PROMPT))
                .map_err(|source| SweepError::Write {
                    path: path.clone(),
                    source,
                })?;
            DEFAULT_PROMPT.to_owned()
        }
        Err(source) => return Err(SweepError::Read { path, source }),
    };
    Ok(template.replace("{{target}}", target))
}

/// Writes the report files, or notes in the report why they could not be written: the verdict
/// is worth more than its files, so a report that cannot be saved is still returned.
fn save_report(dir: &Path, report: &mut Report) {
    if let Err(e) = write_report(dir, report) {
        report
            .problems
            .push(format!("report files: {}", error_chain(&e)));
    }
}

/// Writes `report.json` and `report.md`, each to a temporary name, synced, and then renamed,
/// so neither a reader nor a crash leaves half a report.
fn write_report(dir: &Path, report: &Report) -> Result<(), SweepError> {
    let json = serde_json::to_string_pretty(report).map_err(|e| SweepError::Write {
        path: dir.join("report.json"),
        source: io::Error::other(e),
    })?;
    // Markdown first: if it fails, no `report.json` is left that lacks the failure the returned
    // report carries.
    for (name, text) in [
        ("report.md", report_markdown(report)),
        ("report.json", json),
    ] {
        let path = dir.join(name);
        let partial = dir.join(format!(".{name}.partial"));
        let written = fs::File::create(&partial)
            .and_then(|mut file| {
                file.write_all(text.as_bytes())?;
                file.sync_data()
            })
            .and_then(|()| fs::rename(&partial, &path));
        if let Err(source) = written {
            // Best effort: the error below is what matters, and a leftover partial file is
            // harmless, since readers open only `report.json` and `report.md`.
            drop(fs::remove_file(&partial));
            return Err(SweepError::Write { path, source });
        }
    }
    Ok(())
}

/// The report for a person: findings first, most severe first, then what was not checked.
///
/// Agent text, component names and paths are escaped (see [`escape`]), so none of them can add
/// headings, link syntax or code blocks, or send terminal escape sequences. A bare URL stays
/// visible text, though a renderer that autolinks may make it clickable.
pub fn report_markdown(report: &Report) -> String {
    let mut out = format!(
        "# Sweep of {} ({})\n\nAgent: {}. {} components, {} advisories checked.\n\n",
        report.target, report.started, report.agent, report.components, report.advisories
    );
    out.push_str(&headline(report));
    for group in by_component(&report.findings) {
        let first = group[0];
        let advisories = if group.len() == 1 {
            "1 advisory".to_owned()
        } else {
            format!("{} advisories", group.len())
        };
        out.push_str(&format!(
            "## {} {} {}\n\nFound in {}. {advisories}.\n\n",
            first.finding.severity.to_string().to_uppercase(),
            escape(&component_name(&first.installed)),
            escape(&first.installed.version),
            escape(&first.installed.found_in.to_string()),
        ));
        for f in group {
            out.push_str(&finding_markdown(&f.finding));
        }
    }
    if !report.problems.is_empty() {
        out.push_str("## Not checked\n\n");
        for problem in &report.problems {
            out.push_str(&format!("- {}\n", escape(problem)));
        }
    }
    out
}

/// The sentence under the title: no verdict, a clean result, or a clean result with gaps.
fn headline(report: &Report) -> String {
    if let Some(failure) = &report.failure {
        return format!("**No verdict:** {}\n\n", escape(failure));
    }
    match (report.findings.is_empty(), report.problems.is_empty()) {
        (true, true) => "No installed component is affected by a known advisory.\n\n".to_owned(),
        (true, false) => "No affected component among what was checked; some things were not \
                          checked (see the end).\n\n"
            .to_owned(),
        (false, _) => String::new(),
    }
}

/// Groups findings by component (same lookup, version and place found), in the order of each
/// group's first finding. Findings are sorted most severe first, so each group starts with its
/// worst finding and the groups come worst first.
fn by_component(findings: &[ReportFinding]) -> Vec<Vec<&ReportFinding>> {
    let mut groups: Vec<Vec<&ReportFinding>> = Vec::new();
    for f in findings {
        let key = component_key(&f.installed);
        match groups
            .iter_mut()
            .find(|g| component_key(&g[0].installed) == key)
        {
            Some(group) => group.push(f),
            None => groups.push(vec![f]),
        }
    }
    groups
}

fn component_key(component: &Component) -> String {
    format!(
        "{}|{}|{}",
        component_name(component),
        component.version,
        component.found_in
    )
}

fn finding_markdown(finding: &Finding) -> String {
    let exploited = if finding.known_exploited {
        ", known exploited"
    } else {
        ""
    };
    let mut out = format!(
        "### {} {} ({}{exploited})\n\nWhy: {}\n\nEvidence: {}\n\nFix: {}\n",
        finding.severity,
        escape(&finding.advisories.join(", ")),
        finding.confidence,
        escape(&finding.explanation),
        escape(&finding.evidence),
        escape(&finding.fix.summary),
    );
    // The steps are left out: the commands are what to run, and the steps belong to the fix
    // plan (spec, "Fix flow").
    if !finding.fix.commands.is_empty() {
        // Longer than any backtick run in the commands, so none can close the block early.
        let longest = finding
            .fix
            .commands
            .iter()
            .flat_map(|c| c.split(|ch| ch != '`'))
            .map(str::len)
            .max()
            .unwrap_or(0);
        let fence = "`".repeat(longest.max(2) + 1);
        out.push_str(&format!("\n{fence}sh\n"));
        for command in &finding.fix.commands {
            out.push_str(&plain(command));
            out.push('\n');
        }
        out.push_str(&format!("{fence}\n"));
    }
    out.push('\n');
    out
}

/// Makes `text` one plain Markdown line: whitespace runs (line breaks too) become one space,
/// control and invisible formatting characters ([`is_forging`]) become U+FFFD, and the
/// characters that start inline Markdown (code, emphasis, links, HTML) are backslash-escaped.
/// Each use sits after a label or a heading marker, never at the start of a line, so no block
/// syntax (a heading, a list) can begin.
fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for (i, word) in text.split_whitespace().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        for c in word.chars() {
            if is_forging(c) {
                out.push('\u{fffd}');
                continue;
            }
            if matches!(
                c,
                '\\' | '`' | '*' | '_' | '[' | ']' | '<' | '>' | '~' | '|' | '#' | '&'
            ) {
                out.push('\\');
            }
            out.push(c);
        }
    }
    out
}

fn component_name(component: &Component) -> String {
    match &component.lookup {
        Lookup::Package(p) => format!("{} ({})", p.name, p.ecosystem.osv_name()),
        Lookup::Product(p) => p.to_string(),
    }
}

/// Renders an error and its sources as `outer: inner`.
fn error_chain(error: &impl std::error::Error) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(e) = source {
        text.push_str(&format!(": {e}"));
        source = e.source();
    }
    text
}

/// The running sweep's hold on `.lock` in the sweeps folder. The system releases it when the
/// file closes: on drop, or when the process ends, so a crashed sweep leaves nothing stale.
/// The file is never deleted: a sweep that deleted it could let the next one lock a new file of
/// the same name while a third still holds the old one.
#[derive(Debug)]
struct Lock {
    _file: fs::File,
}

impl Lock {
    fn acquire(sweeps: &Path) -> Result<Self, SweepError> {
        let path = sweeps.join(".lock");
        let write_err = |source| SweepError::Write {
            path: path.clone(),
            source,
        };
        fs::create_dir_all(sweeps).map_err(|source| SweepError::Write {
            path: sweeps.to_owned(),
            source,
        })?;
        let file = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)
            .map_err(write_err)?;
        match file.try_lock() {
            Ok(()) => Ok(Self { _file: file }),
            Err(fs::TryLockError::WouldBlock) => Err(SweepError::Busy { lock: path }),
            Err(fs::TryLockError::Error(e)) => Err(write_err(e)),
        }
    }
}

/// Error that stops a sweep before the agent runs.
#[derive(Debug, thiserror::Error)]
pub enum SweepError {
    /// config.toml names no agent.
    #[error(
        "no agent chosen; set `agent` in config.toml (claude, grok, codex, gemini or opencode)"
    )]
    NoAgent,
    /// The chosen agent is not installed.
    #[error(
        "{agent} is not installed (the login shell cannot find it); install it or choose another \
         agent"
    )]
    AgentNotFound {
        /// The agent.
        agent: AgentKind,
    },
    /// Looking the agent up failed.
    #[error(transparent)]
    Agent(#[from] AgentError),
    /// Another sweep holds the lock.
    #[error("another sweep is running (it holds {}); wait for it to finish", lock.display())]
    Busy {
        /// The lock file.
        lock: PathBuf,
    },
    /// The bundle could not be written.
    #[error(transparent)]
    Bundle(#[from] BundleError),
    /// A sweep file could not be read.
    #[error("cannot read {}", path.display())]
    Read {
        /// The file.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: io::Error,
    },
    /// A sweep file or folder could not be written.
    #[error("cannot write {}", path.display())]
    Write {
        /// The file or folder.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: io::Error,
    },
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use serde_json::Value;
    use serde_json::json;

    use super::*;
    use crate::feeds::Endpoints;
    use crate::feeds::test_server::Request;
    use crate::feeds::test_server::TestServer;

    fn component(lookup: &str, version: &str) -> Component {
        let lookup = if lookup.contains(':') {
            Lookup::Package(lookup.parse().unwrap())
        } else {
            Lookup::Product(lookup.parse().unwrap())
        };
        Component {
            lookup,
            version: version.to_owned(),
            found_in: FoundIn::MacOs,
        }
    }

    /// OSV knows GHSA-1 for lodash and PYSEC-1 for django (whose record spells it `Django`);
    /// NVD knows CVE-9 for curl and nothing for a made-up product that is also missing from the
    /// CPE dictionary.
    fn feeds_server() -> TestServer {
        TestServer::start(|request: &Request| match request.path() {
            "/v1/querybatch" => {
                let body: Value = serde_json::from_str(&request.body).unwrap();
                let results: Vec<Value> = body["queries"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|q| {
                        let id = match q["package"]["name"].as_str().unwrap() {
                            "lodash" => "GHSA-1",
                            _ => "PYSEC-1",
                        };
                        json!({"vulns": [{"id": id, "modified": "2026-01-01T00:00:00Z"}]})
                    })
                    .collect();
                (200, json!({ "results": results }).to_string())
            }
            "/v1/vulns/GHSA-1" => (200, osv_record("GHSA-1", "npm", "lodash")),
            "/v1/vulns/PYSEC-1" => (200, osv_record("PYSEC-1", "PyPI", "Django")),
            "/rest/json/cves/2.0" => {
                let curl =
                    request.query("virtualMatchString").as_deref() == Some("cpe:2.3:*:*:curl");
                let cves = if curl {
                    json!([{"cve": {"id": "CVE-9", "published": "2026-01-01T00:00:00.000"}}])
                } else {
                    json!([])
                };
                let page = json!({
                    "startIndex": 0,
                    "totalResults": cves.as_array().unwrap().len(),
                    "timestamp": "2026-11-01T00:00:00.000",
                    "vulnerabilities": cves
                });
                (200, page.to_string())
            }
            "/rest/json/cpes/2.0" => (200, json!({"totalResults": 0}).to_string()),
            other => (404, format!("unexpected {other}")),
        })
    }

    fn osv_record(id: &str, ecosystem: &str, name: &str) -> String {
        json!({
            "id": id,
            "modified": "2026-01-01T00:00:00Z",
            "affected": [{"package": {"ecosystem": ecosystem, "name": name}}]
        })
        .to_string()
    }

    #[test]
    fn links_each_advisory_to_its_components_and_notes_unknown_products() {
        let server = feeds_server();
        let tmp = tempfile::tempdir().unwrap();
        let feeds = Feeds::with_endpoints(
            tmp.path().to_owned(),
            NvdAccess::Anonymous,
            Endpoints {
                osv: server.url.clone(),
                nvd: server.url.clone(),
                kev: server.url.clone(),
            },
        )
        .without_pacing();
        let inventory = Inventory {
            components: vec![
                component("npm:lodash", "4.17.20"),
                component("curl", "8.0.0"),
                component("npm:lodash", "4.17.21"),
                component("made-up-product", "1"),
                component("pypi:django", "4.2"),
            ],
            ..Inventory::default()
        };
        let history = Config::default_for_tests().history;
        let mut problems = Vec::new();
        let mut seen = Vec::new();
        let fetched = fetch(&feeds, &inventory, history, &mut problems, &mut |p| {
            seen.push(format!("{p:?}"));
        });

        let linked: Vec<(&str, Vec<usize>)> = fetched
            .iter()
            .map(|(a, c)| (a.id.as_str(), c.iter().copied().collect()))
            .collect();
        assert_eq!(
            linked,
            [
                ("GHSA-1", vec![0, 2]),
                ("PYSEC-1", vec![4]),
                ("CVE-9", vec![1])
            ],
            "linked by query, so `Django` reaches django"
        );
        assert_eq!(
            problems,
            ["NVD knows no product named made-up-product, so these were not checked"]
        );
        assert!(seen[0].contains("packages: 2, products: 2"), "{seen:?}");
        assert!(seen[1].contains("done: 1, total: 2"), "{seen:?}");
    }

    fn report_finding(id: &str, severity: &str, kev: bool, lookup: &str) -> ReportFinding {
        ReportFinding {
            finding: serde_json::from_value(json!({
                "advisories": [id],
                "component": "c1",
                "severity": severity,
                "known_exploited": kev,
                "confidence": "confirmed",
                "evidence": "in range",
                "explanation": "Bad.",
                "fix": {"summary": "Upgrade", "steps": [], "commands": [format!("upgrade {id}")]}
            }))
            .unwrap(),
            installed: component(lookup, "1.0"),
        }
    }

    fn report(findings: Vec<ReportFinding>, problems: &[&str]) -> Report {
        Report {
            started: "2026-11-05T10:00:00Z".parse().unwrap(),
            finished: "2026-11-05T10:05:00Z".parse().unwrap(),
            target: "mac".into(),
            agent: AgentKind::Claude,
            components: 2,
            advisories: 1,
            findings,
            problems: problems.iter().map(|p| (*p).to_owned()).collect(),
            failure: None,
            dir: PathBuf::from("/tmp/s"),
        }
    }

    #[test]
    fn markdown_lists_findings_then_gaps() {
        let text = report_markdown(&report(
            vec![
                report_finding("GHSA-1", "high", true, "npm:lodash"),
                report_finding("GHSA-2", "medium", false, "npm:lodash"),
                report_finding("CVE-3", "low", false, "curl"),
            ],
            &["OSV: offline"],
        ));
        assert!(
            text.contains("## HIGH lodash (npm) 1.0\n\nFound in macOS. 2 advisories."),
            "{text}"
        );
        assert!(
            text.contains("### high GHSA-1 (confirmed, known exploited)"),
            "{text}"
        );
        assert!(text.contains("### medium GHSA-2 (confirmed)"), "{text}");
        assert!(
            text.contains("## LOW curl 1.0\n\nFound in macOS. 1 advisory."),
            "{text}"
        );
        assert!(text.contains("```sh\nupgrade GHSA-1\n```"), "{text}");
        assert_eq!(
            text.matches("## HIGH").count(),
            1,
            "one section per component"
        );
        let lodash = text.find("## HIGH lodash").unwrap();
        assert!(lodash < text.find("## LOW curl").unwrap(), "worst first");
        assert!(text.contains("## Not checked\n\n- OSV: offline"), "{text}");
        assert!(!text.contains("No affected"), "{text}");
    }

    #[test]
    fn headline_says_what_the_verdict_covers() {
        let clean = report_markdown(&report(vec![], &[]));
        assert!(
            clean.contains("No installed component is affected"),
            "{clean}"
        );
        let gaps = report_markdown(&report(vec![], &["OSV: offline"]));
        assert!(gaps.contains("some things were not checked"), "{gaps}");
        assert!(
            !gaps.contains("No installed component is affected"),
            "{gaps}"
        );
        let failed = Report {
            failure: Some("claude exited".into()),
            ..report(vec![], &[])
        };
        let failed = report_markdown(&failed);
        assert!(failed.contains("**No verdict:** claude exited"), "{failed}");
        assert!(!failed.contains("No installed component"), "{failed}");
    }

    #[test]
    fn agent_text_cannot_forge_markdown() {
        let mut forged = report_finding("GHSA-1", "low", false, "npm:lodash");
        forged.finding.explanation = "Fine.\n\n## Not checked\n\n- [click](http://x) `x`".into();
        forged.finding.fix.commands = vec!["echo ```".into(), "echo ok".into()];
        let text = report_markdown(&report(vec![forged], &[]));
        assert!(
            text.contains("Fine. \\#\\# Not checked - \\[click\\](http://x) \\`x\\`"),
            "{text}"
        );
        assert!(!text.contains("\n## Not checked"), "{text}");
        assert!(
            text.contains("\n````sh\necho ```\necho ok\n````\n"),
            "{text}"
        );
        assert_eq!(escape("a\u{1b}[2Jb"), "a\u{fffd}\\[2Jb");
        assert_eq!(escape("  two\n words "), "two words");
        assert_eq!(escape("bidi \u{202e}x"), "bidi \u{fffd}x");
        assert_eq!(escape("&#x202e;"), "\\&\\#x202e;", "no entity reference");
        assert_eq!(plain("id \u{1b}[2J\n"), "id \u{fffd}[2J ");

        // The explanation follows a label, so it cannot start a list or a rule.
        let mut listy = report_finding("GHSA-1", "low", false, "npm:lodash");
        listy.finding.explanation = "- one\n1. two\n---".into();
        let text = report_markdown(&report(vec![listy], &[]));
        assert!(text.contains("\nWhy: - one 1. two ---\n"), "{text}");
    }

    #[test]
    fn a_report_that_cannot_be_saved_says_so() {
        let tmp = tempfile::tempdir().unwrap();
        let mut report = report(vec![], &[]);
        save_report(&tmp.path().join("missing"), &mut report);
        assert_eq!(report.problems.len(), 1, "{:?}", report.problems);
        assert!(
            report.problems[0].starts_with("report files: cannot write"),
            "{:?}",
            report.problems
        );
        save_report(tmp.path(), &mut report);
        assert_eq!(report.problems.len(), 1, "saved");
        assert!(tmp.path().join("report.md").exists());
    }

    #[test]
    fn lock_is_exclusive_and_released_on_drop() {
        let tmp = tempfile::tempdir().unwrap();
        let lock = Lock::acquire(tmp.path()).unwrap();
        let err = Lock::acquire(tmp.path()).unwrap_err();
        assert!(matches!(err, SweepError::Busy { .. }), "{err:?}");
        assert!(
            err.to_string().contains("another sweep is running"),
            "{err}"
        );
        drop(lock);
        // Other tests spawn processes. This check failed once in the full suite right after the
        // drop. The likely cause, not confirmed: a child another test is starting holds a copy of
        // every open file, the lock included, until it execs. So the lock may take a moment to
        // come free.
        let again = (0..100).find_map(|_| {
            Lock::acquire(tmp.path()).ok().or_else(|| {
                std::thread::sleep(std::time::Duration::from_millis(20));
                None
            })
        });
        assert!(again.is_some(), "the lock is free once dropped");
    }

    #[test]
    fn sweeps_in_the_same_second_get_their_own_folder() {
        let tmp = tempfile::tempdir().unwrap();
        let at: Timestamp = "2026-11-05T10:00:00Z".parse().unwrap();
        let first = create_sweep_dir(tmp.path(), at).unwrap();
        let second = create_sweep_dir(tmp.path(), at).unwrap();
        let third = create_sweep_dir(tmp.path(), at).unwrap();
        assert_eq!(first, tmp.path().join("20261105T100000Z"));
        assert_eq!(second, tmp.path().join("20261105T100000Z-2"));
        assert_eq!(third, tmp.path().join("20261105T100000Z-3"));

        for n in 4..=SAME_SECOND_LIMIT {
            create_sweep_dir(tmp.path(), at).unwrap_or_else(|e| panic!("{n}: {e}"));
        }
        let err = create_sweep_dir(tmp.path(), at).unwrap_err();
        let exists = io::ErrorKind::AlreadyExists;
        assert!(
            matches!(&err, SweepError::Write { source, .. } if source.kind() == exists),
            "{err:?}"
        );

        // Any other failure stops at the first name instead of trying the next.
        let missing = tmp.path().join("missing");
        let err = create_sweep_dir(&missing, at).unwrap_err();
        let first = missing.join("20261105T100000Z");
        assert!(
            matches!(&err, SweepError::Write { path, .. } if *path == first),
            "{err:?}"
        );
    }

    #[test]
    fn prompt_is_copied_once_then_read() {
        let tmp = tempfile::tempdir().unwrap();
        let data = DataDir::new(tmp.path());
        let text = prompt(&data, "this Mac").unwrap();
        assert!(
            text.starts_with("# Vulnerability sweep: this Mac"),
            "{text}"
        );
        let path = tmp.path().join("prompts/sweep.md");
        fs::write(&path, "Mine: {{target}}").unwrap();
        assert_eq!(prompt(&data, "x").unwrap(), "Mine: x");

        // A template that exists but cannot be read is an error, not a reason to overwrite it.
        // Write-only, so overwriting would succeed if the code tried.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o200)).unwrap();
        let result = prompt(&data, "x");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(result, Err(SweepError::Read { .. })), "{result:?}");
        assert_eq!(fs::read_to_string(&path).unwrap(), "Mine: {{target}}");
    }

    #[test]
    fn report_files_replace_whole() {
        let tmp = tempfile::tempdir().unwrap();
        let report = report(vec![], &[]);
        write_report(tmp.path(), &report).unwrap();
        let json: Value =
            serde_json::from_str(&fs::read_to_string(tmp.path().join("report.json")).unwrap())
                .unwrap();
        assert_eq!(json["target"], "mac");
        let md = fs::read_to_string(tmp.path().join("report.md")).unwrap();
        assert_eq!(md, report_markdown(&report));
        let left: Vec<_> = fs::read_dir(tmp.path()).unwrap().collect();
        assert_eq!(left.len(), 2, "no partial files left");

        let err = write_report(&tmp.path().join("missing"), &report).unwrap_err();
        assert!(matches!(err, SweepError::Write { .. }), "{err:?}");
    }

    #[test]
    fn error_chain_joins_sources() {
        let err = SweepError::Read {
            path: PathBuf::from("/x"),
            source: io::Error::other("disk on fire"),
        };
        assert_eq!(error_chain(&err), "cannot read /x: disk on fire");
    }

    #[test]
    fn unwritable_sweeps_folder_is_a_write_error() {
        let tmp = tempfile::tempdir().unwrap();
        fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o555)).unwrap();
        let in_place = Lock::acquire(tmp.path());
        let sweeps = tmp.path().join("sweeps");
        let missing = Lock::acquire(&sweeps);
        fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let denied = io::ErrorKind::PermissionDenied;
        let lock = tmp.path().join(".lock");
        let Err(SweepError::Write { path, source }) = &in_place else {
            panic!("{in_place:?}");
        };
        assert_eq!((path, source.kind()), (&lock, denied));
        assert!(
            matches!(&missing, Err(SweepError::Write { path, .. }) if *path == sweeps),
            "the folder, not the lock: {missing:?}"
        );
    }
}

#[cfg(test)]
mod markdown_properties {
    use proptest::prelude::*;
    use serde_json::json;

    use super::*;

    // Written out again, not shared with `escape`, so a character dropped from one is caught.
    const SPECIAL: [char; 12] = ['\\', '`', '*', '_', '[', ']', '<', '>', '~', '|', '#', '&'];

    proptest! {
        /// Escaped text is one line with no invisible characters, and every Markdown character
        /// in it is backslash-escaped.
        #[test]
        fn escaped_text_is_one_inert_line(text in any::<String>()) {
            let escaped = escape(&text);
            prop_assert!(!escaped.contains(['\n', '\r']));
            prop_assert!(!escaped.chars().any(is_forging));
            let mut chars = escaped.chars();
            while let Some(c) = chars.next() {
                if c == '\\' {
                    prop_assert!(chars.next().is_some_and(|n| SPECIAL.contains(&n)));
                } else {
                    prop_assert!(!SPECIAL.contains(&c), "unescaped {:?} in {:?}", c, escaped);
                }
            }
        }

        /// Whatever the agent writes, a finding renders as one heading and labelled paragraphs.
        #[test]
        fn a_finding_keeps_its_shape(
            explanation in any::<String>(),
            evidence in any::<String>(),
            summary in any::<String>(),
            commands in prop::collection::vec("[ -~]{0,20}", 0..3),
        ) {
            let finding: Finding = serde_json::from_value(json!({
                "advisories": ["GHSA-1"],
                "component": "c1",
                "severity": "low",
                "known_exploited": false,
                "confidence": "likely",
                "evidence": evidence,
                "explanation": explanation,
                "fix": {"summary": summary, "steps": [], "commands": commands}
            }))
            .unwrap();
            let text = finding_markdown(&finding);
            let lines: Vec<&str> = text.lines().filter(|l| !l.is_empty()).collect();
            prop_assert!(lines[0].starts_with("### low GHSA-1 (likely)"));
            for (line, label) in lines[1..4].iter().zip(["Why:", "Evidence:", "Fix:"]) {
                prop_assert!(line.starts_with(label), "{:?}", line);
            }

            // The commands, if any, sit in one block that nothing inside can close: a closing
            // fence is a line of at least as many backticks as the opening one.
            let body: Vec<&str> = text
                .lines()
                .skip_while(|l| !l.starts_with("Fix:"))
                .skip(2)
                .collect();
            if commands.is_empty() {
                prop_assert_eq!(lines.len(), 4, "{:?}", text);
            } else {
                let fence = body[0].strip_suffix("sh").unwrap();
                prop_assert!(fence.len() >= 3 && fence.bytes().all(|b| b == b'`'));
                let listed: Vec<&str> = commands.iter().map(String::as_str).collect();
                prop_assert_eq!(&body[1..=commands.len()], listed.as_slice());
                prop_assert_eq!(body[commands.len() + 1], fence);
                for command in &commands {
                    let closes = command.trim().len() >= fence.len()
                        && command.trim().bytes().all(|b| b == b'`');
                    prop_assert!(!closes, "{:?} closes {:?}", command, fence);
                }
            }
        }
    }
}
