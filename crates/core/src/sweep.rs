//! One sweep of this Mac: inventory, advisories, the agent's verdict, and the report.
//!
//! Flow (spec, "Sweep flow"): collect the inventory; fetch OSV advisories for its packages, NVD
//! CVEs for its products and the KEV catalog; link each advisory to the components it was
//! fetched for; write the bundle; run the chosen agent in it; validate `findings.json`, retrying
//! once with the problems appended; write `report.json` and `report.md`.
//!
//! A source that fails is recorded in the report and the sweep goes on with the rest. Only one
//! sweep runs at a time: a lock file in the sweeps folder holds the running sweep's pid.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::Path;
use std::path::PathBuf;
use std::process;

use jiff::Timestamp;
use serde::Serialize;

use crate::agent::AgentError;
use crate::agent::AgentKind;
use crate::agent::PROMPT_LINE;
use crate::bundle;
use crate::bundle::BundleError;
use crate::config::Config;
use crate::feeds::Advisory;
use crate::feeds::Feeds;
use crate::feeds::NvdAccess;
use crate::findings;
use crate::findings::Finding;
use crate::findings::Known;
use crate::inventory::Component;
use crate::inventory::FoundIn;
use crate::inventory::Inventory;
use crate::inventory::Lookup;
use crate::paths::DataDir;

/// The built-in sweep prompt, copied to `prompts/sweep.md` on first use so the user can edit it.
const DEFAULT_PROMPT: &str = include_str!("prompts/sweep.md");

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
    /// How many components and advisories went into the bundle.
    pub components: usize,
    /// How many advisories went into the bundle.
    pub advisories: usize,
    /// The affected components, most severe first.
    pub findings: Vec<ReportFinding>,
    /// What could not be checked: failed sources, unknown products, tools not installed.
    pub problems: Vec<String>,
    /// Why the agent's verdict is missing, when it is.
    pub failure: Option<String>,
    /// The sweep's folder: bundle, agent log and this report.
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
/// or the sweep folder cannot be written. Failures after that (a feed, the agent, its findings)
/// are recorded in the returned report instead.
pub fn sweep_mac(
    data_dir: &DataDir,
    config: &Config,
    progress: &mut dyn FnMut(Progress<'_>),
) -> Result<Report, SweepError> {
    let agent = config.agent.ok_or(SweepError::NoAgent)?;
    let binary = agent.locate()?.ok_or(SweepError::AgentNotFound { agent })?;
    let _lock = Lock::acquire(&data_dir.sweeps_dir())?;
    let started = Timestamp::now();
    let dir = data_dir
        .sweeps_dir()
        .join(started.strftime("%Y%m%dT%H%M%SZ").to_string())
        .join("mac");

    progress(Progress::Inventory);
    let inventory = Inventory::collect_mac(&config.project_dirs);
    let mut problems: Vec<String> = inventory.problems.iter().map(error_chain).collect();
    if !inventory.not_installed.is_empty() {
        let tools = inventory.not_installed.join(", ");
        problems.push(format!("not installed, so not checked: {tools}"));
    }

    let feeds = Feeds::new(data_dir, nvd_access(&mut problems));
    let fetched = fetch(&feeds, &inventory, config, &mut problems, progress);
    let entries: Vec<_> = fetched
        .iter()
        .map(|(advisory, components)| bundle::Entry {
            advisory,
            components: components
                .iter()
                .map(|i| bundle::component_id(*i))
                .collect(),
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
    let bundle_dir = dir.join("bundle");
    let known = bundle::write(
        &bundle_dir,
        &prompt,
        &inventory.components,
        &entries,
        kev.as_ref(),
    )?;

    let verdict = judge(agent, &binary, &dir, &known, progress);
    let (findings, failure) = match verdict {
        Ok(findings) => (findings.findings, None),
        Err(failure) => (Vec::new(), Some(failure)),
    };
    let mut findings: Vec<ReportFinding> = findings
        .into_iter()
        .map(|finding| {
            let installed = component_by_id(&inventory.components, &finding.component)
                .expect("validation checked every component id")
                .clone();
            ReportFinding { finding, installed }
        })
        .collect();
    findings.sort_by_key(|f| f.finding.severity);

    let report = Report {
        started,
        finished: Timestamp::now(),
        target: "mac".to_owned(),
        agent,
        components: inventory.components.len(),
        advisories: entries.len(),
        findings,
        problems,
        failure,
        dir: dir.clone(),
    };
    write_report(&dir, &report)?;
    Ok(report)
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

/// Fetches every advisory for the inventory and the indexes of the components each one was
/// fetched for, merged by advisory id.
fn fetch(
    feeds: &Feeds,
    inventory: &Inventory,
    config: &Config,
    problems: &mut Vec<String>,
    progress: &mut dyn FnMut(Progress<'_>),
) -> Vec<(Advisory, BTreeSet<usize>)> {
    let mut packages = BTreeMap::new();
    let mut products = BTreeMap::new();
    for (i, component) in inventory.components.iter().enumerate() {
        match &component.lookup {
            Lookup::Package(p) => packages.entry(p.clone()).or_insert_with(Vec::new).push(i),
            Lookup::Product(p) => products
                .entry(p.to_string())
                .or_insert_with(Vec::new)
                .push((i, p.clone())),
        }
    }
    progress(Progress::Advisories {
        packages: packages.len(),
        products: products.len(),
    });

    let mut found: BTreeMap<String, (Advisory, BTreeSet<usize>)> = BTreeMap::new();
    let mut add = |advisory: Advisory, components: &[usize]| {
        let entry = found
            .entry(advisory.id.clone())
            .or_insert_with(|| (advisory, BTreeSet::new()));
        entry.1.extend(components);
    };

    let package_list: Vec<_> = packages.keys().cloned().collect();
    if !package_list.is_empty() {
        match feeds.osv(&package_list, config.history) {
            Ok(osv) => {
                for e in &osv.failures {
                    problems.push(format!("OSV record: {}", error_chain(e)));
                }
                for advisory in osv.advisories {
                    let components: Vec<usize> = affected_packages(&advisory)
                        .iter()
                        .filter_map(|p| packages.get(p))
                        .flatten()
                        .copied()
                        .collect();
                    add(advisory, &components);
                }
            }
            Err(e) => problems.push(format!("OSV: {}", error_chain(&e))),
        }
    }

    let total = products.len();
    let mut unknown = Vec::new();
    for (done, (name, components)) in products.iter().enumerate() {
        progress(Progress::Product {
            done: done + 1,
            total,
            product: name,
        });
        let product = &components[0].1;
        let indexes: Vec<usize> = components.iter().map(|(i, _)| *i).collect();
        match feeds.nvd(product, config.history) {
            Ok(advisories) if advisories.is_empty() => {
                // No CVEs can mean a clean product or a name NVD does not know; tell them apart.
                match feeds.nvd_product_known(product) {
                    Ok(true) => {}
                    Ok(false) => unknown.push(name.as_str()),
                    Err(e) => {
                        problems.push(format!("NVD product check {name}: {}", error_chain(&e)));
                    }
                }
            }
            Ok(advisories) => {
                for advisory in advisories {
                    add(advisory, &indexes);
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

/// The OSV packages an advisory's record names in `affected`.
fn affected_packages(advisory: &Advisory) -> Vec<crate::package::Package> {
    let record: serde_json::Value =
        serde_json::from_str(advisory.record.get()).unwrap_or(serde_json::Value::Null);
    record["affected"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|a| {
            let ecosystem = a["package"]["ecosystem"].as_str()?;
            let name = a["package"]["name"].as_str()?;
            format!("{ecosystem}:{name}").parse().ok()
        })
        .collect()
}

/// Runs the agent and validates its findings, once more with the problems if they are
/// rejected. Returns why there is no verdict on a second failure.
fn judge(
    agent: AgentKind,
    binary: &Path,
    dir: &Path,
    known: &Known,
    progress: &mut dyn FnMut(Progress<'_>),
) -> Result<findings::Findings, String> {
    let bundle = dir.join("bundle");
    let findings_path = bundle.join("findings.json");
    let mut prompt = PROMPT_LINE.to_owned();
    let mut last = String::new();
    for attempt in 1..=2 {
        progress(Progress::Agent { agent, attempt });
        // A stale file from the first attempt must not pass for the second one's answer.
        drop(fs::remove_file(&findings_path));
        let log = dir.join(format!("agent-{attempt}.log"));
        let outcome = agent
            .run(binary, &bundle, &prompt, &log)
            .map_err(|e| vec![error_chain(&e)])
            .and_then(|()| {
                fs::read_to_string(&findings_path)
                    .map_err(|e| vec![format!("the agent wrote no readable findings.json: {e}")])
            })
            .and_then(|text| findings::validate(&text, known));
        match outcome {
            Ok(findings) => return Ok(findings),
            Err(problems) => {
                last = problems.join("; ");
                prompt = format!(
                    "{PROMPT_LINE} Your previous findings.json was rejected; fix these and \
                     write it again:\n- {}",
                    problems.join("\n- ")
                );
            }
        }
    }
    Err(format!("{agent}'s findings were rejected twice: {last}"))
}

fn component_by_id<'a>(components: &'a [Component], id: &str) -> Option<&'a Component> {
    components
        .iter()
        .enumerate()
        .find(|(i, _)| bundle::component_id(*i) == id)
        .map(|(_, c)| c)
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
                .map_err(|source| SweepError::Io {
                    path: path.clone(),
                    source,
                })?;
            DEFAULT_PROMPT.to_owned()
        }
        Err(source) => return Err(SweepError::Io { path, source }),
    };
    Ok(template.replace("{{target}}", target))
}

fn write_report(dir: &Path, report: &Report) -> Result<(), SweepError> {
    let json = serde_json::to_string_pretty(report).map_err(|e| SweepError::Io {
        path: dir.join("report.json"),
        source: io::Error::other(e),
    })?;
    for (name, text) in [
        ("report.json", json),
        ("report.md", report_markdown(report)),
    ] {
        let path = dir.join(name);
        fs::write(&path, text).map_err(|source| SweepError::Io { path, source })?;
    }
    Ok(())
}

/// The report for a person: findings first, most severe first, then what was not checked.
pub fn report_markdown(report: &Report) -> String {
    let mut out = format!(
        "# Sweep of {} ({})\n\nAgent: {}. {} components, {} advisories checked.\n\n",
        report.target, report.started, report.agent, report.components, report.advisories
    );
    if let Some(failure) = &report.failure {
        out.push_str(&format!("**No verdict:** {failure}\n\n"));
    }
    if report.findings.is_empty() && report.failure.is_none() {
        out.push_str("No installed component is affected by a known advisory.\n\n");
    }
    for group in by_component(&report.findings) {
        let first = group[0];
        out.push_str(&format!(
            "## {} {} {}\n\nFound in {}. {} advisor{}.\n\n",
            first.finding.severity.to_string().to_uppercase(),
            component_name(&first.installed),
            first.installed.version,
            first.installed.found_in,
            group.len(),
            if group.len() == 1 { "y" } else { "ies" },
        ));
        for f in group {
            out.push_str(&finding_markdown(&f.finding));
        }
    }
    if !report.problems.is_empty() {
        out.push_str("## Not checked\n\n");
        for problem in &report.problems {
            out.push_str(&format!("- {problem}\n"));
        }
    }
    out
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
        "### {} {} ({:?}{exploited})\n\n{}\n\nEvidence: {}\n\nFix: {}\n",
        finding.severity,
        finding.advisories.join(", "),
        finding.confidence,
        finding.explanation,
        finding.evidence,
        finding.fix.summary,
    );
    if !finding.fix.commands.is_empty() {
        out.push_str("\n```sh\n");
        for command in &finding.fix.commands {
            out.push_str(command);
            out.push('\n');
        }
        out.push_str("```\n");
    }
    out.push('\n');
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

/// The running sweep's claim on the sweeps folder. Dropping it releases the claim.
#[derive(Debug)]
struct Lock {
    path: PathBuf,
}

impl Lock {
    /// Takes the lock, clearing one left by a sweep that is no longer running.
    fn acquire(sweeps: &Path) -> Result<Self, SweepError> {
        let path = sweeps.join(".lock");
        let io_err = |source| SweepError::Io {
            path: path.clone(),
            source,
        };
        fs::create_dir_all(sweeps).map_err(io_err)?;
        for _ in 0..2 {
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(mut file) => {
                    use std::io::Write as _;
                    write!(file, "{}", process::id()).map_err(io_err)?;
                    return Ok(Self { path });
                }
                // Any failure with no lock file there is a real error; with one there, it is a
                // running sweep or one that crashed.
                Err(e) if !path.exists() => return Err(io_err(e)),
                Err(_) => {
                    let pid = fs::read_to_string(&path).unwrap_or_default();
                    let pid = pid.trim().to_owned();
                    if running(&pid) {
                        return Err(SweepError::Busy { pid, lock: path });
                    }
                    // Left by a sweep that crashed; nothing holds it.
                    fs::remove_file(&path).map_err(io_err)?;
                }
            }
        }
        Err(SweepError::Busy {
            pid: String::new(),
            lock: path,
        })
    }
}

impl Drop for Lock {
    fn drop(&mut self) {
        // Best effort: a lock that cannot be removed is cleared by the next sweep, which finds
        // its pid not running.
        drop(fs::remove_file(&self.path));
    }
}

/// Returns whether `pid` names a running process, by `kill -0`.
fn running(pid: &str) -> bool {
    !pid.is_empty()
        && pid.bytes().all(|b| b.is_ascii_digit())
        && process::Command::new("/bin/kill")
            .args(["-0", pid])
            .stdout(process::Stdio::null())
            .stderr(process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
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
    /// Another sweep is running.
    #[error("another sweep is running (pid {pid}); if it is not, delete {}", lock.display())]
    Busy {
        /// The pid in the lock file.
        pid: String,
        /// The lock file.
        lock: PathBuf,
    },
    /// The bundle could not be written.
    #[error(transparent)]
    Bundle(#[from] BundleError),
    /// A sweep file could not be read or written.
    #[error("cannot write {}", path.display())]
    Io {
        /// The file.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: io::Error,
    },
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::feeds::Endpoints;
    use crate::feeds::test_server::Request;
    use crate::feeds::test_server::TestServer;

    fn component(lookup: &str, version: &str) -> Component {
        let lookup = if lookup.contains(':') && !lookup.starts_with("github:") {
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

    /// OSV knows GHSA-1 for lodash, NVD knows CVE-9 for curl and nothing for a made-up product
    /// that is also missing from the CPE dictionary.
    fn feeds_server() -> TestServer {
        TestServer::start(|request: &Request| match request.path() {
            "/v1/querybatch" => {
                let vulns = json!([{"id": "GHSA-1", "modified": "2026-01-01T00:00:00Z"}]);
                (200, json!({"results": [{"vulns": vulns}]}).to_string())
            }
            "/v1/vulns/GHSA-1" => {
                let record = json!({
                    "id": "GHSA-1",
                    "modified": "2026-01-01T00:00:00Z",
                    "affected": [{"package": {"ecosystem": "npm", "name": "lodash"}}]
                });
                (200, record.to_string())
            }
            "/rest/json/cves/2.0" => {
                let cves =
                    if request.query("virtualMatchString").as_deref() == Some("cpe:2.3:*:*:curl") {
                        json!([{"cve": {"id": "CVE-9", "published": "2026-01-01T00:00:00.000"}}])
                    } else {
                        json!([])
                    };
                let total = cves.as_array().unwrap().len();
                let page = json!({
                    "startIndex": 0,
                    "totalResults": total,
                    "timestamp": "2026-11-01T00:00:00.000",
                    "vulnerabilities": cves
                });
                (200, page.to_string())
            }
            "/rest/json/cpes/2.0" => (200, json!({"totalResults": 0}).to_string()),
            other => (404, format!("unexpected {other}")),
        })
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
            ],
            ..Inventory::default()
        };
        let config = Config::default_for_tests();
        let mut problems = Vec::new();
        let mut seen = Vec::new();
        let fetched = fetch(&feeds, &inventory, &config, &mut problems, &mut |p| {
            seen.push(format!("{p:?}"));
        });

        let linked: Vec<(String, Vec<usize>)> = fetched
            .iter()
            .map(|(a, c)| (a.id.clone(), c.iter().copied().collect()))
            .collect();
        assert_eq!(
            linked,
            [
                ("CVE-9".to_owned(), vec![1]),
                ("GHSA-1".to_owned(), vec![0, 2])
            ]
        );
        assert_eq!(
            problems,
            ["NVD knows no product named made-up-product, so these were not checked"]
        );
        assert!(seen[0].contains("packages: 1, products: 2"), "{seen:?}");
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

    #[test]
    fn markdown_lists_findings_then_gaps() {
        let report = Report {
            started: "2026-11-05T10:00:00Z".parse().unwrap(),
            finished: "2026-11-05T10:05:00Z".parse().unwrap(),
            target: "mac".into(),
            agent: AgentKind::Claude,
            components: 2,
            advisories: 1,
            findings: vec![
                report_finding("GHSA-1", "high", true, "npm:lodash"),
                report_finding("GHSA-2", "medium", false, "npm:lodash"),
                report_finding("CVE-3", "low", false, "curl"),
            ],
            problems: vec!["OSV: offline".into()],
            failure: None,
            dir: PathBuf::from("/tmp/s"),
        };
        let text = report_markdown(&report);
        assert!(
            text.contains("## HIGH lodash (npm) 1.0\n\nFound in macOS. 2 advisories."),
            "{text}"
        );
        assert!(
            text.contains("### high GHSA-1 (Confirmed, known exploited)"),
            "{text}"
        );
        assert!(text.contains("### medium GHSA-2 (Confirmed)"), "{text}");
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
        assert!(
            lodash < text.find("## LOW curl").unwrap(),
            "worst component first"
        );
        assert!(text.contains("## Not checked\n\n- OSV: offline"), "{text}");

        let empty = Report {
            findings: vec![],
            problems: vec![],
            ..report
        };
        assert!(report_markdown(&empty).contains("No installed component is affected"));
    }

    #[test]
    fn lock_is_exclusive_and_stale_locks_are_cleared() {
        let tmp = tempfile::tempdir().unwrap();
        let lock = Lock::acquire(tmp.path()).unwrap();
        let err = Lock::acquire(tmp.path()).unwrap_err();
        assert!(matches!(err, SweepError::Busy { .. }), "{err:?}");
        drop(lock);
        assert!(!tmp.path().join(".lock").exists());

        // A pid that is not running, as a crashed sweep would leave.
        fs::write(tmp.path().join(".lock"), "999999").unwrap();
        let lock = Lock::acquire(tmp.path()).unwrap();
        let pid = fs::read_to_string(tmp.path().join(".lock")).unwrap();
        assert_eq!(pid, process::id().to_string());
        drop(lock);
    }

    #[test]
    fn components_are_found_by_bundle_id() {
        let components = [component("npm:a", "1"), component("npm:b", "2")];
        assert_eq!(component_by_id(&components, "c2").unwrap().version, "2");
        assert_eq!(component_by_id(&components, "c1").unwrap().version, "1");
        assert!(component_by_id(&components, "c3").is_none());
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
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o200)).unwrap();
        }
        let result = prompt(&data, "x");
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        }
        assert!(matches!(result, Err(SweepError::Io { .. })), "{result:?}");
        assert_eq!(fs::read_to_string(&path).unwrap(), "Mine: {{target}}");
    }

    #[test]
    fn error_chain_joins_sources() {
        let err = SweepError::Io {
            path: PathBuf::from("/x"),
            source: io::Error::other("disk on fire"),
        };
        assert_eq!(error_chain(&err), "cannot write /x: disk on fire");
    }

    #[test]
    fn unwritable_sweeps_folder_is_an_io_error() {
        use std::os::unix::fs::PermissionsExt as _;

        let tmp = tempfile::tempdir().unwrap();
        fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o555)).unwrap();
        let result = Lock::acquire(tmp.path());
        fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o755)).unwrap();
        // The cause is the permission, not a lock file that was never there.
        let denied = io::ErrorKind::PermissionDenied;
        assert!(
            matches!(&result, Err(SweepError::Io { source, .. }) if source.kind() == denied),
            "{result:?}"
        );
    }

    #[test]
    fn running_checks_the_pid() {
        assert!(running(&process::id().to_string()));
        assert!(!running("999999"));
        assert!(!running(""));
        assert!(!running("12; rm -rf /"));
    }
}
