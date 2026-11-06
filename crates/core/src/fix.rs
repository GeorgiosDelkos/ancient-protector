//! Fixing one finding or issue after the user confirms it (spec, "Fix flow").
//!
//! The fix the sweep's agent wrote is the plan: [`plan_fix`] reads it from the newest report
//! that has the key, the user confirms it, and [`run_fix`] has the chosen agent carry it out
//! with full access in its own folder, `fixes/<start time>-<key>/`. Every run is appended to
//! `state/fixes.jsonl`, whatever its outcome. A fix holds the sweeps lock, so no sweep or other
//! fix runs while it changes the target.
//!
//! The agent works on the target the report names, and only one the config still lists: this
//! Mac, a repository it clones to open a pull request, or a server it reaches with the sweep's
//! own ssh options.

use std::fmt;
use std::fs;
use std::io;
use std::io::Write as _;
use std::path::Path;
use std::path::PathBuf;

use jiff::Timestamp;
use serde::Deserialize;
use serde::Serialize;

use crate::agent::AgentError;
use crate::agent::AgentKind;
use crate::agent::PROMPT_LINE;
use crate::config::Config;
use crate::findings::Fix;
use crate::findings::is_forging;
use crate::lifecycle;
use crate::lifecycle::FindingKey;
use crate::lifecycle::StateError;
use crate::paths::DataDir;
use crate::server;
use crate::sweep;
use crate::sweep::Lock;
use crate::sweep::Prompt;
use crate::sweep::SweepError;

/// The JSON Schema of `result.json`, written into each fix folder for the agent.
const RESULT_SCHEMA: &str = include_str!("fix-result.schema.json");

/// A fix to confirm: what it is about and what it will do.
#[derive(Debug)]
pub struct FixPlan {
    key: FindingKey,
    target: String,
    fix: Fix,
    /// The report entry, as JSON, for the agent.
    entry: serde_json::Value,
}

impl FixPlan {
    /// Where it applies: `mac`, `github:owner/name` or `server:name`.
    pub fn target(&self) -> &str {
        &self.target
    }

    /// The fix the sweep's agent wrote, which the user confirms.
    pub fn fix(&self) -> &Fix {
        &self.fix
    }
}

/// Reads the fix for `key` from the newest report that has it.
///
/// # Errors
///
/// Fails when no report has `key`, or a report cannot be read.
pub fn plan_fix(data_dir: &DataDir, key: FindingKey) -> Result<FixPlan, FixError> {
    let (report_path, _) = lifecycle::newest_report(&data_dir.sweeps_dir(), key)?
        .ok_or(StateError::UnknownKey { key })?;
    let read_err = |source| FixError::Read {
        path: report_path.clone(),
        source,
    };
    let text = fs::read_to_string(&report_path).map_err(read_err)?;
    let report: Saved = serde_json::from_str(&text)
        .map_err(|e| read_err(io::Error::new(io::ErrorKind::InvalidData, e)))?;
    let entry = report
        .findings
        .into_iter()
        .chain(report.issues)
        .find(|e| e["key"] == key.to_string())
        .expect("newest_report found the key in this report");
    let fix = Fix::deserialize(&entry["fix"])
        .map_err(|e| read_err(io::Error::new(io::ErrorKind::InvalidData, e)))?;
    Ok(FixPlan {
        key,
        target: report.target,
        fix,
        entry,
    })
}

/// The parts of a saved `report.json` a fix needs.
#[derive(Debug, Deserialize)]
struct Saved {
    target: String,
    findings: Vec<serde_json::Value>,
    issues: Vec<serde_json::Value>,
}

/// One fix run, as appended to `state/fixes.jsonl`.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FixRecord {
    /// The finding or issue.
    pub key: FindingKey,
    /// Where the fix ran.
    pub target: String,
    /// The agent that ran it.
    pub agent: AgentKind,
    /// When it started.
    pub started: Timestamp,
    /// When it finished.
    pub finished: Timestamp,
    /// The agent's exit code; `None` when a signal ended it.
    pub exit_code: Option<i32>,
    /// What the agent reported, or `unknown` when it wrote no valid `result.json`.
    pub outcome: Outcome,
    /// The agent's one-line summary, or why its result was not read.
    pub summary: String,
    /// The pull request the agent opened, for a repository.
    pub pull_request: Option<String>,
    /// The fix's folder: prompt, `fix.json`, agent log and result.
    pub dir: PathBuf,
}

/// How a fix ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    /// Done and checked.
    Fixed,
    /// Some of it was done.
    Partial,
    /// Nothing changed.
    Failed,
    /// The agent wrote no valid `result.json`.
    Unknown,
}

impl fmt::Display for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Fixed => "fixed",
            Self::Partial => "partial",
            Self::Failed => "failed",
            Self::Unknown => "unknown",
        })
    }
}

/// What the agent writes in `result.json`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentResult {
    outcome: Outcome,
    summary: String,
    #[serde(default)]
    pull_request: Option<String>,
}

/// Runs the confirmed `plan` with the agent named in `config`, with full access, and records
/// the run in `state/fixes.jsonl`. Call it only after the user confirmed the plan.
///
/// Blocks until the agent finishes; there is no time limit.
///
/// # Errors
///
/// Fails before the agent runs when no agent is configured or found, a sweep or fix is
/// running, the target is no longer configured, or the fix folder cannot be written; and after
/// it ran when the record cannot be appended.
pub fn run_fix(data_dir: &DataDir, config: &Config, plan: &FixPlan) -> Result<FixRecord, FixError> {
    let agent = config.agent.ok_or(SweepError::NoAgent)?;
    let located = agent.locate()?.ok_or(SweepError::AgentNotFound { agent })?;
    let access = access(config, &plan.target, plan.key)?;
    let _lock = Lock::acquire(&data_dir.sweeps_dir())?;

    let started = Timestamp::now();
    let dir = data_dir.fixes_dir().join(format!(
        "{}-{}",
        started.strftime("%Y%m%dT%H%M%SZ"),
        plan.key
    ));
    let prompt = sweep::prompt(data_dir, Prompt::Fix, &plan.target)?.replace("{{access}}", &access);
    let entry = serde_json::to_string_pretty(&plan.entry).expect("a JSON value serializes");
    for (name, text) in [
        ("PROMPT.md", prompt.as_str()),
        ("fix.json", entry.as_str()),
        ("result.schema.json", RESULT_SCHEMA),
    ] {
        let path = dir.join(name);
        fs::create_dir_all(&dir)
            .and_then(|()| fs::write(&path, text))
            .map_err(|source| FixError::Write { path, source })?;
    }

    let status = agent.run_fix(&located, &dir, PROMPT_LINE, &dir.join("agent.log"))?;
    let (outcome, summary, pull_request) = match read_result(&dir.join("result.json")) {
        Ok(result) => (result.outcome, result.summary, result.pull_request),
        Err(why) => (Outcome::Unknown, why, None),
    };
    let record = FixRecord {
        key: plan.key,
        target: plan.target.clone(),
        agent,
        started,
        finished: Timestamp::now(),
        exit_code: status.code(),
        outcome,
        summary,
        pull_request,
        dir,
    };
    append(data_dir, &record)?;
    Ok(record)
}

/// The "Where to work" section of the prompt for `target`, which must still be configured.
fn access(config: &Config, target: &str, key: FindingKey) -> Result<String, FixError> {
    let unknown = || FixError::UnknownTarget {
        target: target.to_owned(),
    };
    if target == "mac" {
        return Ok("This Mac. Run the commands here, as the user.".to_owned());
    }
    if let Some(slug) = target.strip_prefix("github:") {
        let repo = config
            .repos
            .iter()
            .find(|r| r.to_string() == slug)
            .ok_or_else(unknown)?;
        return Ok(format!(
            "The GitHub repository {repo}, with the user's `gh` login.\n\n\
             - A change to files: clone it into this folder (`gh repo clone {repo} repo`), \
             create the branch `ancient-protector/fix-{key}` from the default branch, make the \
             change, commit it with a message that names the advisory or issue, push the \
             branch, and open a pull request with `gh pr create`. Never push to the default \
             branch.\n\
             - A repository setting: run the confirmed `gh api` commands."
        ));
    }
    if let Some(name) = target.strip_prefix("server:") {
        let server = config
            .servers
            .iter()
            .find(|s| s.name.to_string() == name)
            .ok_or_else(unknown)?;
        let ssh = server::ssh_command_line(&server.conn);
        return Ok(format!(
            "The server {name}. You are on this Mac; run every command on the server as\n\n\
             ```sh\n{ssh} '<command>'\n```\n\n\
             with exactly these ssh options, and connect to no other host. Use `sudo` where \
             the confirmed command does; if sudo asks for a password, stop and write \
             `failed`."
        ));
    }
    Err(unknown())
}

/// Reads and checks `result.json`, or says why it cannot be used.
fn read_result(path: &Path) -> Result<AgentResult, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("no result.json: {e}"))?;
    let result: AgentResult =
        serde_json::from_str(&text).map_err(|e| format!("result.json: {e}"))?;
    if result.outcome == Outcome::Unknown {
        return Err("result.json: outcome must be fixed, partial or failed".to_owned());
    }
    let summary = result.summary.trim();
    if summary.is_empty() || summary.chars().any(is_forging) {
        return Err("result.json: summary must be one line of text".to_owned());
    }
    // Shown to the user as a link, so only a plain https URL on GitHub.
    let plain_url = |u: &String| {
        u.starts_with("https://github.com/") && u.bytes().all(|b| (b'!'..=b'~').contains(&b))
    };
    if result.pull_request.as_ref().is_some_and(|u| !plain_url(u)) {
        return Err("result.json: pull_request must be an https://github.com/ URL".to_owned());
    }
    Ok(AgentResult {
        summary: summary.to_owned(),
        ..result
    })
}

/// Appends `record` to `state/fixes.jsonl` as one line, under the state lock.
fn append(data_dir: &DataDir, record: &FixRecord) -> Result<(), FixError> {
    let line = serde_json::to_string(record).expect("a fix record serializes");
    lifecycle::locked(data_dir, |state| {
        let path = state.join("fixes.jsonl");
        fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .and_then(|mut file| {
                file.write_all(format!("{line}\n").as_bytes())?;
                file.sync_data()
            })
            .map_err(|source| StateError::Write { path, source })
    })?;
    Ok(())
}

/// Error from planning or running a fix.
#[derive(Debug, thiserror::Error)]
pub enum FixError {
    /// The report's target is no longer in config.toml.
    #[error("{target} is not in config.toml any more; add it back to fix it")]
    UnknownTarget {
        /// The target.
        target: String,
    },
    /// The agent, the lock or the prompt failed, as they would for a sweep.
    #[error(transparent)]
    Sweep(#[from] SweepError),
    /// The agent could not be found or started.
    #[error(transparent)]
    Agent(#[from] AgentError),
    /// The state could not be read or written.
    #[error(transparent)]
    State(#[from] StateError),
    /// A report could not be read.
    #[error("cannot read {}", path.display())]
    Read {
        /// The file.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: io::Error,
    },
    /// A fix file could not be written.
    #[error("cannot write {}", path.display())]
    Write {
        /// The file.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: io::Error,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(toml: &str) -> Config {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(&path, toml).unwrap();
        Config::load(&path, Path::new("/home")).unwrap()
    }

    #[test]
    fn each_target_gets_its_own_instructions_and_must_be_configured() {
        let config = config(
            "[github]\nrepos = [\"o/r\"]\n\n[[servers]]\nname = \"web\"\n\
             host = \"10.0.0.5\"\nuser = \"ops\"\nidentity_file = \"/k/id_ed\"\n",
        );
        let key = FindingKey::new(&["x"]);
        assert!(
            access(&config, "mac", key)
                .unwrap()
                .starts_with("This Mac.")
        );

        let repo = access(&config, "github:o/r", key).unwrap();
        assert!(repo.contains("`gh repo clone o/r repo`"), "{repo}");
        assert!(
            repo.contains(&format!("`ancient-protector/fix-{key}`")),
            "{repo}"
        );
        assert!(repo.contains("Never push to the default branch"), "{repo}");

        let server = access(&config, "server:web", key).unwrap();
        assert!(
            server.contains("ssh -T -o BatchMode=yes -o StrictHostKeyChecking=yes"),
            "{server}"
        );
        assert!(
            server.contains("-l ops -i /k/id_ed -o IdentitiesOnly=yes -- 10.0.0.5 '<command>'"),
            "{server}"
        );

        for gone in ["github:o/gone", "server:db", "laptop", "github:", "server:"] {
            assert!(
                matches!(
                    access(&config, gone, key),
                    Err(FixError::UnknownTarget { .. })
                ),
                "{gone}"
            );
        }
    }

    #[test]
    fn the_result_must_be_a_known_outcome_with_a_plain_summary() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("result.json");
        let read = |json: &str| {
            fs::write(&path, json).unwrap();
            read_result(&path)
        };
        let ok = read(
            r#"{"outcome": "partial", "summary": " half done ",
            "pull_request": "https://github.com/o/r/pull/1"}"#,
        )
        .unwrap();
        assert_eq!(ok.outcome, Outcome::Partial);
        assert_eq!(ok.summary, "half done");
        assert!(
            read(r#"{"outcome": "fixed", "summary": "x"}"#)
                .unwrap()
                .pull_request
                .is_none()
        );

        let bad = [
            (
                r#"{"outcome": "unknown", "summary": "x"}"#,
                "outcome must be",
            ),
            (r#"{"outcome": "fixed", "summary": " "}"#, "one line"),
            (r#"{"outcome": "fixed", "summary": "a\nb"}"#, "one line"),
            (
                r#"{"outcome": "fixed", "summary": "x", "extra": 1}"#,
                "unknown field",
            ),
            (
                r#"{"outcome": "fixed", "summary": "x", "pull_request": "http://evil/1"}"#,
                "https://github.com/ URL",
            ),
            (
                r#"{"outcome": "fixed", "summary": "x", "pull_request": "https://github.com/a b"}"#,
                "https://github.com/ URL",
            ),
        ];
        for (json, why) in bad {
            let err = read(json).unwrap_err();
            assert!(err.contains(why), "{json}: {err}");
        }
        fs::remove_file(&path).unwrap();
        assert!(
            read_result(&path)
                .unwrap_err()
                .starts_with("no result.json")
        );
    }
}
