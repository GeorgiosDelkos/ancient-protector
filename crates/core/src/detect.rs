//! What this Mac already has, for the settings window to start from: the agents and tools on
//! the login shell's `PATH`, the `gh` login and its repositories, the hosts in
//! `~/.ssh/config`, the usual project folders, and whether an NVD key is in the Keychain.
//!
//! Nothing here changes anything; every part that cannot be read comes back empty, since a
//! settings window that fails to open over one missing tool helps no one.

use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::Path;
use std::path::PathBuf;

use serde::Deserialize;
use serde::Serialize;

use crate::agent::AgentKind;
use crate::inventory::command;

/// The agents a sweep can run, in the order the settings window lists them.
const AGENTS: [AgentKind; 5] = [
    AgentKind::Claude,
    AgentKind::Grok,
    AgentKind::Gemini,
    AgentKind::Opencode,
    AgentKind::Codex,
];

/// The tools a Mac sweep reads, plus `gh` and `ssh`, which repository and server sweeps use.
const TOOLS: [&str; 10] = [
    "brew", "npm", "node", "uv", "pipx", "cargo", "rustup", "python3", "gh", "ssh",
];

/// Folders people keep projects in, relative to the home folder. Arbitrary: the common names
/// on macOS; a folder that does not exist is not suggested.
const PROJECT_FOLDERS: [&str; 7] = [
    "code",
    "Code",
    "Projects",
    "Developer",
    "src",
    "Documents/Github",
    "Documents/GitHub",
];

/// How many of the user's repositories `gh repo list` returns. Arbitrary: enough to pick from
/// without a long wait.
const REPO_LIMIT: &str = "100";

const PATH_MARK: &str = "__ancient_protector_path__";
const BIN_MARK: &str = "__ancient_protector_bin__";
const END_MARK: &str = "__ancient_protector_end__";

/// What the settings window starts from.
#[derive(Debug, Serialize)]
pub struct Detected {
    /// Each agent, and where the login shell finds it.
    pub agents: Vec<Found>,
    /// Each tool, and where the login shell finds it.
    pub tools: Vec<Found>,
    /// The `gh` login, or `None` when gh is missing or not logged in.
    pub gh_login: Option<String>,
    /// The user's repositories, newest push first; empty without a gh login.
    pub repos: Vec<RepoInfo>,
    /// The concrete hosts in `~/.ssh/config`.
    pub ssh_hosts: Vec<SshHost>,
    /// Usual project folders that exist.
    pub folders: Vec<PathBuf>,
    /// Whether an NVD API key is in the Keychain.
    pub nvd_key: bool,
}

/// A program and where it was found.
#[derive(Debug, Serialize)]
pub struct Found {
    /// Its name (`claude`, `brew`).
    pub name: String,
    /// Its path, or `None` when the login shell does not find it.
    pub path: Option<PathBuf>,
}

/// One of the user's repositories.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RepoInfo {
    /// `owner/name`.
    pub name_with_owner: String,
    /// Whether it is private.
    pub is_private: bool,
    /// When it was last pushed, as GitHub says.
    pub pushed_at: Option<String>,
}

/// A host from `~/.ssh/config`.
#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct SshHost {
    /// The alias, as `ssh <alias>` takes it.
    pub alias: String,
    /// Its `HostName`, when the config sets one.
    pub host_name: Option<String>,
}

/// Asks the login shell for its `PATH`, and has every tool the core runs from now on found on
/// it, as in the user's terminal. For the menu-bar app, which macOS starts with a minimal
/// `PATH`; returns `false` when the shell gave no answer, and the process's `PATH` stays.
pub fn use_login_shell_path() -> bool {
    match login_shell() {
        Some(answer) => {
            command::use_search_path(answer.path);
            true
        }
        None => false,
    }
}

/// Detects what this Mac has. Takes a few seconds: it runs the login shell, `gh` twice and
/// the Keychain lookup.
pub fn detect(home: &Path) -> Detected {
    let answer = login_shell();
    let found = |name: &str| Found {
        name: name.to_owned(),
        path: answer.as_ref().and_then(|a| a.binary(name)),
    };
    let agents = AGENTS.iter().map(|a| found(a.binary())).collect();
    let tools: Vec<Found> = TOOLS.iter().map(|t| found(t)).collect();
    let gh = tools
        .iter()
        .find(|t| t.name == "gh")
        .and_then(|t| t.path.clone());
    let gh_login = gh.as_deref().and_then(gh_login);
    let repos = match (&gh, &gh_login) {
        (Some(gh), Some(_)) => gh_repos(gh),
        _ => Vec::new(),
    };
    let ssh_hosts = fs::read_to_string(home.join(".ssh/config"))
        .map(|text| ssh_hosts(&text))
        .unwrap_or_default();
    let folders = PROJECT_FOLDERS
        .iter()
        .map(|f| home.join(f))
        .filter(|p| p.is_dir())
        .collect();
    Detected {
        agents,
        tools,
        gh_login,
        repos,
        ssh_hosts,
        folders,
        nvd_key: crate::feeds::NvdAccess::has_keychain_key(),
    }
}

/// The login shell's answer: its `PATH`, and each program it found.
#[derive(Debug)]
struct Answer {
    path: OsString,
    binaries: Vec<(String, PathBuf)>,
}

impl Answer {
    fn binary(&self, name: &str) -> Option<PathBuf> {
        self.binaries
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, p)| p.clone())
    }
}

fn login_shell() -> Option<Answer> {
    let shell = env::var("SHELL").unwrap_or_else(|_| "/bin/zsh".to_owned());
    let names: Vec<&str> = AGENTS.iter().map(|a| a.binary()).chain(TOOLS).collect();
    // The names are this module's constants, so they need no quoting.
    let script = format!(
        "printf '%s\\n' {PATH_MARK} \"$PATH\"; for b in {}; do printf '{BIN_MARK}%s\\t%s\\n' \
         \"$b\" \"$(command -v \"$b\")\"; done; printf '%s\\n' {END_MARK}",
        names.join(" ")
    );
    let output = command::run_any_status(&shell, &["-lc", &script]).ok()??;
    parse_answer(&output.stdout)
}

/// Reads the marked lines of the login shell's answer. Lines before the `PATH` mark (startup
/// files that print) are ignored; a program found as anything but an absolute path (an alias,
/// a function) counts as not found.
fn parse_answer(stdout: &str) -> Option<Answer> {
    let mut lines = stdout.lines().skip_while(|l| l.trim() != PATH_MARK).skip(1);
    let path = OsString::from(lines.next()?);
    let mut binaries = Vec::new();
    for line in lines {
        if line.trim() == END_MARK {
            return Some(Answer { path, binaries });
        }
        let Some((name, found)) = line.strip_prefix(BIN_MARK).and_then(|l| l.split_once('\t'))
        else {
            continue;
        };
        if Path::new(found).is_absolute() {
            binaries.push((name.to_owned(), PathBuf::from(found)));
        }
    }
    None
}

fn gh_login(gh: &Path) -> Option<String> {
    let gh = gh.to_str()?;
    let login = command::run(gh, &["api", "user", "--jq", ".login"]).ok()??;
    let login = login.trim();
    let plain = !login.is_empty()
        && login
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-');
    plain.then(|| login.to_owned())
}

fn gh_repos(gh: &Path) -> Vec<RepoInfo> {
    let Some(gh) = gh.to_str() else {
        return Vec::new();
    };
    let fields = "nameWithOwner,isPrivate,pushedAt";
    let args = ["repo", "list", "--limit", REPO_LIMIT, "--json", fields];
    command::run(gh, &args)
        .ok()
        .flatten()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default()
}

/// The concrete hosts in an ssh config: each `Host` alias without a pattern character (`*`,
/// `?`, `!`), with the `HostName` of its block. `Match` blocks and `Include`d files are not
/// read; a host there can still be typed in.
fn ssh_hosts(config: &str) -> Vec<SshHost> {
    let mut hosts: Vec<SshHost> = Vec::new();
    let mut block: Vec<usize> = Vec::new();
    for line in config.lines() {
        let line = line.trim();
        let Some((keyword, rest)) = line.split_once(|c: char| c.is_whitespace() || c == '=') else {
            continue;
        };
        let rest = rest
            .trim_start_matches(|c: char| c.is_whitespace() || c == '=')
            .trim();
        match keyword.to_ascii_lowercase().as_str() {
            "host" => {
                block.clear();
                for alias in rest.split_whitespace() {
                    let concrete = !alias.contains(['*', '?', '!']);
                    if concrete && !hosts.iter().any(|h| h.alias == alias) {
                        block.push(hosts.len());
                        hosts.push(SshHost {
                            alias: alias.to_owned(),
                            host_name: None,
                        });
                    }
                }
            }
            "match" => block.clear(),
            "hostname" => {
                for &i in &block {
                    hosts[i].host_name.get_or_insert_with(|| rest.to_owned());
                }
            }
            _ => {}
        }
    }
    hosts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_login_shell_answer_is_read_between_its_marks() {
        let stdout = format!(
            "Welcome to zsh\n{PATH_MARK}\n/opt/homebrew/bin:/usr/bin\n\
             {BIN_MARK}claude\t/Users/me/.local/bin/claude\n\
             {BIN_MARK}codex\t\n\
             {BIN_MARK}ll\tll: aliased to ls -l\n\
             {END_MARK}\n"
        );
        let answer = parse_answer(&stdout).unwrap();
        assert_eq!(answer.path, OsString::from("/opt/homebrew/bin:/usr/bin"));
        assert_eq!(
            answer.binary("claude"),
            Some(PathBuf::from("/Users/me/.local/bin/claude"))
        );
        assert_eq!(answer.binary("codex"), None, "not found");
        assert_eq!(answer.binary("ll"), None, "an alias is not a program");
        assert!(
            parse_answer(&format!("{PATH_MARK}\n/usr/bin\n")).is_none(),
            "no end mark"
        );
        assert!(parse_answer("nothing marked\n").is_none());
    }

    #[test]
    fn ssh_hosts_are_the_concrete_aliases_with_their_host_names() {
        let config = "\
Include ~/.orbstack/ssh/config
Host *
  ServerAliveInterval 30
Host web web-alias
  HostName 10.0.0.5
  User ops
host db-1
  hostname=db.internal
Host *.corp !gate
  User me
Match host staging
  HostName ignored
Host web
  HostName shadowed
";
        assert_eq!(
            ssh_hosts(config),
            [
                SshHost {
                    alias: "web".to_owned(),
                    host_name: Some("10.0.0.5".to_owned())
                },
                SshHost {
                    alias: "web-alias".to_owned(),
                    host_name: Some("10.0.0.5".to_owned())
                },
                SshHost {
                    alias: "db-1".to_owned(),
                    host_name: Some("db.internal".to_owned())
                },
            ]
        );
    }
}
