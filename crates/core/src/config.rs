//! `config.toml`: which agent to run, when, how far back, and which targets to sweep.
//!
//! The file is parsed into private `Raw*` types that mirror the TOML, then resolved into
//! [`Config`]. Resolving checks the whole file and reports every problem at once, so one edit
//! fixes them all. [`Config::load`] returns only valid targets with unique names.

use std::collections::HashSet;
use std::fmt;
use std::fs;
use std::io;
use std::num::NonZeroU16;
use std::num::NonZeroU32;
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;

use jiff::civil::Date;
use serde::Deserialize;

use crate::agent::AgentKind;

/// The config written by [`DataDir::init`](crate::DataDir::init).
pub(crate) const DEFAULT_CONFIG: &str = include_str!("default-config.toml");

/// A validated `config.toml`.
#[derive(Debug, PartialEq, Eq)]
pub struct Config {
    /// The agent that runs sweeps and fixes. `None` until the user picks one.
    pub agent: Option<AgentKind>,
    /// When sweeps run without a click.
    pub schedule: Schedule,
    /// How far back the first feed download goes.
    pub history: History,
    /// Absolute folders searched for lockfiles on this Mac.
    pub project_dirs: Vec<PathBuf>,
    /// GitHub repositories to sweep, without duplicates.
    pub repos: Vec<RepoSlug>,
    /// Servers to sweep, with unique names.
    pub servers: Vec<Server>,
}

impl Config {
    /// Reads and validates the config at `path`, expanding `~/` against `home`.
    ///
    /// # Errors
    ///
    /// [`LoadConfigError::Missing`] when there is no file (create one with
    /// [`DataDir::init`](crate::DataDir::init)), [`LoadConfigError::Read`] and
    /// [`LoadConfigError::Parse`] when it cannot be read or is not valid TOML for this
    /// schema, and [`LoadConfigError::Invalid`] with every problem found.
    pub fn load(path: &Path, home: &Path) -> Result<Self, LoadConfigError> {
        let text = match fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Err(LoadConfigError::Missing {
                    path: path.to_owned(),
                });
            }
            Err(source) => {
                return Err(LoadConfigError::Read {
                    path: path.to_owned(),
                    source,
                });
            }
        };
        let raw: RawConfig = toml::from_str(&text).map_err(|source| LoadConfigError::Parse {
            path: path.to_owned(),
            source,
        })?;
        raw.resolve(home)
            .map_err(|problems| LoadConfigError::Invalid {
                path: path.to_owned(),
                problems,
            })
    }
}

/// When sweeps run on their own.
#[derive(Debug, PartialEq, Eq)]
pub enum Schedule {
    /// Only when the user asks.
    Manual,
    /// Every this many hours, plus when the user asks.
    EveryHours(NonZeroU32),
}

/// How far back the first download of each advisory feed goes. Later sweeps fetch only
/// records modified since the previous sweep.
#[derive(Debug, PartialEq, Eq)]
pub enum History {
    /// The full history of every feed.
    All,
    /// Advisories published or modified on or after this date.
    Since(Date),
}

/// A GitHub repository as `owner/name`.
#[derive(Debug, PartialEq, Eq)]
pub struct RepoSlug {
    owner: String,
    name: String,
}

impl FromStr for RepoSlug {
    type Err = ParseRepoSlugError;

    /// Parses `owner/name` using GitHub's rules: an owner of 1 to 39 ASCII letters, digits
    /// and inner single hyphens; a name of 1 to 100 ASCII letters, digits, `.`, `-` and
    /// `_`, other than `.` and `..`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (owner, name) = s.split_once('/').ok_or(ParseRepoSlugError::NoSlash)?;
        let owner_ok = (1..=39).contains(&owner.len())
            && owner
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !owner.starts_with('-')
            && !owner.ends_with('-')
            && !owner.contains("--");
        if !owner_ok {
            return Err(ParseRepoSlugError::Owner);
        }
        let name_ok = (1..=100).contains(&name.len())
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
            && name != "."
            && name != "..";
        if !name_ok {
            return Err(ParseRepoSlugError::Name);
        }
        Ok(Self {
            owner: owner.to_owned(),
            name: name.to_owned(),
        })
    }
}

impl fmt::Display for RepoSlug {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.owner, self.name)
    }
}

/// Why a string is not an `owner/name` repository.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ParseRepoSlugError {
    /// There is no `/` between owner and name.
    #[error("expected owner/name")]
    NoSlash,
    /// The owner breaks GitHub's account name rules.
    #[error("owner must be 1-39 letters, digits or single inner hyphens")]
    Owner,
    /// The name breaks GitHub's repository name rules.
    #[error("name must be 1-100 letters, digits, '.', '-' or '_'")]
    Name,
}

/// A server the agent inspects over SSH.
#[derive(Debug, PartialEq, Eq)]
pub struct Server {
    /// Unique name, used to identify the target in reports.
    pub name: String,
    /// How to reach it.
    pub conn: SshConn,
}

/// How to reach a server over SSH. Authentication always comes from the user's ssh-agent
/// or key files; the config never holds passwords.
#[derive(Debug, PartialEq, Eq)]
pub enum SshConn {
    /// A `Host` alias from `~/.ssh/config`.
    Alias(String),
    /// Connection fields; anything left out falls back to ssh's own defaults.
    Direct {
        /// Hostname or address.
        host: String,
        /// Login user.
        user: Option<String>,
        /// TCP port.
        port: Option<NonZeroU16>,
        /// Private key file, `~/` expanded.
        identity_file: Option<PathBuf>,
    },
}

/// Error from [`Config::load`].
#[derive(Debug, thiserror::Error)]
pub enum LoadConfigError {
    /// There is no config file yet.
    #[error("no config at {}", path.display())]
    Missing {
        /// Where the config was expected.
        path: PathBuf,
    },
    /// The file exists but could not be read.
    #[error("cannot read config {}", path.display())]
    Read {
        /// The config file.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: io::Error,
    },
    /// The file is not valid TOML, or has unknown or mistyped keys.
    #[error("cannot parse config {}", path.display())]
    Parse {
        /// The config file.
        path: PathBuf,
        /// The parser's error, with line and column.
        #[source]
        source: toml::de::Error,
    },
    /// The file parsed but some values are invalid.
    #[error("invalid config {}: {}", path.display(), join_problems(problems))]
    Invalid {
        /// The config file.
        path: PathBuf,
        /// Every problem found, in file order.
        problems: Vec<ConfigProblem>,
    },
}

fn join_problems(problems: &[ConfigProblem]) -> String {
    problems
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("; ")
}

/// One invalid value in `config.toml`. Each message names the key and how to fix it.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ConfigProblem {
    /// `history.since` is neither `"all"` nor a date.
    #[error("history.since = {value:?}: use \"all\" or a date like \"2025-01-31\"")]
    Since {
        /// The value found.
        value: String,
    },
    /// A project folder is relative after `~/` expansion.
    #[error("mac.project_dirs[{index}] = {value:?}: use an absolute path or one starting with ~/")]
    RelativeProjectDir {
        /// Position in the list.
        index: usize,
        /// The value found.
        value: String,
    },
    /// A repository is not `owner/name`.
    #[error("github.repos[{index}] = {value:?}: {reason}")]
    Repo {
        /// Position in the list.
        index: usize,
        /// The value found.
        value: String,
        /// What is wrong with it.
        reason: ParseRepoSlugError,
    },
    /// A repository is listed twice.
    #[error("github.repos[{index}] = \"{repo}\" is listed twice; remove one")]
    DuplicateRepo {
        /// Position of the second occurrence.
        index: usize,
        /// The repeated repository.
        repo: RepoSlug,
    },
    /// A server name is empty, `.` or `..`, or has characters other than letters, digits,
    /// `.`, `-` and `_`.
    #[error(
        "servers[{index}].name = {value:?}: use letters, digits, '.', '-' or '_' (not . or ..)"
    )]
    ServerName {
        /// Position in the list.
        index: usize,
        /// The value found.
        value: String,
    },
    /// Two servers share a name, ignoring case.
    #[error("servers[{index}].name = {name:?} is used twice; names must be unique ignoring case")]
    DuplicateServer {
        /// Position of the second occurrence.
        index: usize,
        /// The repeated name.
        name: String,
    },
    /// A server sets both `ssh` and connection fields, or neither.
    #[error(
        "servers[{index}]: set either ssh (an ~/.ssh/config alias) or host, not both or neither"
    )]
    ServerConn {
        /// Position in the list.
        index: usize,
    },
    /// `ssh`, `host` or `user` is empty or starts with `-`.
    #[error("servers[{index}].{key} = {value:?}: must be non-empty and not start with '-'")]
    SshValue {
        /// Position in the list.
        index: usize,
        /// The key holding the value.
        key: &'static str,
        /// The value found.
        value: String,
    },
    /// `identity_file` is relative after `~/` expansion.
    #[error(
        "servers[{index}].identity_file = {value:?}: use an absolute path or one starting with ~/"
    )]
    RelativeIdentityFile {
        /// Position in the list.
        index: usize,
        /// The value found.
        value: String,
    },
}

/// `config.toml` as written. Every table is optional so a fresh file can be short.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    agent: Option<AgentKind>,
    #[serde(default)]
    schedule: RawSchedule,
    #[serde(default)]
    history: RawHistory,
    #[serde(default)]
    mac: RawMac,
    #[serde(default)]
    github: RawGithub,
    #[serde(default)]
    servers: Vec<RawServer>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSchedule {
    every_hours: Option<NonZeroU32>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawHistory {
    since: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawMac {
    #[serde(default)]
    project_dirs: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawGithub {
    #[serde(default)]
    repos: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawServer {
    name: String,
    ssh: Option<String>,
    host: Option<String>,
    user: Option<String>,
    port: Option<NonZeroU16>,
    identity_file: Option<String>,
}

impl RawConfig {
    fn resolve(self, home: &Path) -> Result<Config, Vec<ConfigProblem>> {
        let mut problems = Vec::new();

        let schedule = self
            .schedule
            .every_hours
            .map_or(Schedule::Manual, Schedule::EveryHours);
        let history = resolve_history(self.history.since.as_deref(), &mut problems);
        let project_dirs = resolve_project_dirs(self.mac.project_dirs, home, &mut problems);
        let repos = resolve_repos(self.github.repos, &mut problems);
        let servers = resolve_servers(self.servers, home, &mut problems);

        if !problems.is_empty() {
            return Err(problems);
        }
        Ok(Config {
            agent: self.agent,
            schedule,
            history,
            project_dirs,
            repos,
            servers,
        })
    }
}

/// A missing `since` means the full history, matching the default config.
fn resolve_history(since: Option<&str>, problems: &mut Vec<ConfigProblem>) -> History {
    let Some(value) = since.filter(|v| *v != "all") else {
        return History::All;
    };
    if let Ok(date) = value.parse() {
        return History::Since(date);
    }
    problems.push(ConfigProblem::Since {
        value: value.to_owned(),
    });
    History::All
}

fn resolve_project_dirs(
    raw: Vec<String>,
    home: &Path,
    problems: &mut Vec<ConfigProblem>,
) -> Vec<PathBuf> {
    let mut dirs = Vec::with_capacity(raw.len());
    for (index, value) in raw.into_iter().enumerate() {
        let path = expand_home(&value, home);
        if path.is_absolute() {
            dirs.push(path);
        } else {
            problems.push(ConfigProblem::RelativeProjectDir { index, value });
        }
    }
    dirs
}

/// GitHub owner and repository names ignore case, so `Octo/App` and `octo/app` are duplicates.
fn resolve_repos(raw: Vec<String>, problems: &mut Vec<ConfigProblem>) -> Vec<RepoSlug> {
    let mut seen = HashSet::new();
    let mut repos = Vec::with_capacity(raw.len());
    for (index, value) in raw.into_iter().enumerate() {
        match value.parse::<RepoSlug>() {
            Ok(repo) => {
                if seen.insert(repo.to_string().to_ascii_lowercase()) {
                    repos.push(repo);
                } else {
                    problems.push(ConfigProblem::DuplicateRepo { index, repo });
                }
            }
            Err(reason) => problems.push(ConfigProblem::Repo {
                index,
                value,
                reason,
            }),
        }
    }
    repos
}

/// Server names become folder names under each sweep, and the default macOS file system
/// ignores case, so names are unique ignoring case and may not be `.` or `..`.
fn resolve_servers(
    raw: Vec<RawServer>,
    home: &Path,
    problems: &mut Vec<ConfigProblem>,
) -> Vec<Server> {
    let mut seen = HashSet::new();
    let mut servers = Vec::with_capacity(raw.len());
    for (index, server) in raw.into_iter().enumerate() {
        let name_ok = !matches!(server.name.as_str(), "" | "." | "..")
            && server
                .name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'));
        if !name_ok {
            problems.push(ConfigProblem::ServerName {
                index,
                value: server.name.clone(),
            });
        } else if !seen.insert(server.name.to_ascii_lowercase()) {
            problems.push(ConfigProblem::DuplicateServer {
                index,
                name: server.name.clone(),
            });
        }

        match resolve_conn(index, &server, home) {
            Ok(conn) => servers.push(Server {
                name: server.name,
                conn,
            }),
            Err(problem) => problems.push(problem),
        }
    }
    servers
}

/// Accepts exactly one of `ssh` and the connection fields.
fn resolve_conn(index: usize, server: &RawServer, home: &Path) -> Result<SshConn, ConfigProblem> {
    let has_fields = server.host.is_some()
        || server.user.is_some()
        || server.port.is_some()
        || server.identity_file.is_some();
    let conn = match (&server.ssh, &server.host) {
        (Some(alias), None) if !has_fields => {
            check_ssh_word(index, "ssh", alias)?;
            SshConn::Alias(alias.clone())
        }
        (None, Some(host)) => {
            check_ssh_word(index, "host", host)?;
            if let Some(user) = &server.user {
                check_ssh_word(index, "user", user)?;
            }
            let identity_file = match server.identity_file.as_deref() {
                None => None,
                Some(value) => {
                    let path = expand_home(value, home);
                    if !path.is_absolute() {
                        return Err(ConfigProblem::RelativeIdentityFile {
                            index,
                            value: value.to_owned(),
                        });
                    }
                    Some(path)
                }
            };
            SshConn::Direct {
                host: host.clone(),
                user: server.user.clone(),
                port: server.port,
                identity_file,
            }
        }
        _ => return Err(ConfigProblem::ServerConn { index }),
    };
    Ok(conn)
}

/// These values become ssh arguments: an empty one is meaningless and one starting with `-`
/// would be read as an ssh option.
fn check_ssh_word(index: usize, key: &'static str, value: &str) -> Result<(), ConfigProblem> {
    if value.is_empty() || value.starts_with('-') {
        return Err(ConfigProblem::SshValue {
            index,
            key,
            value: value.to_owned(),
        });
    }
    Ok(())
}

/// Expands a leading `~/` (or a lone `~`) to `home`. Other paths are returned unchanged.
fn expand_home(value: &str, home: &Path) -> PathBuf {
    if value == "~" {
        home.to_owned()
    } else if let Some(rest) = value.strip_prefix("~/") {
        home.join(rest)
    } else {
        PathBuf::from(value)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    const HOME: &str = "/Users/me";

    fn resolve(text: &str) -> Result<Config, Vec<ConfigProblem>> {
        let raw: RawConfig = toml::from_str(text).unwrap();
        raw.resolve(Path::new(HOME))
    }

    #[test]
    fn default_config_is_valid_and_empty() {
        let config = resolve(DEFAULT_CONFIG).unwrap();
        assert_eq!(
            config,
            Config {
                agent: None,
                schedule: Schedule::Manual,
                history: History::All,
                project_dirs: vec![],
                repos: vec![],
                servers: vec![],
            }
        );
    }

    #[test]
    fn full_config_resolves() {
        let config = resolve(
            r#"
            agent = "claude"
            schedule.every_hours = 24
            history.since = "2025-01-31"
            mac.project_dirs = ["~/Documents/Github", "/opt/src", "~"]
            github.repos = ["octo-org/my.repo_1"]

            [[servers]]
            name = "prod"
            ssh = "prod-alias"

            [[servers]]
            name = "db-1"
            host = "10.0.0.5"
            user = "admin"
            port = 2222
            identity_file = "~/.ssh/id_ed25519"
            "#,
        )
        .unwrap();

        assert_eq!(config.agent, Some(AgentKind::Claude));
        assert_eq!(
            config.schedule,
            Schedule::EveryHours(NonZeroU32::new(24).unwrap())
        );
        assert_eq!(
            config.history,
            History::Since(jiff::civil::date(2025, 1, 31))
        );
        assert_eq!(
            config.project_dirs,
            [
                PathBuf::from("/Users/me/Documents/Github"),
                PathBuf::from("/opt/src"),
                PathBuf::from("/Users/me"),
            ]
        );
        assert_eq!(config.repos[0].to_string(), "octo-org/my.repo_1");
        assert_eq!(
            config.servers,
            [
                Server {
                    name: "prod".into(),
                    conn: SshConn::Alias("prod-alias".into()),
                },
                Server {
                    name: "db-1".into(),
                    conn: SshConn::Direct {
                        host: "10.0.0.5".into(),
                        user: Some("admin".into()),
                        port: NonZeroU16::new(2222),
                        identity_file: Some("/Users/me/.ssh/id_ed25519".into()),
                    },
                },
            ]
        );
    }

    #[test]
    fn all_problems_are_reported_together() {
        let problems = resolve(
            r#"
            history.since = "last year"
            mac.project_dirs = ["/ok", "relative/dir"]
            github.repos = ["a/b", "no-slash", "-bad/x", "a/..", "A/b"]

            [[servers]]
            name = "x"
            ssh = "alias"
            host = "also-host"

            [[servers]]
            name = "X"

            [[servers]]
            name = "bad name"
            ssh = "alias"
            port = 22

            [[servers]]
            name = ".."
            ssh = "-oProxyCommand=x"

            [[servers]]
            name = "ok"
            host = "h"
            user = ""

            [[servers]]
            name = "key"
            host = "h"
            identity_file = "keys/id"
            "#,
        )
        .unwrap_err();

        assert_eq!(
            problems,
            [
                ConfigProblem::Since {
                    value: "last year".into()
                },
                ConfigProblem::RelativeProjectDir {
                    index: 1,
                    value: "relative/dir".into()
                },
                ConfigProblem::Repo {
                    index: 1,
                    value: "no-slash".into(),
                    reason: ParseRepoSlugError::NoSlash
                },
                ConfigProblem::Repo {
                    index: 2,
                    value: "-bad/x".into(),
                    reason: ParseRepoSlugError::Owner
                },
                ConfigProblem::Repo {
                    index: 3,
                    value: "a/..".into(),
                    reason: ParseRepoSlugError::Name
                },
                ConfigProblem::DuplicateRepo {
                    index: 4,
                    repo: "A/b".parse().unwrap()
                },
                ConfigProblem::ServerConn { index: 0 },
                ConfigProblem::DuplicateServer {
                    index: 1,
                    name: "X".into()
                },
                ConfigProblem::ServerConn { index: 1 },
                ConfigProblem::ServerName {
                    index: 2,
                    value: "bad name".into()
                },
                ConfigProblem::ServerConn { index: 2 },
                ConfigProblem::ServerName {
                    index: 3,
                    value: "..".into()
                },
                ConfigProblem::SshValue {
                    index: 3,
                    key: "ssh",
                    value: "-oProxyCommand=x".into()
                },
                ConfigProblem::SshValue {
                    index: 4,
                    key: "user",
                    value: String::new()
                },
                ConfigProblem::RelativeIdentityFile {
                    index: 5,
                    value: "keys/id".into()
                },
            ]
        );
    }

    #[test]
    fn alias_with_any_connection_field_is_rejected() {
        for field in [
            "host = \"h\"",
            "user = \"u\"",
            "port = 22",
            "identity_file = \"k\"",
        ] {
            let text = format!("[[servers]]\nname = \"s\"\nssh = \"a\"\n{field}\n");
            assert_eq!(
                resolve(&text).unwrap_err(),
                [ConfigProblem::ServerConn { index: 0 }],
                "{field}"
            );
        }
    }

    #[test]
    fn port_zero_is_rejected() {
        let text = "[[servers]]\nname = \"s\"\nhost = \"h\"\nport = 0\n";
        assert!(toml::from_str::<RawConfig>(text).is_err());
    }

    #[test]
    fn unknown_keys_are_rejected() {
        let err = toml::from_str::<RawConfig>("[mac]\nproject_dir = []\n").unwrap_err();
        assert!(err.to_string().contains("project_dir"), "{err}");
    }

    #[test]
    fn load_distinguishes_missing_unparsable_and_invalid() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("config.toml");
        let home = Path::new(HOME);

        let err = Config::load(&path, home).unwrap_err();
        assert!(matches!(err, LoadConfigError::Missing { .. }), "{err:?}");

        fs::write(&path, "agent = ").unwrap();
        let err = Config::load(&path, home).unwrap_err();
        assert!(matches!(err, LoadConfigError::Parse { .. }), "{err:?}");

        fs::write(&path, "github.repos = [\"x\"]").unwrap();
        let err = Config::load(&path, home).unwrap_err();
        assert!(matches!(err, LoadConfigError::Invalid { .. }), "{err:?}");
        assert!(err.to_string().contains("github.repos[0]"), "{err}");

        fs::write(&path, "agent = \"grok\"").unwrap();
        let config = Config::load(&path, home).unwrap();
        assert_eq!(config.agent, Some(AgentKind::Grok));
    }

    #[test]
    fn load_reports_unreadable_file() {
        let tmp = tempfile::tempdir().unwrap();
        let err = Config::load(tmp.path(), Path::new(HOME)).unwrap_err();
        assert!(matches!(err, LoadConfigError::Read { .. }), "{err:?}");
    }

    #[test]
    fn repo_slug_length_limits() {
        let owner39 = "a".repeat(39);
        let name100 = "b".repeat(100);
        assert!(format!("{owner39}/{name100}").parse::<RepoSlug>().is_ok());
        assert_eq!(
            format!("{owner39}a/x").parse::<RepoSlug>(),
            Err(ParseRepoSlugError::Owner)
        );
        assert_eq!(
            format!("x/{name100}b").parse::<RepoSlug>(),
            Err(ParseRepoSlugError::Name)
        );
        assert_eq!("/x".parse::<RepoSlug>(), Err(ParseRepoSlugError::Owner));
        assert_eq!("x/".parse::<RepoSlug>(), Err(ParseRepoSlugError::Name));
        assert_eq!("a--b/x".parse::<RepoSlug>(), Err(ParseRepoSlugError::Owner));
        assert_eq!("a-/x".parse::<RepoSlug>(), Err(ParseRepoSlugError::Owner));
        assert_eq!("a/b/c".parse::<RepoSlug>(), Err(ParseRepoSlugError::Name));
        assert_eq!("a/.".parse::<RepoSlug>(), Err(ParseRepoSlugError::Name));
        assert!("a-b/.x".parse::<RepoSlug>().is_ok());
    }

    proptest! {
        #[test]
        fn repo_slug_round_trips(
            owner in "[a-zA-Z0-9]([a-zA-Z0-9]|-[a-zA-Z0-9]){0,18}",
            name in "[a-zA-Z0-9._-]{1,100}",
        ) {
            prop_assume!(name != "." && name != "..");
            let text = format!("{owner}/{name}");
            let slug: RepoSlug = text.parse().unwrap();
            prop_assert_eq!(slug.to_string(), text);
        }

        #[test]
        fn repo_slug_never_panics(text in "\\PC{0,60}") {
            if let Ok(slug) = text.parse::<RepoSlug>() {
                prop_assert_eq!(slug.to_string(), text);
            }
        }
    }
}
