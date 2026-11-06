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

use jiff::Timestamp;
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
    /// A config with nothing in it, for tests elsewhere in the crate.
    #[cfg(test)]
    pub(crate) fn default_for_tests() -> Self {
        Self {
            agent: None,
            schedule: Schedule::Manual,
            history: History::All,
            project_dirs: Vec::new(),
            repos: Vec::new(),
            servers: Vec::new(),
        }
    }

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
            // A dangling symlink also reads as NotFound, but `init` cannot replace it, so only
            // a path with nothing at it counts as missing.
            Err(e)
                if e.kind() == io::ErrorKind::NotFound && fs::symlink_metadata(path).is_err() =>
            {
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum History {
    /// The full history of every feed.
    All,
    /// Advisories published on or after this date.
    Since(Since),
}

/// The first day of the history window, with its start instant (midnight UTC) resolved once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Since {
    date: Date,
    start: Timestamp,
}

impl Since {
    /// Returns `None` when midnight UTC of `date` is outside the range of a [`Timestamp`],
    /// which is narrower than that of a [`Date`] (around the years -9999 and 9999).
    pub(crate) fn new(date: Date) -> Option<Self> {
        let start = date.to_zoned(jiff::tz::TimeZone::UTC).ok()?.timestamp();
        Some(Self { date, start })
    }

    /// Returns the date as written in `history.since`.
    pub fn date(self) -> Date {
        self.date
    }

    /// Returns midnight UTC of the date.
    pub fn start(self) -> Timestamp {
        self.start
    }
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

/// A server the app inspects over SSH.
#[derive(Debug, PartialEq, Eq)]
pub struct Server {
    /// Unique name, used to identify the target in reports.
    pub name: ServerName,
    /// How to reach it.
    pub conn: SshConn,
    /// Folders on the server whose lockfiles are read, like the Mac's project folders.
    pub dirs: Vec<RemoteDir>,
}

/// A server's name: 1 to 64 ASCII letters, digits, `.`, `-` and `_`, not `.` or `..`, so it is
/// safe as a folder name. Unique ignoring case, since the default macOS file system ignores
/// case. Only [`Config::load`] constructs one.
#[derive(Debug, PartialEq, Eq)]
pub struct ServerName(String);

impl fmt::Display for ServerName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// An absolute folder on a server: 1 to 1024 bytes of ASCII letters, digits, `/`, `.`, `-` and
/// `_`, starting with `/`, with no `..` part. The app hands it to the server script in single
/// quotes, which this character set cannot end, and it cannot climb out of what the user named.
/// Only [`Config::load`] constructs one.
#[derive(Debug, PartialEq, Eq)]
pub struct RemoteDir(String);

impl RemoteDir {
    fn parse(value: &str) -> Option<Self> {
        let ok = (1..=1024).contains(&value.len())
            && value.starts_with('/')
            && value.split('/').all(|part| part != "..")
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'-' | b'_'));
        ok.then(|| Self(value.to_owned()))
    }

    /// The folder as written in the config.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// How to reach a server over SSH. Authentication always comes from the user's ssh-agent
/// or key files; the config never holds passwords.
#[derive(Debug, PartialEq, Eq)]
pub enum SshConn {
    /// A `Host` alias from `~/.ssh/config`.
    Alias(SshWord),
    /// Connection fields; anything left out falls back to ssh's own defaults.
    Direct {
        /// Hostname or address.
        host: SshWord,
        /// Login user.
        user: Option<SshWord>,
        /// TCP port.
        port: Option<NonZeroU16>,
        /// Private key file, `~/` expanded.
        identity_file: Option<PathBuf>,
    },
}

/// A host alias, hostname, address or user that is safe to pass to ssh as one argument.
///
/// It is 1 to 255 bytes of ASCII letters, digits, `.`, `-`, `_` and `:` (for IPv6), and does
/// not start with `-`. That rules out what ssh would read as something else: a leading `-` is
/// an option, `@` splits user from host (ssh takes the host after the last `@`, overriding the
/// configured one), `ssh://` is a URI, and whitespace or shell characters could split the
/// value into several words wherever it is pasted into a command or an agent prompt. Only
/// [`Config::load`] constructs one.
#[derive(Debug, PartialEq, Eq)]
pub struct SshWord(String);

impl SshWord {
    fn parse(value: &str) -> Option<Self> {
        let ok = (1..=255).contains(&value.len())
            && !value.starts_with('-')
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b':'));
        ok.then(|| Self(value.to_owned()))
    }
}

impl fmt::Display for SshWord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
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
    /// A server name is empty, `.` or `..`, longer than 64 bytes, or has characters other than
    /// letters, digits, `.`, `-` and `_`.
    #[error(
        "servers[{index}].name = {value:?}: use 1-64 letters, digits, '.', '-' or '_' (not . or ..)"
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
    /// A server sets `ssh` together with connection fields, or sets no `ssh` and no `host`.
    #[error(
        "servers[{index}]: set either ssh (an ~/.ssh/config alias) or host with optional user, \
         port and identity_file, not both"
    )]
    ServerConn {
        /// Position in the list.
        index: usize,
    },
    /// `ssh`, `host` or `user` is not an [`SshWord`].
    #[error(
        "servers[{index}].{key} = {value:?}: use 1-255 letters, digits, '.', '-', '_' or ':', \
         not starting with '-'"
    )]
    SshValue {
        /// Position in the list.
        index: usize,
        /// The key holding the value.
        key: &'static str,
        /// The value found.
        value: String,
    },
    /// `identity_file` is relative after `~/` expansion, or has characters other than ASCII
    /// letters, digits, `/`, `.`, `-` and `_`.
    #[error(
        "servers[{index}].identity_file = {value:?}: use an absolute path or one starting with \
         ~/, of letters, digits, '/', '.', '-' or '_'"
    )]
    IdentityFile {
        /// Position in the list.
        index: usize,
        /// The value found.
        value: String,
    },
    /// A folder in `dirs` is not a [`RemoteDir`].
    #[error(
        "servers[{index}].dirs = {value:?}: use an absolute path of letters, digits, '/', '.', \
         '-' or '_', without '..'"
    )]
    RemoteDir {
        /// Position of the server in the list.
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
    #[serde(default)]
    dirs: Vec<String>,
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
///
/// Only `YYYY-MM-DD` is accepted. jiff's `Date` parser also takes a datetime with an offset
/// and keeps only its civil date, which can be a day later than the instant in UTC, and the
/// compact `YYYYMMDD` form. Requiring the value to print back unchanged rules both out.
fn resolve_history(since: Option<&str>, problems: &mut Vec<ConfigProblem>) -> History {
    let Some(value) = since.filter(|v| *v != "all") else {
        return History::All;
    };
    if let Ok(date) = value.parse::<Date>()
        && date.to_string() == value
        && let Some(since) = Since::new(date)
    {
        return History::Since(since);
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
        // 64 is arbitrary: well under macOS's 255-byte file name limit, so the name still fits
        // in a folder name with a prefix or suffix added.
        let name_ok = (1..=64).contains(&server.name.len())
            && !matches!(server.name.as_str(), "." | "..")
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

        let mut dirs = Vec::with_capacity(server.dirs.len());
        for value in &server.dirs {
            match RemoteDir::parse(value) {
                Some(dir) => dirs.push(dir),
                None => problems.push(ConfigProblem::RemoteDir {
                    index,
                    value: value.clone(),
                }),
            }
        }

        if let Some(conn) = resolve_conn(index, &server, home, problems)
            && name_ok
        {
            servers.push(Server {
                name: ServerName(server.name),
                conn,
                dirs,
            });
        }
    }
    servers
}

/// Accepts exactly one of `ssh` and the connection fields, and reports every bad value of the
/// server, not only the first.
fn resolve_conn(
    index: usize,
    server: &RawServer,
    home: &Path,
    problems: &mut Vec<ConfigProblem>,
) -> Option<SshConn> {
    let before = problems.len();

    let has_fields = server.host.is_some()
        || server.user.is_some()
        || server.port.is_some()
        || server.identity_file.is_some();
    let shape_ok = match &server.ssh {
        Some(_) => !has_fields,
        None => server.host.is_some(),
    };
    if !shape_ok {
        problems.push(ConfigProblem::ServerConn { index });
    }

    let mut word = |key, value: &Option<String>| {
        let value = value.as_deref()?;
        let parsed = SshWord::parse(value);
        if parsed.is_none() {
            problems.push(ConfigProblem::SshValue {
                index,
                key,
                value: value.to_owned(),
            });
        }
        parsed
    };
    let alias = word("ssh", &server.ssh);
    let host = word("host", &server.host);
    let user = word("user", &server.user);
    let identity_file = server.identity_file.as_deref().and_then(|value| {
        let path = expand_home(value, home);
        // The path goes into ssh arguments and agent prompts like an SshWord, so it is held to a
        // safe path character set; a key under a folder with spaces needs a symlink.
        let safe = path
            .as_os_str()
            .as_encoded_bytes()
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'-' | b'_'));
        if path.is_absolute() && safe {
            return Some(path);
        }
        problems.push(ConfigProblem::IdentityFile {
            index,
            value: value.to_owned(),
        });
        None
    });

    if problems.len() > before {
        return None;
    }
    match (alias, host) {
        (Some(alias), None) => Some(SshConn::Alias(alias)),
        (None, Some(host)) => Some(SshConn::Direct {
            host,
            user,
            port: server.port,
            identity_file,
        }),
        _ => unreachable!("a server with both or neither of ssh and host failed shape_ok"),
    }
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

    fn word(value: &str) -> SshWord {
        SshWord::parse(value).unwrap()
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
            dirs = ["/srv/app", "/opt/my_app-2.0"]

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
        let History::Since(since) = config.history else {
            panic!("expected a history window, got {:?}", config.history);
        };
        assert_eq!(since.date(), jiff::civil::date(2025, 1, 31));
        assert_eq!(since.start(), "2025-01-31T00:00:00Z".parse().unwrap());
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
                    name: ServerName("prod".into()),
                    conn: SshConn::Alias(word("prod-alias")),
                    dirs: vec![
                        RemoteDir("/srv/app".into()),
                        RemoteDir("/opt/my_app-2.0".into())
                    ],
                },
                Server {
                    name: ServerName("db-1".into()),
                    conn: SshConn::Direct {
                        host: word("10.0.0.5"),
                        user: Some(word("admin")),
                        port: NonZeroU16::new(2222),
                        identity_file: Some("/Users/me/.ssh/id_ed25519".into()),
                    },
                    dirs: vec![],
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
                ConfigProblem::IdentityFile {
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
            "identity_file = \"/k\"",
        ] {
            let text = format!("[[servers]]\nname = \"s\"\nssh = \"a\"\n{field}\n");
            assert_eq!(
                resolve(&text).unwrap_err(),
                [ConfigProblem::ServerConn { index: 0 }],
                "{field}"
            );
        }
    }

    /// Values ssh would read as a different destination, an option, or several words.
    #[test]
    fn ssh_words_reject_what_ssh_would_reinterpret() {
        for bad in [
            "",
            "-oProxyCommand=x",
            "db.internal@attacker.example",
            "ssh://attacker.example",
            "good.com -oProxyCommand=id",
            "a\nb",
            "a;b",
            "$(id)",
            "a`b`",
            "a%h",
            "a#b",
            "a/b",
            &"a".repeat(256),
        ] {
            assert_eq!(SshWord::parse(bad), None, "{bad:?}");
        }
        for good in [
            "prod",
            "db-1.internal",
            "10.0.0.5",
            "::1",
            "fe80::1",
            "deploy_user",
        ] {
            assert_eq!(SshWord::parse(good).unwrap().to_string(), good);
        }
        assert!(SshWord::parse(&"a".repeat(255)).is_some());
    }

    #[test]
    fn every_problem_of_one_server_is_reported() {
        let problems = resolve(
            "[[servers]]\nname = \"s\"\nssh = \"a b\"\nhost = \"-h\"\nuser = \"\"\n\
             identity_file = \"keys/id\"\n",
        )
        .unwrap_err();
        assert_eq!(
            problems,
            [
                ConfigProblem::ServerConn { index: 0 },
                ConfigProblem::SshValue {
                    index: 0,
                    key: "ssh",
                    value: "a b".into()
                },
                ConfigProblem::SshValue {
                    index: 0,
                    key: "host",
                    value: "-h".into()
                },
                ConfigProblem::SshValue {
                    index: 0,
                    key: "user",
                    value: String::new()
                },
                ConfigProblem::IdentityFile {
                    index: 0,
                    value: "keys/id".into()
                },
            ]
        );
    }

    #[test]
    fn identity_file_allows_only_safe_path_characters() {
        for bad in [
            "/tmp/id\n-oProxyCommand=x",
            "/k -oProxyCommand=id",
            "~/.ssh/id; curl x | sh",
            "/keys/$(id)",
            "/Library/Application Support/id",
        ] {
            let text = format!("[[servers]]\nname = \"s\"\nhost = \"h\"\nidentity_file = {bad:?}");
            assert_eq!(
                resolve(&text).unwrap_err(),
                [ConfigProblem::IdentityFile {
                    index: 0,
                    value: bad.into()
                }],
                "{bad:?}"
            );
        }
    }

    #[test]
    fn remote_dirs_are_absolute_safe_and_stay_inside() {
        for bad in [
            "srv/app",
            "",
            "/srv/../etc",
            "/srv/..",
            "/srv/it's",
            "/srv/a b",
            "/srv/$(id)",
            "/srv/a\nb",
        ] {
            let text = format!("[[servers]]\nname = \"s\"\nssh = \"a\"\ndirs = [{bad:?}]");
            assert_eq!(
                resolve(&text).unwrap_err(),
                [ConfigProblem::RemoteDir {
                    index: 0,
                    value: bad.into()
                }],
                "{bad:?}"
            );
        }
        let long = format!("/{}", "a".repeat(1023));
        let text = format!("[[servers]]\nname = \"s\"\nssh = \"a\"\ndirs = [\"{long}\", \"/\"]");
        let config = resolve(&text).unwrap();
        assert_eq!(config.servers[0].dirs[0].as_str(), long);
        assert_eq!(config.servers[0].dirs[1].as_str(), "/");
        let longer = format!("[[servers]]\nname = \"s\"\nssh = \"a\"\ndirs = [\"{long}a\"]");
        assert!(resolve(&longer).is_err());
        assert!(
            ConfigProblem::RemoteDir {
                index: 0,
                value: "x".into()
            }
            .to_string()
            .contains("without '..'")
        );
    }

    #[test]
    fn since_accepts_only_plain_dates() {
        for bad in [
            "2025-02-01T01:00:00+14:00",
            "2025-01-31T00:00:00Z",
            "20250131",
            "2025-02-29",
            "2025-1-31",
            "9999-12-31",
            "-009999-01-01",
        ] {
            let text = format!("history.since = {bad:?}");
            assert_eq!(
                resolve(&text).unwrap_err(),
                [ConfigProblem::Since { value: bad.into() }],
                "{bad}"
            );
        }
        let config = resolve("history.since = \"2024-02-29\"").unwrap();
        assert_eq!(
            config.history,
            History::Since(Since::new(jiff::civil::date(2024, 2, 29)).unwrap())
        );
    }

    #[test]
    fn server_name_length_limit() {
        let ok = format!("[[servers]]\nname = \"{}\"\nssh = \"a\"\n", "n".repeat(64));
        assert!(resolve(&ok).is_ok());
        let long = "n".repeat(65);
        let text = format!("[[servers]]\nname = \"{long}\"\nssh = \"a\"\n");
        assert_eq!(
            resolve(&text).unwrap_err(),
            [ConfigProblem::ServerName {
                index: 0,
                value: long
            }]
        );
    }

    #[test]
    fn dangling_symlink_is_not_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("config.toml");
        std::os::unix::fs::symlink(tmp.path().join("gone"), &path).unwrap();

        let err = Config::load(&path, Path::new(HOME)).unwrap_err();
        assert!(matches!(err, LoadConfigError::Read { .. }), "{err:?}");
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
