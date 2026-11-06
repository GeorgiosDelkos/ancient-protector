//! What the settings show, worked out from the config and what [`crate::detect`] found, so the
//! app's UI only lays it out: each section's one-line summary, the choices in it, and which
//! are chosen.
//!
//! Folders are shown as people write them (`~/code`) and compared after `~/` expansion;
//! repositories are compared ignoring case, as GitHub does. A choice already in the config is
//! listed once, first, whether or not detection found it too.

use std::path::Path;
use std::path::PathBuf;

use serde::Serialize;

use crate::agent::AgentKind;
use crate::config::Config;
use crate::config::History;
use crate::config::Schedule;
use crate::config::Server;
use crate::config::ServerName;
use crate::config::SshConn;
use crate::config::SshWord;
use crate::detect::Detected;

/// The interval the "Every N hours" field shows while the schedule is manual. Arbitrary: four
/// sweeps a day.
const DEFAULT_HOURS: u32 = 6;

/// The date the "Since" field shows while history is `all`. Arbitrary: a recent year start.
const DEFAULT_SINCE: &str = "2025-01-01";

/// The settings' content.
#[derive(Debug, Serialize)]
pub struct SettingsView {
    /// Each section, in order, with its summary.
    pub sections: Vec<SectionLine>,
    /// The agents, chosen or not, found or not.
    pub agents: Vec<AgentChoice>,
    /// The schedule and history.
    pub schedule: ScheduleChoice,
    /// The folders searched for lockfiles, then suggested ones.
    pub folders: Vec<FolderChoice>,
    /// The tools a Mac sweep reads.
    pub tools: Vec<ToolLine>,
    /// The `gh` login, or `None` when gh is missing or logged out.
    pub gh_login: Option<String>,
    /// The repositories swept, then the user's other repositories.
    pub repos: Vec<RepoChoice>,
    /// The servers swept.
    pub servers: Vec<ServerLine>,
    /// Hosts from `~/.ssh/config` that are not swept yet.
    pub hosts: Vec<HostChoice>,
    /// Whether an NVD API key is in the Keychain.
    pub nvd_key: bool,
}

/// A section of the settings.
#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Section {
    /// The agent.
    Agent,
    /// Schedule and history.
    Schedule,
    /// This Mac's folders and tools.
    Mac,
    /// GitHub repositories.
    Github,
    /// Servers.
    Servers,
    /// The NVD API key.
    Nvd,
}

/// A section's line in the list.
#[derive(Debug, Serialize)]
pub struct SectionLine {
    /// Which section.
    pub id: Section,
    /// Its title.
    pub title: &'static str,
    /// Its value, briefly: "Claude Code", "3 folders".
    pub summary: String,
    /// Whether it needs the user before a sweep works well.
    pub attention: bool,
}

/// An agent to choose.
#[derive(Debug, Serialize)]
pub struct AgentChoice {
    /// The agent, as [`crate::Setting::Agent`] takes it.
    pub agent: AgentKind,
    /// Its name as people know it.
    pub name: &'static str,
    /// Where the login shell finds it.
    pub path: Option<PathBuf>,
    /// Whether it can be chosen: only an agent the login shell finds can run a sweep.
    pub available: bool,
    /// Whether it is the chosen one.
    pub chosen: bool,
}

/// The schedule and history, with the values their fields show.
#[derive(Debug, Serialize)]
pub struct ScheduleChoice {
    /// Whether sweeps run on a schedule.
    pub automatic: bool,
    /// The interval in hours, or the default while manual.
    pub hours: u32,
    /// Whether the first download fetches every advisory.
    pub all_history: bool,
    /// The `since` date, or the default while `all`.
    pub since: String,
}

/// A folder searched for lockfiles, or a suggested one.
#[derive(Debug, Serialize)]
pub struct FolderChoice {
    /// The folder, as [`crate::Setting::AddFolder`] and `RemoveFolder` take it.
    pub value: String,
    /// Whether the config has it.
    pub chosen: bool,
}

/// A tool a Mac sweep reads.
#[derive(Debug, Serialize)]
pub struct ToolLine {
    /// Its name as people know it.
    pub name: &'static str,
    /// Where the login shell finds it.
    pub path: Option<PathBuf>,
}

/// A repository to sweep.
#[derive(Debug, Serialize)]
pub struct RepoChoice {
    /// `owner/name`.
    pub repo: String,
    /// Whether it is private; `None` for one the user typed that gh did not list.
    pub private: Option<bool>,
    /// Whether it is swept.
    pub chosen: bool,
}

/// A server that is swept.
#[derive(Debug, Serialize)]
pub struct ServerLine {
    /// Its name.
    pub name: String,
    /// How it is reached: the alias, or `user@host:port`.
    pub reach: String,
    /// Its folders searched for lockfiles.
    pub dirs: Vec<String>,
}

/// A host from `~/.ssh/config` that can be added.
#[derive(Debug, Serialize)]
pub struct HostChoice {
    /// Its alias.
    pub alias: String,
    /// Its `HostName`, when the config sets one.
    pub host_name: Option<String>,
    /// Whether the alias works as a server name and an ssh argument.
    pub addable: bool,
}

/// The settings' content for `config` and what was detected, with folders shown against
/// `home`.
pub fn settings_view(config: &Config, detected: &Detected, home: &Path) -> SettingsView {
    let servers: Vec<ServerLine> = config.servers.iter().map(server_line).collect();
    // A host is swept when a server reaches it through its alias; one reached directly at a
    // host that happens to share the name is not. Adding a host names the server after its
    // alias, so a name already taken (ignoring case, as the config checks) cannot be added.
    let swept = |alias: &str| {
        config
            .servers
            .iter()
            .any(|s| matches!(&s.conn, SshConn::Alias(a) if a.to_string() == alias))
    };
    let named = |alias: &str| {
        config
            .servers
            .iter()
            .any(|s| s.name.to_string().eq_ignore_ascii_case(alias))
    };
    let hosts = detected
        .ssh_hosts
        .iter()
        .filter(|h| !swept(&h.alias))
        .map(|h| HostChoice {
            alias: h.alias.clone(),
            host_name: h.host_name.clone(),
            addable: !named(&h.alias)
                && ServerName::is_valid(&h.alias)
                && SshWord::parse(&h.alias).is_some(),
        })
        .collect();
    SettingsView {
        sections: sections(config, detected),
        agents: detected
            .agents
            .iter()
            .map(|(agent, path)| AgentChoice {
                agent: *agent,
                name: agent.name(),
                path: path.clone(),
                available: path.is_some(),
                chosen: config.agent == Some(*agent),
            })
            .collect(),
        schedule: schedule_choice(config),
        folders: folders(config, detected, home),
        tools: detected
            .tools
            .iter()
            .map(|t| ToolLine {
                name: t.name,
                path: t.path.clone(),
            })
            .collect(),
        gh_login: detected.gh_login.clone(),
        repos: repos(config, detected),
        servers,
        hosts,
        nvd_key: detected.nvd_key,
    }
}

fn sections(config: &Config, detected: &Detected) -> Vec<SectionLine> {
    let line = |id, title, summary: String, attention| SectionLine {
        id,
        title,
        summary,
        attention,
    };
    let agent = config.agent.map_or("Choose one", AgentKind::name);
    let schedule = match config.schedule {
        Schedule::Manual => "Manual".to_owned(),
        Schedule::EveryHours(hours) => format!("Every {hours} h"),
    };
    let nvd = if detected.nvd_key {
        "In Keychain"
    } else {
        "Not set"
    };
    vec![
        line(
            Section::Agent,
            "Agent",
            agent.to_owned(),
            config.agent.is_none(),
        ),
        line(Section::Schedule, "Schedule", schedule, false),
        line(
            Section::Mac,
            "This Mac",
            count(config.project_dirs.len(), "folder", "folders"),
            false,
        ),
        line(
            Section::Github,
            "GitHub",
            count(config.repos.len(), "repository", "repositories"),
            false,
        ),
        line(
            Section::Servers,
            "Servers",
            count(config.servers.len(), "server", "servers"),
            false,
        ),
        line(Section::Nvd, "NVD key", nvd.to_owned(), !detected.nvd_key),
    ]
}

fn count(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

fn schedule_choice(config: &Config) -> ScheduleChoice {
    let (automatic, hours) = match config.schedule {
        Schedule::Manual => (false, DEFAULT_HOURS),
        Schedule::EveryHours(hours) => (true, hours.get()),
    };
    let (all_history, since) = match config.history {
        History::All => (true, DEFAULT_SINCE.to_owned()),
        History::Since(since) => (false, since.date().to_string()),
    };
    ScheduleChoice {
        automatic,
        hours,
        all_history,
        since,
    }
}

fn folders(config: &Config, detected: &Detected, home: &Path) -> Vec<FolderChoice> {
    let chosen = config.project_dirs.iter().map(|dir| FolderChoice {
        value: shown(dir, home),
        chosen: true,
    });
    let suggested = detected
        .folders
        .iter()
        .filter(|dir| !config.project_dirs.contains(dir))
        .map(|dir| FolderChoice {
            value: shown(dir, home),
            chosen: false,
        });
    chosen.chain(suggested).collect()
}

/// `/Users/me/code` as `~/code`, the way people write their own folders.
fn shown(dir: &Path, home: &Path) -> String {
    match dir.strip_prefix(home) {
        Ok(rest) if rest.as_os_str().is_empty() => "~".to_owned(),
        Ok(rest) => format!("~/{}", rest.display()),
        Err(_) => dir.display().to_string(),
    }
}

fn repos(config: &Config, detected: &Detected) -> Vec<RepoChoice> {
    let swept = |repo: &str| {
        config
            .repos
            .iter()
            .any(|r| r.to_string().eq_ignore_ascii_case(repo))
    };
    let listed = |repo: &str| {
        detected
            .repos
            .iter()
            .any(|r| r.name_with_owner.eq_ignore_ascii_case(repo))
    };
    let typed = config
        .repos
        .iter()
        .map(ToString::to_string)
        .filter(|r| !listed(r))
        .map(|repo| RepoChoice {
            repo,
            private: None,
            chosen: true,
        });
    let found = detected.repos.iter().map(|r| RepoChoice {
        repo: r.name_with_owner.clone(),
        private: Some(r.is_private),
        chosen: swept(&r.name_with_owner),
    });
    typed.chain(found).collect()
}

fn server_line(server: &Server) -> ServerLine {
    let reach = match &server.conn {
        SshConn::Alias(alias) => alias.to_string(),
        SshConn::Direct {
            host, user, port, ..
        } => {
            let user = user.as_ref().map_or(String::new(), |u| format!("{u}@"));
            let port = port.map_or(String::new(), |p| format!(":{p}"));
            format!("{user}{host}{port}")
        }
    };
    ServerLine {
        name: server.name.to_string(),
        reach,
        dirs: server.dirs.iter().map(|d| d.as_str().to_owned()).collect(),
    }
}

#[cfg(test)]
mod tests {
    use crate::detect::RepoInfo;
    use crate::detect::SshHost;
    use crate::detect::Tool;

    use super::*;

    const HOME: &str = "/Users/me";

    fn config(text: &str) -> Config {
        Config::from_text(Path::new("/c/config.toml"), text, Path::new(HOME)).unwrap()
    }

    fn detected() -> Detected {
        Detected {
            agents: vec![
                (AgentKind::Claude, Some(PathBuf::from("/bin/claude"))),
                (AgentKind::Codex, None),
            ],
            tools: vec![Tool {
                program: "brew",
                name: "Homebrew",
                path: None,
            }],
            gh_login: Some("me".to_owned()),
            repos: vec![
                RepoInfo {
                    name_with_owner: "me/app".to_owned(),
                    is_private: true,
                },
                RepoInfo {
                    name_with_owner: "me/site".to_owned(),
                    is_private: false,
                },
            ],
            ssh_hosts: vec![
                SshHost {
                    alias: "web".to_owned(),
                    host_name: Some("10.0.0.5".to_owned()),
                },
                SshHost {
                    alias: "db".to_owned(),
                    host_name: None,
                },
                SshHost {
                    alias: "-bad".to_owned(),
                    host_name: None,
                },
            ],
            folders: vec![
                PathBuf::from("/Users/me/code"),
                PathBuf::from("/Users/me/src"),
            ],
            nvd_key: false,
        }
    }

    fn summaries(view: &SettingsView) -> Vec<(&str, &str, bool)> {
        view.sections
            .iter()
            .map(|s| (s.title, s.summary.as_str(), s.attention))
            .collect()
    }

    #[test]
    fn a_new_config_asks_for_an_agent_and_an_nvd_key() {
        let view = settings_view(&config(""), &detected(), Path::new(HOME));
        assert_eq!(
            summaries(&view),
            [
                ("Agent", "Choose one", true),
                ("Schedule", "Manual", false),
                ("This Mac", "0 folders", false),
                ("GitHub", "0 repositories", false),
                ("Servers", "0 servers", false),
                ("NVD key", "Not set", true),
            ]
        );
        assert!(view.agents.iter().all(|a| !a.chosen));
        assert_eq!(view.agents[0].name, "Claude Code");
        assert!(view.agents[0].available);
        assert_eq!(view.agents[1].path, None);
        assert!(
            !view.agents[1].available,
            "not found, so it cannot run a sweep"
        );
        let s = &view.schedule;
        assert_eq!(
            (s.automatic, s.hours, s.all_history, s.since.as_str()),
            (false, DEFAULT_HOURS, true, DEFAULT_SINCE)
        );
        assert_eq!(view.tools[0].name, "Homebrew");
    }

    #[test]
    fn a_filled_config_shows_its_choices_first_and_suggests_the_rest() {
        let text = r#"
agent = "claude"
[schedule]
every_hours = 1
[history]
since = "2026-03-01"
[mac]
project_dirs = ["~/code", "/opt/work"]
[github]
repos = ["Me/App", "other/lib"]
[[servers]]
name = "web"
ssh = "web"
dirs = ["/srv/app"]
"#;
        let mut found = detected();
        found.nvd_key = true;
        let view = settings_view(&config(text), &found, Path::new(HOME));
        assert_eq!(
            summaries(&view),
            [
                ("Agent", "Claude Code", false),
                ("Schedule", "Every 1 h", false),
                ("This Mac", "2 folders", false),
                ("GitHub", "2 repositories", false),
                ("Servers", "1 server", false),
                ("NVD key", "In Keychain", false),
            ]
        );
        assert!(view.agents[0].chosen);
        let s = &view.schedule;
        assert_eq!(
            (s.automatic, s.hours, s.all_history, s.since.as_str()),
            (true, 1, false, "2026-03-01")
        );

        let folders: Vec<(&str, bool)> = view
            .folders
            .iter()
            .map(|f| (f.value.as_str(), f.chosen))
            .collect();
        assert_eq!(
            folders,
            [("~/code", true), ("/opt/work", true), ("~/src", false)]
        );

        let repos: Vec<(&str, Option<bool>, bool)> = view
            .repos
            .iter()
            .map(|r| (r.repo.as_str(), r.private, r.chosen))
            .collect();
        assert_eq!(
            repos,
            [
                ("other/lib", None, true),
                ("me/app", Some(true), true),
                ("me/site", Some(false), false)
            ],
            "a typed repository first; a listed one matched ignoring case"
        );

        assert_eq!(view.servers[0].reach, "web");
        assert_eq!(view.servers[0].dirs, ["/srv/app"]);
        let hosts: Vec<(&str, bool)> = view
            .hosts
            .iter()
            .map(|h| (h.alias.as_str(), h.addable))
            .collect();
        assert_eq!(
            hosts,
            [("db", true), ("-bad", false)],
            "web is swept already"
        );
    }

    #[test]
    fn a_host_is_hidden_only_when_its_alias_is_swept_and_offered_only_under_a_free_name() {
        let text = r#"
[[servers]]
name = "DB"
host = "web"
"#;
        let view = settings_view(&config(text), &detected(), Path::new(HOME));
        let hosts: Vec<(&str, bool)> = view
            .hosts
            .iter()
            .map(|h| (h.alias.as_str(), h.addable))
            .collect();
        assert_eq!(
            hosts,
            [("web", true), ("db", false), ("-bad", false)],
            "web is only a direct server's host; DB takes the name db"
        );
    }

    #[test]
    fn direct_servers_read_as_user_at_host_and_port() {
        let text = r#"
[[servers]]
name = "box"
host = "10.0.0.9"
user = "ops"
port = 2222
"#;
        let view = settings_view(&config(text), &detected(), Path::new(HOME));
        assert_eq!(view.servers[0].reach, "ops@10.0.0.9:2222");
        assert_eq!(view.hosts.len(), 3);
    }

    #[test]
    fn folders_under_home_are_shown_with_a_tilde() {
        let home = Path::new(HOME);
        assert_eq!(shown(Path::new("/Users/me"), home), "~");
        assert_eq!(shown(Path::new("/Users/me/code/x"), home), "~/code/x");
        assert_eq!(shown(Path::new("/Users/meg/code"), home), "/Users/meg/code");
        assert_eq!(count(1, "folder", "folders"), "1 folder");
        assert_eq!(count(0, "folder", "folders"), "0 folders");
    }
}
