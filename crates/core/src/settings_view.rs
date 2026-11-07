//! What the settings show, worked out from the config and what [`crate::detect`] found, so the
//! app's UI only lays it out: the headline, the sections in their groups with each one's
//! one-line summary, the choices in them, and which are chosen.
//!
//! Models are offered for the chosen agent, grouped by who serves them: one provider per
//! agent, except opencode, whose `provider/model` names say. A chosen model the agent does
//! not list (typed, or listed no more) is still offered, so the choice always shows.
//!
//! Folders are shown as people write them (`~/code`) and compared after `~/` expansion;
//! repositories are compared ignoring case, as GitHub does. Folders and repositories in the
//! config are listed once each: chosen folders first, then suggested ones; repositories the
//! user typed that gh does not list first, then gh's list in its order, chosen or not.

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
use crate::feeds::NVD_PER_30_SECONDS_ANONYMOUS;
use crate::feeds::NVD_PER_30_SECONDS_WITH_KEY;

/// The interval the "Every N hours" field shows while the schedule is manual. Arbitrary: four
/// sweeps a day.
const DEFAULT_HOURS: u32 = 6;

/// The date the "Since" field shows while history is `all`. Arbitrary: a recent year start.
const DEFAULT_SINCE: &str = "2025-01-01";

/// The settings' content.
#[derive(Debug, Serialize)]
pub struct SettingsView {
    /// The top line: "Ready to sweep", "2 settings need you".
    pub headline: String,
    /// Whether no section needs the user.
    pub ready: bool,
    /// The sections in their groups, in order, each with its summary.
    pub groups: Vec<SectionGroup>,
    /// The agents, chosen or not, found or not.
    pub agents: Vec<AgentChoice>,
    /// The chosen agent's models, or `None` while no agent is chosen.
    pub model: Option<ModelView>,
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
    /// NVD's request limits without and with a key, and which one applies.
    pub nvd_rates: [NvdRate; 2],
}

/// One of NVD's request limits.
#[derive(Debug, Serialize)]
pub struct NvdRate {
    /// When it applies: "Without a key".
    pub label: &'static str,
    /// Requests allowed in any 30 seconds.
    pub per_30_seconds: u32,
    /// Whether it is the limit sweeps run under now.
    pub applies: bool,
}

/// NVD's limits as the settings show them: each one's label, its rate, and whether it is the
/// one with a key.
const NVD_RATES: [(&str, u32, bool); 2] = [
    ("Without a key", NVD_PER_30_SECONDS_ANONYMOUS, false),
    ("With a key", NVD_PER_30_SECONDS_WITH_KEY, true),
];

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

/// Sections listed together under a title.
#[derive(Debug, Serialize)]
pub struct SectionGroup {
    /// The group's title: "Sweeps", "Targets".
    pub title: &'static str,
    /// Its sections, in order.
    pub sections: Vec<SectionLine>,
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

/// The models the chosen agent can run with.
#[derive(Debug, Serialize)]
pub struct ModelView {
    /// The agent, as [`crate::Setting::Model`] takes it.
    pub agent: AgentKind,
    /// Whether the agent runs its own default model, as no model is chosen.
    pub default: bool,
    /// Who serves the models, each with its models; one provider unless the agent is
    /// opencode. Empty when the agent lists no models and none is chosen.
    pub providers: Vec<ProviderChoice>,
    /// Whether there are models to offer (the agent's own list, or Claude Code's aliases);
    /// when there are none, the user types one.
    pub listed: bool,
    /// What the field for a typed model says while empty.
    pub hint: &'static str,
}

/// A provider and its models.
#[derive(Debug, Serialize)]
pub struct ProviderChoice {
    /// Its name: "Anthropic", "ollama"; empty for opencode models named without one.
    pub name: String,
    /// Its name as shown: "Other" for the empty one.
    pub label: String,
    /// Whether the chosen model is one of its models; the first provider when no model is.
    pub chosen: bool,
    /// Its models.
    pub models: Vec<ModelOption>,
}

/// A model to choose.
#[derive(Debug, Serialize)]
pub struct ModelOption {
    /// The model as [`crate::Setting::Model`] takes it: `opus`, `ollama/gemma4:e4b`.
    pub value: String,
    /// Its name without the provider: `gemma4:e4b`.
    pub label: String,
    /// The full name under the label, when the label drops the provider.
    pub sub: Option<String>,
    /// Whether it is the chosen model.
    pub chosen: bool,
}

/// Claude Code's aliases for the newest model of each family, which its `--model` takes
/// (`claude --help`, checked 2026-11-07); its CLI lists no models.
const CLAUDE_MODELS: [&str; 3] = ["opus", "sonnet", "haiku"];

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
    let groups = groups(config, detected);
    let attention = groups
        .iter()
        .flat_map(|g| &g.sections)
        .filter(|s| s.attention)
        .count();
    SettingsView {
        headline: headline(attention),
        ready: attention == 0,
        groups,
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
        model: config
            .agent
            .map(|agent| model_view(config, detected, agent)),
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
        nvd_rates: NVD_RATES.map(|(label, per_30_seconds, with_key)| NvdRate {
            label,
            per_30_seconds,
            applies: with_key == detected.nvd_key,
        }),
    }
}

fn groups(config: &Config, detected: &Detected) -> Vec<SectionGroup> {
    let line = |id, title, summary: String, attention| SectionLine {
        id,
        title,
        summary,
        attention,
    };
    let agent = match (
        config.agent,
        config.agent.and_then(|a| config.models.get(&a)),
    ) {
        (None, _) => "Choose one".to_owned(),
        (Some(agent), None) => agent.name().to_owned(),
        (Some(agent), Some(model)) => format!("{} · {model}", agent.name()),
    };
    let schedule = match config.schedule {
        Schedule::Manual => "Manual".to_owned(),
        Schedule::EveryHours(hours) => format!("Every {hours} h"),
    };
    let nvd = if detected.nvd_key {
        "In Keychain"
    } else {
        "Not set"
    };
    let group = |title, sections| SectionGroup { title, sections };
    vec![
        group(
            "Sweeps",
            vec![
                line(Section::Agent, "Agent", agent, config.agent.is_none()),
                line(Section::Schedule, "Schedule", schedule, false),
            ],
        ),
        group(
            "Targets",
            vec![
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
            ],
        ),
        group(
            "Advisories",
            vec![line(
                Section::Nvd,
                "NVD key",
                nvd.to_owned(),
                // Optional, as its page says: it speeds up the first sweep, and sweeps work
                // without it, so it never counts as needing the user.
                false,
            )],
        ),
    ]
}

/// "Ready to sweep" once nothing needs the user, else how many sections do.
fn headline(attention: usize) -> String {
    match attention {
        0 => "Ready to sweep".to_owned(),
        1 => "1 setting needs you".to_owned(),
        n => format!("{n} settings need you"),
    }
}

fn model_view(config: &Config, detected: &Detected, agent: AgentKind) -> ModelView {
    let chosen = config.models.get(&agent).map(|m| m.as_str().to_owned());
    let listed: Option<Vec<String>> = match agent {
        AgentKind::Claude => Some(CLAUDE_MODELS.map(str::to_owned).to_vec()),
        AgentKind::Grok | AgentKind::Opencode => detected
            .models
            .iter()
            .find(|(a, _)| *a == agent)
            .map(|(_, models)| models.clone()),
        AgentKind::Codex | AgentKind::Gemini => None,
    };
    let mut values = listed.clone().unwrap_or_default();
    if let Some(chosen) = &chosen
        && !values.contains(chosen)
    {
        values.insert(0, chosen.clone());
    }

    let providers = by_provider(agent, values, chosen.as_deref());
    let listed = listed.is_some_and(|l| !l.is_empty());
    ModelView {
        agent,
        default: chosen.is_none(),
        providers,
        listed,
        hint: if listed {
            "Another model"
        } else {
            "Model name, as --model takes it"
        },
    }
}

/// `values` grouped by who serves them, in order, with the chosen model's provider marked
/// (the first provider when none is chosen).
fn by_provider(agent: AgentKind, values: Vec<String>, chosen: Option<&str>) -> Vec<ProviderChoice> {
    let mut providers: Vec<ProviderChoice> = Vec::new();
    for value in values {
        let (provider, label) = match (agent.provider(), value.split_once('/')) {
            (Some(provider), _) => (provider.to_owned(), value.clone()),
            (None, Some((provider, label))) => (provider.to_owned(), label.to_owned()),
            (None, None) => (String::new(), value.clone()),
        };
        let option = ModelOption {
            chosen: chosen == Some(value.as_str()),
            sub: (label != value).then(|| value.clone()),
            value,
            label,
        };
        match providers.iter_mut().find(|p| p.name == provider) {
            Some(group) => group.models.push(option),
            None => providers.push(ProviderChoice {
                label: if provider.is_empty() {
                    "Other".to_owned()
                } else {
                    provider.clone()
                },
                name: provider,
                chosen: false,
                models: vec![option],
            }),
        }
    }
    let on = providers
        .iter()
        .position(|p| p.models.iter().any(|m| m.chosen))
        .unwrap_or(0);
    if let Some(provider) = providers.get_mut(on) {
        provider.chosen = true;
    }
    providers
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
            models: vec![(
                AgentKind::Opencode,
                vec![
                    "opencode/big-pickle".to_owned(),
                    "ollama/gemma4:e4b".to_owned(),
                    "ollama/qwen3".to_owned(),
                ],
            )],
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

    #[test]
    fn the_headline_counts_what_needs_the_user_and_the_nvd_key_is_optional() {
        assert_eq!(headline(0), "Ready to sweep");
        assert_eq!(headline(1), "1 setting needs you");
        assert_eq!(headline(3), "3 settings need you");
        let view = settings_view(&config("agent = \"claude\""), &detected(), Path::new(HOME));
        assert!(!detected().nvd_key);
        let rates: Vec<_> = view
            .nvd_rates
            .iter()
            .map(|r| (r.label, r.per_30_seconds, r.applies))
            .collect();
        assert_eq!(
            rates,
            [("Without a key", 5, true), ("With a key", 50, false)]
        );
        assert_eq!(view.headline, "Ready to sweep");
        assert!(view.ready);
    }

    /// A provider as the tests compare it: its name, whether it is chosen, and each model's
    /// value, label and whether it is chosen.
    type Offered = (String, bool, Vec<(String, String, bool)>);

    fn models(view: &SettingsView) -> Vec<Offered> {
        let model = view.model.as_ref().unwrap();
        model
            .providers
            .iter()
            .map(|p| {
                let options = p
                    .models
                    .iter()
                    .map(|m| (m.value.clone(), m.label.clone(), m.chosen))
                    .collect();
                (p.name.clone(), p.chosen, options)
            })
            .collect()
    }

    fn owned(name: &str, chosen: bool, options: &[(&str, &str, bool)]) -> Offered {
        let options = options
            .iter()
            .map(|(v, l, c)| ((*v).to_owned(), (*l).to_owned(), *c))
            .collect();
        (name.to_owned(), chosen, options)
    }

    #[test]
    fn models_are_offered_for_the_chosen_agent_by_provider() {
        let view = settings_view(&config(""), &detected(), Path::new(HOME));
        assert!(view.model.is_none(), "no agent, so no models");

        let view = settings_view(&config("agent = \"claude\""), &detected(), Path::new(HOME));
        let model = view.model.as_ref().unwrap();
        assert_eq!(
            (model.agent, model.default, model.listed, model.hint),
            (AgentKind::Claude, true, true, "Another model")
        );
        assert_eq!(
            models(&view),
            [owned(
                "Anthropic",
                true,
                &[
                    ("opus", "opus", false),
                    ("sonnet", "sonnet", false),
                    ("haiku", "haiku", false)
                ]
            )]
        );

        let text = "agent = \"opencode\"\nmodels.opencode = \"ollama/gemma4:e4b\"";
        let view = settings_view(&config(text), &detected(), Path::new(HOME));
        assert_eq!(
            models(&view),
            [
                owned(
                    "opencode",
                    false,
                    &[("opencode/big-pickle", "big-pickle", false)]
                ),
                owned(
                    "ollama",
                    true,
                    &[
                        ("ollama/gemma4:e4b", "gemma4:e4b", true),
                        ("ollama/qwen3", "qwen3", false)
                    ]
                ),
            ]
        );
        assert_eq!(
            summaries(&view)[0],
            ("Agent", "opencode · ollama/gemma4:e4b", false)
        );
        let model = view.model.as_ref().unwrap();
        assert!(!model.default);
        let gemma = &model.providers[1].models[0];
        assert_eq!(gemma.sub.as_deref(), Some("ollama/gemma4:e4b"));
        assert_eq!(model.providers[1].label, "ollama");
    }

    #[test]
    fn a_typed_model_shows_even_when_the_agent_lists_none() {
        let view = settings_view(&config("agent = \"gemini\""), &detected(), Path::new(HOME));
        let model = view.model.as_ref().unwrap();
        assert!(!model.listed);
        assert!(model.providers.is_empty());
        assert_eq!(model.hint, "Model name, as --model takes it");

        let text = "agent = \"gemini\"\nmodels.gemini = \"gemini-3.1-pro\"";
        let view = settings_view(&config(text), &detected(), Path::new(HOME));
        assert!(!view.model.as_ref().unwrap().listed);
        assert_eq!(
            models(&view),
            [owned(
                "Google",
                true,
                &[("gemini-3.1-pro", "gemini-3.1-pro", true)]
            )]
        );

        let text = "agent = \"claude\"\nmodels.claude = \"claude-opus-4-1\"";
        let view = settings_view(&config(text), &detected(), Path::new(HOME));
        let options = &models(&view)[0].2;
        assert_eq!(
            options[0],
            (
                "claude-opus-4-1".to_owned(),
                "claude-opus-4-1".to_owned(),
                true
            )
        );
        assert_eq!(options.len(), 4);

        let text = "agent = \"opencode\"\nmodels.opencode = \"local\"";
        let view = settings_view(&config(text), &detected(), Path::new(HOME));
        assert_eq!(models(&view)[0].0, "", "a name without a provider has none");
        assert!(models(&view)[0].1);
        let other = &view.model.as_ref().unwrap().providers[0];
        assert_eq!(other.label, "Other");
        assert_eq!(other.models[0].sub, None, "the label is the whole name");
    }

    fn summaries(view: &SettingsView) -> Vec<(&str, &str, bool)> {
        view.groups
            .iter()
            .flat_map(|g| &g.sections)
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
                ("NVD key", "Not set", false),
            ]
        );
        assert_eq!(view.headline, "1 setting needs you");
        assert!(!view.ready);
        let titles: Vec<&str> = view.groups.iter().map(|g| g.title).collect();
        assert_eq!(titles, ["Sweeps", "Targets", "Advisories"]);
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
        assert!(view.nvd_rates[1].applies, "a key in the Keychain");
        assert!(!view.nvd_rates[0].applies);
        assert_eq!(view.headline, "Ready to sweep");
        assert!(view.ready);
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
