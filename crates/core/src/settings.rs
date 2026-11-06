//! Changes the settings make to `config.toml`.
//!
//! Each change is one [`Setting`], applied to the file as the user left it, so comments and
//! layout stay. Before it is written, the changed text goes through the same parsing and
//! checks as [`Config::load`]; a change that would make the config invalid is refused with
//! the reason, and the file is untouched. A missing config starts from the default one.

use std::fs;
use std::io;
use std::io::Write as _;
use std::path::Path;
use std::path::PathBuf;
use std::process;
use std::sync::Mutex;
use std::sync::PoisonError;

use serde::Deserialize;
use toml_edit::Array;
use toml_edit::ArrayOfTables;
use toml_edit::DocumentMut;
use toml_edit::Item;
use toml_edit::Table;
use toml_edit::value;

use crate::agent::AgentKind;
use crate::config::Config;
use crate::config::DEFAULT_CONFIG;
use crate::config::LoadConfigError;
use crate::config::expand_home;
use crate::paths::DataDir;

/// Held while a change is read, applied and written, so changes in this process apply one
/// after another.
static SAVING: Mutex<()> = Mutex::new(());

/// One change to the config.
#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Setting {
    /// The agent sweeps and fixes run with; `None` unsets it.
    Agent {
        /// The agent.
        agent: Option<AgentKind>,
    },
    /// Sweep every this many hours; `None` sweeps only on demand.
    Schedule {
        /// The interval in hours.
        every_hours: Option<u32>,
    },
    /// How far back the first advisory download goes: `all`, or a date like `2025-01-31`.
    History {
        /// The value of `since`.
        since: String,
    },
    /// Adds a folder searched for lockfiles, unless it is there already.
    AddFolder {
        /// The folder, absolute or starting with `~/`.
        dir: String,
    },
    /// Removes a folder searched for lockfiles, however the file spells it (`~/code` or
    /// `/Users/me/code`).
    RemoveFolder {
        /// The folder, absolute or starting with `~/`.
        dir: String,
    },
    /// Adds a repository to sweep, unless it is there already (GitHub ignores case).
    AddRepo {
        /// As `owner/name`; spaces around it are dropped.
        repo: String,
    },
    /// Stops sweeping a repository.
    RemoveRepo {
        /// As `owner/name`.
        repo: String,
    },
    /// Adds a server reached through an alias from `~/.ssh/config`, named after the alias.
    AddServer {
        /// The ssh alias.
        ssh: String,
    },
    /// Removes the server with this name.
    RemoveServer {
        /// Its name.
        name: String,
    },
}

/// Applies `setting` to the config in `data_dir`, writes it, and returns the config as the
/// file now has it.
///
/// # Errors
///
/// Fails when the config cannot be read or is not TOML, when the change would make it invalid
/// (the error lists every problem, and nothing is written), or when it cannot be written.
pub fn save_setting(
    data_dir: &DataDir,
    home: &Path,
    setting: &Setting,
) -> Result<Config, SaveSettingError> {
    // Read, edit and write are one step: two changes at once (two quick clicks) would each
    // edit the same text, and the later write would drop the earlier change. A poisoned lock
    // guards no data, so it is used as it is.
    let _saving = SAVING.lock().unwrap_or_else(PoisonError::into_inner);
    let path = data_dir.config_file();
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == io::ErrorKind::NotFound => DEFAULT_CONFIG.to_owned(),
        Err(source) => return Err(SaveSettingError::Read { path, source }),
    };
    let mut doc: DocumentMut = text.parse().map_err(|source| SaveSettingError::Edit {
        path: path.clone(),
        source,
    })?;
    apply(&mut doc, setting, home).map_err(|table| SaveSettingError::Inline {
        path: path.clone(),
        table,
    })?;
    let changed = doc.to_string();
    let config = Config::from_text(&path, &changed, home)?;
    write(&path, &changed)?;
    Ok(config)
}

/// Applies `setting` to `doc`. Fails with the table's name when the file writes it inline
/// (`github = { repos = [...] }`), which this does not edit.
fn apply(doc: &mut DocumentMut, setting: &Setting, home: &Path) -> Result<(), &'static str> {
    match setting {
        Setting::Agent { agent: Some(agent) } => {
            let fresh = !doc.contains_key("agent");
            doc["agent"] = value(agent.binary());
            if fresh {
                keep_opening_comments_on_top(doc, "agent");
            }
        }
        Setting::Agent { agent: None } => {
            restore_opening_comments(doc, "agent");
            doc.remove("agent");
        }
        Setting::Schedule { every_hours } => {
            let schedule = table(doc, "schedule")?;
            match every_hours {
                Some(hours) => schedule["every_hours"] = value(i64::from(*hours)),
                None => drop(schedule.remove("every_hours")),
            }
        }
        Setting::History { since } => {
            table(doc, "history")?["since"] = value(since.as_str());
        }
        Setting::AddFolder { dir } => {
            let same = |entry: &str| expand_home(entry, home) == expand_home(dir, home);
            add(array(table(doc, "mac")?, "project_dirs"), dir, same);
        }
        Setting::RemoveFolder { dir } => {
            let dirs = array(table(doc, "mac")?, "project_dirs");
            dirs.retain(|v| {
                v.as_str()
                    .is_none_or(|e| expand_home(e, home) != expand_home(dir, home))
            });
        }
        Setting::AddRepo { repo } => {
            let repo = repo.trim();
            add(array(table(doc, "github")?, "repos"), repo, |e| {
                e.eq_ignore_ascii_case(repo)
            });
        }
        Setting::RemoveRepo { repo } => {
            let repos = array(table(doc, "github")?, "repos");
            repos.retain(|v| v.as_str().is_none_or(|e| !e.eq_ignore_ascii_case(repo)));
        }
        Setting::AddServer { ssh } => {
            let mut server = Table::new();
            server["name"] = value(ssh.as_str());
            server["ssh"] = value(ssh.as_str());
            servers(doc)?.push(server);
        }
        Setting::RemoveServer { name } => {
            let servers = servers(doc)?;
            servers.retain(|t| t.get("name").and_then(Item::as_str) != Some(name));
            if servers.is_empty() {
                doc.remove("servers");
            }
        }
    }
    Ok(())
}

/// Undoes [`keep_opening_comments_on_top`] before `key` is removed: the opening comments it
/// moved onto the key go back above the first table, so removing the key keeps them.
fn restore_opening_comments(doc: &mut DocumentMut, key: &str) {
    let Some(opening) = doc
        .as_table()
        .key(key)
        .and_then(|k| k.leaf_decor().prefix())
        .and_then(|p| p.as_str())
        .filter(|p| !p.trim().is_empty())
        .map(str::to_owned)
    else {
        return;
    };
    let Some(first) = doc
        .as_table_mut()
        .iter_mut()
        .find_map(|(_, item)| item.as_table_mut())
    else {
        return;
    };
    let own = first
        .decor()
        .prefix()
        .and_then(|p| p.as_str())
        .unwrap_or_default()
        .to_owned();
    first.decor_mut().set_prefix(format!("{opening}{own}"));
}

/// A new top-level key goes above every table, so above the file's opening comments, which
/// `toml_edit` keeps in the first table's prefix along with that table's own comment. This
/// moves the opening block, up to the last blank line, above the key; the table keeps the
/// comment right above its header.
fn keep_opening_comments_on_top(doc: &mut DocumentMut, key: &str) {
    let Some(first) = doc
        .as_table_mut()
        .iter_mut()
        .find_map(|(_, item)| item.as_table_mut())
    else {
        return;
    };
    let Some(prefix) = first
        .decor()
        .prefix()
        .and_then(|p| p.as_str())
        .map(str::to_owned)
    else {
        return;
    };
    let Some(split) = prefix.rfind("\n\n") else {
        return;
    };
    let (opening, own) = prefix.split_at(split + 1);
    let opening = opening.to_owned();
    first.decor_mut().set_prefix(own.to_owned());
    if let Some(mut key) = doc.as_table_mut().key_mut(key) {
        key.leaf_decor_mut().set_prefix(opening);
    }
}

/// The table `name`, created when missing. Anything else under that name (an inline table, or
/// a hand-edited `mac = 1`) is refused, not replaced: an inline table is valid, and replacing
/// it would drop the user's values.
fn table<'a>(doc: &'a mut DocumentMut, name: &'static str) -> Result<&'a mut Table, &'static str> {
    doc.entry(name)
        .or_insert_with(|| Item::Table(Table::new()))
        .as_table_mut()
        .ok_or(name)
}

/// The array `name` in `table`, created when missing. One that is not an array (`repos = 1`)
/// is replaced; the checks before writing refuse that file anyway, so nothing is lost.
fn array<'a>(table: &'a mut Table, name: &str) -> &'a mut Array {
    let item = table.entry(name).or_insert_with(|| value(Array::new()));
    if !item.is_array() {
        *item = value(Array::new());
    }
    item.as_array_mut().expect("made an array just above")
}

/// Appends `entry` unless an entry is `same` as it.
fn add(array: &mut Array, entry: &str, same: impl Fn(&str) -> bool) {
    if !array.iter().any(|v| v.as_str().is_some_and(&same)) {
        array.push(entry);
    }
}

/// The `[[servers]]` tables, created when missing; refused when the file writes them another
/// way (`servers = [{ ... }]`), as in [`table`].
fn servers(doc: &mut DocumentMut) -> Result<&mut ArrayOfTables, &'static str> {
    doc.entry("servers")
        .or_insert_with(|| Item::ArrayOfTables(ArrayOfTables::new()))
        .as_array_of_tables_mut()
        .ok_or("servers")
}

/// Writes `text` to a temporary name, syncs it, and renames it over `path`, so neither a
/// reader nor a crash sees half a config.
fn write(path: &Path, text: &str) -> Result<(), SaveSettingError> {
    let write_err = |source| SaveSettingError::Write {
        path: path.to_owned(),
        source,
    };
    let dir = path.parent().expect("the config file has a folder");
    fs::create_dir_all(dir).map_err(write_err)?;
    // Named per process, so a CLI or a second app saving at the same moment never writes into
    // this file; within a process, `SAVING` keeps saves apart.
    let partial = dir.join(format!(".config.toml.{}.partial", process::id()));
    fs::File::create(&partial)
        .and_then(|mut file| {
            file.write_all(text.as_bytes())?;
            file.sync_data()
        })
        .and_then(|()| fs::rename(&partial, path))
        .map_err(write_err)
}

/// Error from changing the config.
#[derive(Debug, thiserror::Error)]
pub enum SaveSettingError {
    /// The config could not be read.
    #[error("cannot read {}", path.display())]
    Read {
        /// The file.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: io::Error,
    },
    /// The config is not TOML, so it cannot be edited in place.
    #[error("cannot edit {}; fix it by hand first", path.display())]
    Edit {
        /// The file.
        path: PathBuf,
        /// The parser's error, with line and column.
        #[source]
        source: toml_edit::TomlError,
    },
    /// The table the change edits is written inline; nothing was written.
    #[error(
        "{} writes {table} inline; change it there by hand, or rewrite it as a [{table}] section",
        path.display()
    )]
    Inline {
        /// The file.
        path: PathBuf,
        /// The table.
        table: &'static str,
    },
    /// The change would make the config invalid; nothing was written.
    #[error(transparent)]
    Invalid(#[from] LoadConfigError),
    /// The config could not be written.
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
    use crate::config::Schedule;

    use super::*;

    #[expect(
        clippy::needless_pass_by_value,
        reason = "the tests read better passing each setting whole"
    )]
    fn save(data_dir: &DataDir, setting: Setting) -> Result<Config, SaveSettingError> {
        save_setting(data_dir, Path::new("/home"), &setting)
    }

    #[test]
    fn changes_keep_the_comments_and_start_from_the_default_config() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = DataDir::new(tmp.path());
        let config = save(
            &data_dir,
            Setting::Agent {
                agent: Some(AgentKind::Claude),
            },
        )
        .unwrap();
        assert_eq!(config.agent, Some(AgentKind::Claude));

        save(
            &data_dir,
            Setting::Schedule {
                every_hours: Some(6),
            },
        )
        .unwrap();
        save(
            &data_dir,
            Setting::History {
                since: "2025-01-01".to_owned(),
            },
        )
        .unwrap();
        for dir in ["~/code", "/Users/me/src"] {
            save(
                &data_dir,
                Setting::AddFolder {
                    dir: dir.to_owned(),
                },
            )
            .unwrap();
        }
        save(&data_dir, repo_added("o/r")).unwrap();
        let server = Setting::AddServer {
            ssh: "web".to_owned(),
        };
        let config = save(&data_dir, server).unwrap();
        assert_eq!(config.schedule, Schedule::EveryHours(6.try_into().unwrap()));
        assert_eq!(
            config.project_dirs,
            [PathBuf::from("/home/code"), PathBuf::from("/Users/me/src")]
        );
        assert_eq!(config.repos.len(), 1);
        assert_eq!(config.servers.len(), 1);

        let text = fs::read_to_string(data_dir.config_file()).unwrap();
        assert!(
            text.starts_with("# Ancient Protector configuration."),
            "{text}"
        );
        let agent = text.find("agent = \"claude\"").unwrap();
        assert!(
            agent > text.find("# The coding agent").unwrap(),
            "below the opening: {text}"
        );
        assert!(
            agent < text.find("# Sweep automatically").unwrap(),
            "{text}"
        );
        let header = text.find("[schedule]").unwrap();
        assert!(
            text[header..].starts_with("[schedule]\nevery_hours = 6\n"),
            "{text}"
        );
        assert!(
            text.contains("# Sweep automatically every N hours"),
            "comments stay: {text}"
        );
        assert!(text.contains("every_hours = 6"), "{text}");
        assert!(text.contains("agent = \"claude\""), "{text}");

        let config = save(
            &data_dir,
            Setting::RemoveServer {
                name: "web".to_owned(),
            },
        )
        .unwrap();
        assert_eq!(config.servers.len(), 0);
        assert!(
            !fs::read_to_string(data_dir.config_file())
                .unwrap()
                .contains("name = \"web\""),
            "the server's table is gone (the comments keep their example)"
        );
        let config = save(&data_dir, Setting::Schedule { every_hours: None }).unwrap();
        assert_eq!(config.schedule, Schedule::Manual);
        let config = save(&data_dir, Setting::Agent { agent: None }).unwrap();
        assert_eq!(config.agent, None);
    }

    fn repo_added(repo: &str) -> Setting {
        Setting::AddRepo {
            repo: repo.to_owned(),
        }
    }

    #[test]
    fn folders_and_repos_are_added_once_and_removed_however_they_are_spelled() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = DataDir::new(tmp.path());
        let folder = |dir: &str| Setting::AddFolder {
            dir: dir.to_owned(),
        };
        save(&data_dir, folder("~/code")).unwrap();
        save(&data_dir, folder("/Users/me/src")).unwrap();
        let config = save(&data_dir, folder("/home/code")).unwrap();
        assert_eq!(
            config.project_dirs,
            [PathBuf::from("/home/code"), PathBuf::from("/Users/me/src")],
            "/home/code is ~/code"
        );
        let config = save(
            &data_dir,
            Setting::RemoveFolder {
                dir: "/home/code".to_owned(),
            },
        )
        .unwrap();
        assert_eq!(config.project_dirs, [PathBuf::from("/Users/me/src")]);

        save(&data_dir, repo_added(" o/r ")).unwrap();
        let config = save(&data_dir, repo_added("O/R")).unwrap();
        assert_eq!(config.repos.len(), 1, "GitHub ignores case");
        save(&data_dir, repo_added("o/s")).unwrap();
        let config = save(
            &data_dir,
            Setting::RemoveRepo {
                repo: "O/r".to_owned(),
            },
        )
        .unwrap();
        let repos: Vec<String> = config.repos.iter().map(ToString::to_string).collect();
        assert_eq!(repos, ["o/s"]);
    }

    #[test]
    fn unsetting_the_agent_keeps_the_opening_comments() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = DataDir::new(tmp.path());
        let agent = Some(AgentKind::Claude);
        save(&data_dir, Setting::Agent { agent }).unwrap();
        save(&data_dir, Setting::Agent { agent: None }).unwrap();
        let text = fs::read_to_string(data_dir.config_file()).unwrap();
        assert!(
            text.starts_with("# Ancient Protector configuration."),
            "{text}"
        );
        assert!(text.contains("# The coding agent"), "{text}");
        save(&data_dir, Setting::Agent { agent }).unwrap();
        let again = fs::read_to_string(data_dir.config_file()).unwrap();
        assert!(
            again.starts_with("# Ancient Protector configuration."),
            "{again}"
        );
    }

    #[test]
    fn inline_tables_are_refused_not_replaced() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = DataDir::new(tmp.path());
        let inline = "github = { repos = [\"a/b\"] }\n\
                      mac = { project_dirs = [\"/x\"] }\n\
                      schedule = { every_hours = 2 }\n\
                      servers = [{ name = \"web\", ssh = \"web\" }]\n";
        fs::create_dir_all(data_dir.config_file().parent().unwrap()).unwrap();
        fs::write(data_dir.config_file(), inline).unwrap();
        for (change, table) in [
            (repo_added("c/d"), "github"),
            (
                Setting::AddFolder {
                    dir: "/y".to_owned(),
                },
                "mac",
            ),
            (Setting::Schedule { every_hours: None }, "schedule"),
            (
                Setting::AddServer {
                    ssh: "db".to_owned(),
                },
                "servers",
            ),
            (
                Setting::RemoveServer {
                    name: "web".to_owned(),
                },
                "servers",
            ),
        ] {
            let err = save(&data_dir, change).unwrap_err();
            assert!(
                matches!(err, SaveSettingError::Inline { table: t, .. } if t == table),
                "{err:?}"
            );
        }
        assert_eq!(fs::read_to_string(data_dir.config_file()).unwrap(), inline);
    }

    #[test]
    fn changes_made_at_once_all_land() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = DataDir::new(tmp.path());
        std::thread::scope(|scope| {
            for i in 0..8 {
                let data_dir = &data_dir;
                scope.spawn(move || save(data_dir, repo_added(&format!("o/r{i}"))).unwrap());
            }
        });
        let config = Config::load_or_default(&data_dir.config_file(), Path::new("/home")).unwrap();
        assert_eq!(config.repos.len(), 8, "no change overwrote another");
        let leftovers: Vec<_> = fs::read_dir(data_dir.config_file().parent().unwrap())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().ends_with(".partial"))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
    }

    #[test]
    fn an_invalid_change_is_refused_and_nothing_is_written() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = DataDir::new(tmp.path());
        save(&data_dir, repo_added("o/r")).unwrap();
        let before = fs::read_to_string(data_dir.config_file()).unwrap();

        for bad in [
            repo_added("not a repo"),
            Setting::Schedule {
                every_hours: Some(0),
            },
            Setting::History {
                since: "yesterday".to_owned(),
            },
            Setting::AddFolder {
                dir: "relative/dir".to_owned(),
            },
            Setting::AddServer {
                ssh: "-oProxyCommand=x".to_owned(),
            },
            Setting::AddServer {
                ssh: "web:22".to_owned(),
            },
        ] {
            let err = save(&data_dir, bad).unwrap_err();
            assert!(matches!(err, SaveSettingError::Invalid(_)), "{err:?}");
        }
        assert_eq!(fs::read_to_string(data_dir.config_file()).unwrap(), before);

        fs::write(data_dir.config_file(), "agent = ").unwrap();
        let err = save(&data_dir, Setting::Agent { agent: None }).unwrap_err();
        assert!(matches!(err, SaveSettingError::Edit { .. }), "{err:?}");
    }
}
