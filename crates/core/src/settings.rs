//! Changes the settings window makes to `config.toml`.
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
use crate::paths::DataDir;

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
    /// The folders searched for lockfiles, replacing the list.
    ProjectDirs {
        /// The folders, absolute or starting with `~/`.
        dirs: Vec<String>,
    },
    /// The repositories swept, replacing the list.
    Repos {
        /// Each as `owner/name`.
        repos: Vec<String>,
    },
    /// Adds a server reached through an alias from `~/.ssh/config`.
    AddServer {
        /// Its name in reports.
        name: String,
        /// The ssh alias.
        ssh: String,
        /// Folders on it searched for lockfiles.
        dirs: Vec<String>,
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
    apply(&mut doc, setting);
    let changed = doc.to_string();
    let config = Config::from_text(&path, &changed, home)?;
    write(&path, &changed)?;
    Ok(config)
}

fn apply(doc: &mut DocumentMut, setting: &Setting) {
    match setting {
        Setting::Agent { agent: Some(agent) } => {
            let fresh = !doc.contains_key("agent");
            doc["agent"] = value(agent.binary());
            if fresh {
                keep_opening_comments_on_top(doc, "agent");
            }
        }
        Setting::Agent { agent: None } => {
            doc.remove("agent");
        }
        Setting::Schedule { every_hours } => {
            let schedule = table(doc, "schedule");
            match every_hours {
                Some(hours) => schedule["every_hours"] = value(i64::from(*hours)),
                None => drop(schedule.remove("every_hours")),
            }
        }
        Setting::History { since } => {
            table(doc, "history")["since"] = value(since.as_str());
        }
        Setting::ProjectDirs { dirs } => {
            table(doc, "mac")["project_dirs"] = value(Array::from_iter(dirs));
        }
        Setting::Repos { repos } => {
            table(doc, "github")["repos"] = value(Array::from_iter(repos));
        }
        Setting::AddServer { name, ssh, dirs } => {
            let mut server = Table::new();
            server["name"] = value(name.as_str());
            server["ssh"] = value(ssh.as_str());
            if !dirs.is_empty() {
                server["dirs"] = value(Array::from_iter(dirs));
            }
            servers(doc).push(server);
        }
        Setting::RemoveServer { name } => {
            servers(doc).retain(|t| t.get("name").and_then(Item::as_str) != Some(name));
            if servers(doc).is_empty() {
                doc.remove("servers");
            }
        }
    }
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

/// The table `name`, created when missing. One that is not a table (a hand-edited `mac = 1`)
/// is replaced; the checks before writing would have refused that file anyway.
fn table<'a>(doc: &'a mut DocumentMut, name: &str) -> &'a mut Table {
    let item = doc.entry(name).or_insert_with(|| Item::Table(Table::new()));
    if !item.is_table() {
        *item = Item::Table(Table::new());
    }
    item.as_table_mut().expect("made a table just above")
}

fn servers(doc: &mut DocumentMut) -> &mut ArrayOfTables {
    let item = doc
        .entry("servers")
        .or_insert_with(|| Item::ArrayOfTables(ArrayOfTables::new()));
    if !item.is_array_of_tables() {
        *item = Item::ArrayOfTables(ArrayOfTables::new());
    }
    item.as_array_of_tables_mut()
        .expect("made an array of tables just above")
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
    let partial = dir.join(".config.toml.partial");
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
        let dirs = vec!["~/code".to_owned(), "/Users/me/src".to_owned()];
        save(&data_dir, Setting::ProjectDirs { dirs }).unwrap();
        save(
            &data_dir,
            Setting::Repos {
                repos: vec!["o/r".to_owned()],
            },
        )
        .unwrap();
        let server = Setting::AddServer {
            name: "web".to_owned(),
            ssh: "web".to_owned(),
            dirs: vec!["/srv/app".to_owned()],
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

    #[test]
    fn an_invalid_change_is_refused_and_nothing_is_written() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = DataDir::new(tmp.path());
        save(
            &data_dir,
            Setting::Repos {
                repos: vec!["o/r".to_owned()],
            },
        )
        .unwrap();
        let before = fs::read_to_string(data_dir.config_file()).unwrap();

        for bad in [
            Setting::Repos {
                repos: vec!["not a repo".to_owned()],
            },
            Setting::Schedule {
                every_hours: Some(0),
            },
            Setting::History {
                since: "yesterday".to_owned(),
            },
            Setting::ProjectDirs {
                dirs: vec!["relative/dir".to_owned()],
            },
            Setting::AddServer {
                name: "../x".to_owned(),
                ssh: "x".to_owned(),
                dirs: vec![],
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
