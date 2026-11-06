//! Settings, shown inside the popover: what the Mac has, what the config says, and changes
//! to it.
//!
//! Detection and config edits are the core's (`detect`, `save_setting`); this module turns
//! them into commands. A missing config reads as the default one, which the first change
//! writes. The commands marked `async` are plain blocking
//! functions that Tauri runs off the main thread, since detection runs the login shell and
//! `gh`; none of them is a future.

use std::path::PathBuf;

use ancient_protector_core::Config;
use ancient_protector_core::Detected;
use ancient_protector_core::History;
use ancient_protector_core::NvdAccess;
use ancient_protector_core::Schedule;
use ancient_protector_core::Setting;
use ancient_protector_core::SshConn;
use ancient_protector_core::detect;
use ancient_protector_core::save_setting;
use serde::Serialize;
use tauri::AppHandle;
use tauri::Manager as _;
use tauri::State;
use tauri_plugin_dialog::DialogExt as _;

use crate::runner;
use crate::runner::Runner;
use crate::tray;

/// What the settings view shows.
#[derive(Debug, Serialize)]
pub(crate) struct SettingsData {
    detected: Detected,
    /// The config as the file has it; `None` when it cannot be read.
    config: Option<Current>,
    /// Why the config cannot be read.
    problem: Option<String>,
    /// Where it is.
    path: PathBuf,
}

/// The config's values, as the settings view shows them.
#[derive(Debug, Serialize)]
struct Current {
    agent: Option<String>,
    every_hours: Option<u32>,
    since: String,
    project_dirs: Vec<PathBuf>,
    repos: Vec<String>,
    servers: Vec<ServerView>,
}

#[derive(Debug, Serialize)]
struct ServerView {
    name: String,
    /// How it is reached: the alias, or `user@host:port`.
    reach: String,
    dirs: Vec<String>,
}

impl Current {
    fn of(config: &Config) -> Self {
        Self {
            agent: config.agent.map(|a| a.binary().to_owned()),
            every_hours: match config.schedule {
                Schedule::Manual => None,
                Schedule::EveryHours(hours) => Some(hours.get()),
            },
            since: match config.history {
                History::All => "all".to_owned(),
                History::Since(since) => since.date().to_string(),
            },
            project_dirs: config.project_dirs.clone(),
            repos: config.repos.iter().map(ToString::to_string).collect(),
            servers: config.servers.iter().map(ServerView::of).collect(),
        }
    }
}

impl ServerView {
    fn of(server: &ancient_protector_core::Server) -> Self {
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
        Self {
            name: server.name.to_string(),
            reach,
            dirs: server.dirs.iter().map(|d| d.as_str().to_owned()).collect(),
        }
    }
}

/// Detects the Mac and reads the config, holding the popover open: detection can raise a
/// macOS prompt (Documents access, the Keychain) that would otherwise hide it.
#[tauri::command(async)]
#[expect(
    clippy::needless_pass_by_value,
    reason = "Tauri hands command arguments over by value"
)]
pub(crate) fn settings_data(app: AppHandle, runner: State<'_, Runner>) -> SettingsData {
    let _held = tray::hold_popover(&app);
    let path = runner.data_dir().config_file();
    let (config, problem) = match Config::load_or_default(&path, runner.home()) {
        Ok(config) => (Some(Current::of(&config)), None),
        Err(e) => (None, Some(error_chain(&e))),
    };
    SettingsData {
        detected: detect(runner.home()),
        config,
        problem,
        path,
    }
}

/// Applies one change to `config.toml`, and refreshes the popover and the tray icon.
#[tauri::command(async)]
#[expect(
    clippy::needless_pass_by_value,
    reason = "Tauri hands command arguments over by value"
)]
pub(crate) fn save(app: AppHandle, setting: Setting) -> Result<(), String> {
    let runner = app.state::<Runner>();
    save_setting(runner.data_dir(), runner.home(), &setting).map_err(|e| error_chain(&e))?;
    runner::changed(&app);
    Ok(())
}

/// Stores the NVD API key in the Keychain.
#[tauri::command(async)]
#[expect(
    clippy::needless_pass_by_value,
    reason = "Tauri hands command arguments over by value"
)]
pub(crate) fn set_nvd_key(key: String) -> Result<(), String> {
    NvdAccess::save_to_keychain(&key).map_err(|e| e.to_string())
}

/// Lets the user pick a folder, keeping the popover open while the system's picker has the
/// focus. `None` when the user cancels.
#[tauri::command(async)]
#[expect(
    clippy::needless_pass_by_value,
    reason = "Tauri hands command arguments over by value"
)]
pub(crate) fn pick_folder(app: AppHandle) -> Option<PathBuf> {
    let _held = tray::hold_popover(&app);
    app.dialog()
        .file()
        .set_title("Add a folder to search for lockfiles")
        .blocking_pick_folder()
        .and_then(|picked| picked.into_path().ok())
}

/// An error and its sources as one line, `outer: inner`.
fn error_chain(error: &dyn std::error::Error) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(inner) = source {
        text.push_str(&format!(": {inner}"));
        source = inner.source();
    }
    text
}
