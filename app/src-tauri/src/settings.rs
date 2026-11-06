//! Settings, shown inside the popover: commands that return the core's [`SettingsView`], and
//! change the config through [`save_setting`], returning the view as it now is so the UI
//! shows a change without asking again.
//!
//! Detection takes about two seconds (the login shell and `gh` twice), so it runs once, when
//! the app starts, and again only when the user asks; every view reuses it. A missing config
//! reads as the default one, which the first change writes. The commands marked `async` are
//! plain blocking functions that Tauri runs off the main thread; none of them is a future.

use std::sync::Mutex;
use std::sync::MutexGuard;
use std::sync::PoisonError;
use std::thread;

use ancient_protector_core::Config;
use ancient_protector_core::Detected;
use ancient_protector_core::NvdAccess;
use ancient_protector_core::Setting;
use ancient_protector_core::SettingsView;
use ancient_protector_core::detect;
use ancient_protector_core::save_setting;
use ancient_protector_core::settings_view;
use tauri::AppHandle;
use tauri::Manager as _;
use tauri_plugin_dialog::DialogExt as _;

use crate::runner;
use crate::runner::Runner;
use crate::tray;

/// What detection found, once it has run.
#[derive(Debug, Default)]
pub(crate) struct Detection(Mutex<Option<Detected>>);

impl Detection {
    /// Detected data is replaced whole, so a poisoned lock still holds a valid value.
    fn lock(&self) -> MutexGuard<'_, Option<Detected>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// When detection runs again.
#[derive(Debug, Clone, Copy)]
enum Fresh {
    /// Only when it has not run yet.
    IfMissing,
    /// Now, as the user asked.
    Now,
}

/// Runs detection in the background as the app starts, so the settings open at once. Any
/// macOS prompt it raises (Documents access, the Keychain) shows before the popover opens.
pub(crate) fn detect_at_start(app: AppHandle) {
    thread::spawn(move || drop(detected(&app, Fresh::IfMissing)));
}

/// The settings as they are now.
#[tauri::command(async)]
#[expect(
    clippy::needless_pass_by_value,
    reason = "Tauri hands command arguments over by value"
)]
pub(crate) fn settings_data(app: AppHandle) -> Result<SettingsView, String> {
    let config = read_config(&app)?;
    Ok(view(&app, &config, Fresh::IfMissing))
}

/// Detects the Mac again, for a tool installed or a repository created since.
#[tauri::command(async)]
#[expect(
    clippy::needless_pass_by_value,
    reason = "Tauri hands command arguments over by value"
)]
pub(crate) fn detect_again(app: AppHandle) -> Result<SettingsView, String> {
    let config = read_config(&app)?;
    Ok(view(&app, &config, Fresh::Now))
}

/// Applies one change to `config.toml`, refreshes the popover and the tray icon, and returns
/// the settings as they now are.
#[tauri::command(async)]
#[expect(
    clippy::needless_pass_by_value,
    reason = "Tauri hands command arguments over by value"
)]
pub(crate) fn save(app: AppHandle, setting: Setting) -> Result<SettingsView, String> {
    let config = apply(&app, &setting)?;
    Ok(view(&app, &config, Fresh::IfMissing))
}

/// Lets the user pick a folder to search for lockfiles and adds it. `None` when the user
/// cancels. The popover is held open while the system's picker has the focus.
#[tauri::command(async)]
#[expect(
    clippy::needless_pass_by_value,
    reason = "Tauri hands command arguments over by value"
)]
pub(crate) fn add_folder(app: AppHandle) -> Result<Option<SettingsView>, String> {
    let picked = {
        let _held = tray::hold_popover(&app);
        app.dialog()
            .file()
            .set_title("Add a folder to search for lockfiles")
            .blocking_pick_folder()
            .and_then(|picked| picked.into_path().ok())
    };
    let Some(dir) = picked else {
        return Ok(None);
    };
    let dir = dir
        .to_str()
        .ok_or_else(|| format!("{} is not UTF-8, which config.toml needs", dir.display()))?
        .to_owned();
    let config = apply(&app, &Setting::AddFolder { dir })?;
    Ok(Some(view(&app, &config, Fresh::IfMissing)))
}

/// Stores the NVD API key in the Keychain, and returns the settings as they now are.
#[tauri::command(async)]
#[expect(
    clippy::needless_pass_by_value,
    reason = "Tauri hands command arguments over by value"
)]
pub(crate) fn set_nvd_key(app: AppHandle, key: String) -> Result<SettingsView, String> {
    NvdAccess::save_to_keychain(&key).map_err(|e| e.to_string())?;
    if let Some(found) = app.state::<Detection>().lock().as_mut() {
        found.nvd_key = true;
    }
    let config = read_config(&app)?;
    Ok(view(&app, &config, Fresh::IfMissing))
}

fn read_config(app: &AppHandle) -> Result<Config, String> {
    let runner = app.state::<Runner>();
    Config::load_or_default(&runner.data_dir().config_file(), runner.home()).map_err(|e| {
        format!(
            "{} Fix config.toml by hand, or delete it to start from the default.",
            error_chain(&e)
        )
    })
}

fn apply(app: &AppHandle, setting: &Setting) -> Result<Config, String> {
    let runner = app.state::<Runner>();
    let config =
        save_setting(runner.data_dir(), runner.home(), setting).map_err(|e| error_chain(&e))?;
    runner::changed(app);
    Ok(config)
}

fn view(app: &AppHandle, config: &Config, fresh: Fresh) -> SettingsView {
    let found = detected(app, fresh);
    let found = found.as_ref().expect("detected() leaves a value");
    settings_view(config, found, app.state::<Runner>().home())
}

/// What detection found, detecting first when `fresh` says so. The lock is held while
/// detecting, so a view asked for while detection runs waits for it instead of running a
/// second one.
fn detected(app: &AppHandle, fresh: Fresh) -> MutexGuard<'_, Option<Detected>> {
    let mut found = app.state::<Detection>().inner().lock();
    if found.is_none() || matches!(fresh, Fresh::Now) {
        // A prompt detection raises would take the focus and hide the popover.
        let _held = tray::hold_popover(app);
        *found = Some(detect(app.state::<Runner>().home()));
    }
    found
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
