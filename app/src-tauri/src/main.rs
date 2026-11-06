//! Ancient Protector's menu-bar app: a tray icon that shows the worst open finding, a popover
//! with each target's findings and a Sweep now button, sweeps on the configured schedule, and
//! a notification for each sweep that finds something new and critical or high.
//!
//! All the work is in `ancient-protector-core`; this crate wires it to Tauri. The popover is
//! the one window: it shows what [`overview`] returns and asks again on every `changed` event.
//! Settings are not edited here: the popover shows them and opens `config.toml` (decided
//! 2026-11-06), so the file stays the one source of truth that the CLI and agents also edit.

mod runner;
mod tray;

use std::path::PathBuf;
use std::process::Command;

use ancient_protector_core::Config;
use ancient_protector_core::DataDir;
use ancient_protector_core::FindingKey;
use ancient_protector_core::Latest;
use ancient_protector_core::ParseFindingKeyError;
use ancient_protector_core::latest;
use ancient_protector_core::plan_fix;
use jiff::Timestamp;
use serde::Serialize;
use tauri::ActivationPolicy;
use tauri::AppHandle;
use tauri::Manager as _;
use tauri::State;
use tauri::WindowEvent;
use tauri_plugin_autostart::MacosLauncher;

use crate::runner::Runner;
use crate::runner::Status;

fn main() {
    let home = std::env::home_dir().expect("a Mac user has a home directory");
    let data_dir = DataDir::for_home(&home);
    tauri::Builder::default()
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_autostart::init(
            MacosLauncher::LaunchAgent,
            None,
        ))
        .plugin(tauri_plugin_positioner::init())
        .manage(Runner::new(data_dir, home))
        .manage(tray::Popover::default())
        .invoke_handler(tauri::generate_handler![
            overview,
            sweep_now,
            open_config,
            quit,
            fix_preview,
            fix,
            dismiss
        ])
        .setup(|app| {
            // A menu-bar app: no Dock icon and no app menu (LSUIElement).
            app.set_activation_policy(ActivationPolicy::Accessory);
            tray::create(app.handle())?;
            runner::schedule(app.handle().clone());
            Ok(())
        })
        .on_window_event(|window, event| {
            // The popover closes when it loses focus, like a menu.
            if let WindowEvent::Focused(false) = event {
                tray::hide_on_blur(window);
            }
        })
        .run(tauri::generate_context!())
        .expect("the app's context and plugins are valid");
}

/// What the popover shows.
#[derive(Debug, Serialize)]
struct Overview {
    status: Status,
    /// Each configured target's open findings; empty when the config cannot be read.
    targets: Vec<Latest>,
    /// The chosen agent, when one is.
    agent: Option<String>,
    /// "manual" or "every N hours".
    schedule: String,
    /// The config file, which "Edit settings" opens.
    config: PathBuf,
    /// Why the config or the reports could not be read.
    problem: Option<String>,
}

// Async: Tauri runs it off the main thread, so reading every report never stalls the UI.
#[tauri::command(async)]
#[expect(
    clippy::needless_pass_by_value,
    reason = "Tauri hands command arguments over by value"
)]
fn overview(runner: State<'_, Runner>) -> Overview {
    let status = runner.status();
    let config_path = runner.data_dir().config_file();
    let config = match Config::load(&config_path, runner.home()) {
        Ok(config) => config,
        Err(e) => {
            return Overview {
                status,
                targets: Vec::new(),
                agent: None,
                schedule: String::new(),
                config: config_path,
                problem: Some(e.to_string()),
            };
        }
    };
    let (targets, problem) = match latest(runner.data_dir(), &config) {
        Ok(targets) => (targets, None),
        Err(e) => (Vec::new(), Some(e.to_string())),
    };
    let schedule = config.schedule.to_string();
    Overview {
        status,
        targets,
        agent: config.agent.map(|a| a.to_string()),
        schedule,
        config: config_path,
        problem,
    }
}

#[tauri::command]
#[expect(
    clippy::needless_pass_by_value,
    reason = "Tauri hands command arguments over by value"
)]
fn sweep_now(app: AppHandle) -> Result<(), String> {
    runner::start(&app).map_err(ToString::to_string)
}

/// Opens `config.toml` in the user's text editor, creating the default one first. Async, so
/// waiting for `open` never stalls the UI.
#[tauri::command(async)]
#[expect(
    clippy::needless_pass_by_value,
    reason = "Tauri hands command arguments over by value"
)]
fn open_config(runner: State<'_, Runner>) -> Result<(), String> {
    let path = runner.data_dir().config_file();
    if !path.exists() {
        runner.data_dir().init().map_err(|e| e.to_string())?;
    }
    let status = Command::new("open")
        .arg("-t")
        .arg(&path)
        .status()
        .map_err(|e| format!("cannot run open: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("open -t {} failed", path.display()))
    }
}

#[tauri::command]
#[expect(
    clippy::needless_pass_by_value,
    reason = "Tauri hands command arguments over by value"
)]
fn quit(app: AppHandle) {
    app.exit(0);
}

/// What the detail view shows before the user confirms a fix.
#[derive(Debug, Serialize)]
struct FixPreview {
    /// Where it runs: "this Mac", the repository, or the server and its ssh command.
    destination: String,
    /// When the sweep that found it started.
    found: Timestamp,
    summary: String,
    steps: Vec<String>,
    commands: Vec<String>,
    agent: String,
}

/// Checks the fix of `key` as the CLI's `fix` does before it asks: the finding is current and
/// not dismissed, its fix is well formed, the target is configured and the agent installed.
#[tauri::command(async)]
#[expect(
    clippy::needless_pass_by_value,
    reason = "Tauri hands command arguments over by value"
)]
fn fix_preview(runner: State<'_, Runner>, key: String) -> Result<FixPreview, String> {
    let key: FindingKey = key
        .parse()
        .map_err(|e: ParseFindingKeyError| e.to_string())?;
    let config =
        Config::load(&runner.data_dir().config_file(), runner.home()).map_err(|e| e.to_string())?;
    let plan = plan_fix(runner.data_dir(), &config, key).map_err(|e| e.to_string())?;
    Ok(FixPreview {
        destination: plan.destination().to_owned(),
        found: plan.found(),
        summary: plan.fix().summary.clone(),
        steps: plan.fix().steps.clone(),
        commands: plan.fix().commands.clone(),
        agent: plan.agent().to_string(),
    })
}

/// Runs the fix of `key`, which the user just confirmed in the detail view, with full access.
#[tauri::command]
#[expect(
    clippy::needless_pass_by_value,
    reason = "Tauri hands command arguments over by value"
)]
fn fix(app: AppHandle, key: String, title: String) -> Result<(), String> {
    let key: FindingKey = key
        .parse()
        .map_err(|e: ParseFindingKeyError| e.to_string())?;
    runner::start_fix(&app, key, title).map_err(ToString::to_string)
}

/// Dismisses `key` for `reason`; it shows again when its advisory changes.
#[tauri::command(async)]
#[expect(
    clippy::needless_pass_by_value,
    reason = "Tauri hands command arguments over by value"
)]
fn dismiss(app: AppHandle, key: String, reason: String) -> Result<(), String> {
    let key: FindingKey = key
        .parse()
        .map_err(|e: ParseFindingKeyError| e.to_string())?;
    let runner = app.state::<Runner>();
    ancient_protector_core::dismiss(runner.data_dir(), key, &reason).map_err(|e| e.to_string())?;
    runner::changed(&app);
    Ok(())
}
