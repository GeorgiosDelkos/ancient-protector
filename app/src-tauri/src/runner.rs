//! Runs sweeps off the UI thread, one at a time, and on the configured schedule.
//!
//! [`Runner::status`] is the one piece of shared state: a single lock (CON-1) that [`start`]
//! takes to check and claim the sweeping state in one step, so two clicks, or a click and the
//! schedule, cannot start two sweeps. The core's own lock on the sweeps folder still guards
//! against a sweep from the CLI; that one surfaces as a failed sweep.

use std::path::Path;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::PoisonError;
use std::thread;
use std::time::Duration;

use ancient_protector_core::Config;
use ancient_protector_core::DataDir;
use ancient_protector_core::Report;
use ancient_protector_core::Targets;
use ancient_protector_core::alerts;
use ancient_protector_core::last_sweep_started;
use ancient_protector_core::sweep;
use jiff::Timestamp;
use serde::Serialize;
use tauri::AppHandle;
use tauri::Emitter as _;
use tauri::Manager as _;
use tauri_plugin_notification::NotificationExt as _;

use crate::tray;

/// How often the schedule is checked. Arbitrary: a sweep is due every few hours, so a minute
/// late is nothing, and a Mac that wakes after a missed sweep runs it within a minute.
const SCHEDULE_CHECK: Duration = Duration::from_secs(60);

/// How many alert lines a notification lists before "and N more". Arbitrary: what fits in a
/// macOS notification without being cut.
const ALERT_LINES: usize = 3;

/// The app's state: where the data is, and what the sweep is doing.
#[derive(Debug)]
pub(crate) struct Runner {
    data_dir: DataDir,
    home: PathBuf,
    status: Mutex<Status>,
}

/// What the sweep is doing, as the popover and the tray icon show it.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub(crate) enum Status {
    /// No sweep is running; the last one, if any, had a verdict for every target.
    Idle,
    /// A sweep is running.
    Sweeping {
        /// Its current step, one line.
        step: String,
    },
    /// The last sweep stopped, or a target in it got no verdict.
    Failed {
        /// Why, one line.
        error: String,
    },
}

impl Runner {
    pub(crate) fn new(data_dir: DataDir, home: PathBuf) -> Self {
        Self {
            data_dir,
            home,
            status: Mutex::new(Status::Idle),
        }
    }

    pub(crate) fn data_dir(&self) -> &DataDir {
        &self.data_dir
    }

    pub(crate) fn home(&self) -> &Path {
        &self.home
    }

    pub(crate) fn status(&self) -> Status {
        self.lock().clone()
    }

    fn set(&self, status: Status) {
        *self.lock() = status;
    }

    /// The status holds no invariant a panic could break halfway, so a poisoned lock is
    /// used as it is (CON-8).
    fn lock(&self) -> std::sync::MutexGuard<'_, Status> {
        self.status.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Starts a sweep of every target on its own thread.
///
/// # Errors
///
/// Fails when a sweep started from the app is already running.
pub(crate) fn start(app: &AppHandle) -> Result<(), &'static str> {
    let runner = app.state::<Runner>();
    {
        let mut status = runner.lock();
        if matches!(*status, Status::Sweeping { .. }) {
            return Err("a sweep is already running");
        }
        *status = Status::Sweeping {
            step: "starting".to_owned(),
        };
    }
    changed(app);
    let app = app.clone();
    thread::spawn(move || run(&app));
    Ok(())
}

fn run(app: &AppHandle) {
    let runner = app.state::<Runner>();
    let config_path = runner.data_dir().config_file();
    let swept = Config::load(&config_path, runner.home())
        .map_err(|e| e.to_string())
        .and_then(|config| {
            let mut progress = |p: ancient_protector_core::Progress<'_>| {
                runner.set(Status::Sweeping {
                    step: p.to_string(),
                });
                changed(app);
            };
            sweep(runner.data_dir(), &config, Targets::All, &mut progress)
                .map_err(|e| e.to_string())
        });
    let status = match swept {
        Ok(reports) => {
            notify(app, &alerts(&reports));
            verdicts(&reports)
        }
        Err(error) => Status::Failed { error },
    };
    runner.set(status);
    changed(app);
}

/// Idle when every target got a verdict, otherwise the first that did not, and why.
fn verdicts(reports: &[Report]) -> Status {
    reports
        .iter()
        .find_map(|r| {
            let failure = r.failure.as_ref()?;
            Some(Status::Failed {
                error: format!("{}: {failure}", r.target),
            })
        })
        .unwrap_or(Status::Idle)
}

/// Raises one notification listing the new critical and high findings, if there are any.
fn notify(app: &AppHandle, alerts: &[String]) {
    if alerts.is_empty() {
        return;
    }
    let mut body = alerts[..alerts.len().min(ALERT_LINES)].join("\n");
    if alerts.len() > ALERT_LINES {
        body.push_str(&format!("\nand {} more", alerts.len() - ALERT_LINES));
    }
    let title = match alerts.len() {
        1 => "1 new critical or high finding".to_owned(),
        n => format!("{n} new critical or high findings"),
    };
    // Best effort: a notification the user turned off is not an error worth showing.
    drop(app.notification().builder().title(title).body(body).show());
}

/// Tells the popover to ask again, and updates the tray icon.
fn changed(app: &AppHandle) {
    // Best effort: no window may be listening yet.
    drop(app.emit("changed", ()));
    tray::refresh(app);
}

/// Checks every [`SCHEDULE_CHECK`] whether a scheduled sweep is due, and starts it. The
/// config is read each time, so an edit to the schedule applies without a restart.
pub(crate) fn schedule(app: AppHandle) {
    thread::spawn(move || {
        loop {
            thread::sleep(SCHEDULE_CHECK);
            let runner = app.state::<Runner>();
            let Ok(config) = Config::load(&runner.data_dir().config_file(), runner.home()) else {
                continue;
            };
            let Ok(last) = last_sweep_started(runner.data_dir()) else {
                continue;
            };
            if config.schedule.due(last, Timestamp::now()) {
                // Already running (from a click): this check is simply skipped.
                start(&app).ok();
            }
        }
    });
}
