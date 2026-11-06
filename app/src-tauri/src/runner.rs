//! Runs sweeps off the UI thread, one at a time, and on the configured schedule.
//!
//! [`Runner`] holds the one piece of shared state behind a single lock: the status, and when
//! the app last started a sweep. [`start`] takes it to check and claim the sweeping state in
//! one step, so two clicks, or a click and the schedule, cannot start two sweeps. The core's
//! own lock on the sweeps folder still guards against a sweep from the CLI; that one surfaces
//! as a failed sweep.

use std::panic;
use std::panic::AssertUnwindSafe;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::MutexGuard;
use std::sync::PoisonError;
use std::thread;
use std::time::Duration;

use ancient_protector_core::Config;
use ancient_protector_core::DataDir;
use ancient_protector_core::Progress;
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
    shared: Mutex<Shared>,
}

#[derive(Debug)]
struct Shared {
    status: Status,
    /// When the app last started a sweep. A sweep that fails before it writes its folder (no
    /// agent configured, another sweep running) leaves no trace on disk, so the schedule
    /// counts this too, and does not retry such a sweep every minute.
    started: Option<Timestamp>,
}

/// What the sweep is doing, as the popover and the tray icon show it.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub(crate) enum Status {
    /// No sweep is running, and the last one, if any, had a verdict for every target.
    Idle,
    /// A sweep is running.
    Sweeping {
        /// Its current step, one line.
        step: String,
    },
    /// The last sweep stopped, a target in it got no verdict, or the schedule could not be
    /// checked.
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
            shared: Mutex::new(Shared {
                status: Status::Idle,
                started: None,
            }),
        }
    }

    pub(crate) fn data_dir(&self) -> &DataDir {
        &self.data_dir
    }

    pub(crate) fn home(&self) -> &Path {
        &self.home
    }

    pub(crate) fn status(&self) -> Status {
        self.lock().status.clone()
    }

    fn set(&self, status: Status) {
        self.lock().status = status;
    }

    /// The state holds no invariant a panic could break halfway (each field is replaced
    /// whole), so a poisoned lock is used as it is.
    fn lock(&self) -> MutexGuard<'_, Shared> {
        self.shared.lock().unwrap_or_else(PoisonError::into_inner)
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
        let mut shared = runner.lock();
        if matches!(shared.status, Status::Sweeping { .. }) {
            return Err("a sweep is already running");
        }
        shared.status = Status::Sweeping {
            step: "starting".to_owned(),
        };
        shared.started = Some(Timestamp::now());
    }
    changed(app);
    let app = app.clone();
    thread::spawn(move || {
        // A panic in the sweep would otherwise leave the status at sweeping for good, and
        // every later start would be refused.
        let status = panic::catch_unwind(AssertUnwindSafe(|| run(&app))).unwrap_or_else(|_| {
            Status::Failed {
                error: "the sweep stopped unexpectedly".to_owned(),
            }
        });
        app.state::<Runner>().set(status);
        changed(&app);
    });
    Ok(())
}

/// Runs one sweep and returns the status it leaves.
fn run(app: &AppHandle) -> Status {
    let runner = app.state::<Runner>();
    let config_path = runner.data_dir().config_file();
    let swept = Config::load(&config_path, runner.home())
        .map_err(|e| e.to_string())
        .and_then(|config| {
            let mut progress = |p: Progress<'_>| {
                runner.set(Status::Sweeping {
                    step: p.to_string(),
                });
                changed(app);
            };
            sweep(runner.data_dir(), &config, Targets::All, &mut progress)
                .map_err(|e| e.to_string())
        });
    match swept {
        Ok(reports) => {
            if let Some((title, body)) = notification(&alerts(&reports)) {
                // Best effort: a notification the user turned off is not an error to show.
                drop(app.notification().builder().title(title).body(body).show());
            }
            verdicts(&reports)
        }
        Err(error) => Status::Failed { error },
    }
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

/// The title and body of the notification for `alerts`, or `None` when there are none.
fn notification(alerts: &[String]) -> Option<(String, String)> {
    let title = match alerts.len() {
        0 => return None,
        1 => "1 new critical or high finding".to_owned(),
        n => format!("{n} new critical or high findings"),
    };
    let mut body = alerts[..alerts.len().min(ALERT_LINES)].join("\n");
    if alerts.len() > ALERT_LINES {
        body.push_str(&format!("\nand {} more", alerts.len() - ALERT_LINES));
    }
    Some((title, body))
}

/// Tells the popover to ask again, and updates the tray icon.
pub(crate) fn changed(app: &AppHandle) {
    // Best effort: no window may be listening yet.
    drop(app.emit("changed", ()));
    tray::refresh(app);
}

/// Checks every [`SCHEDULE_CHECK`] whether a scheduled sweep is due, and starts it. The
/// config is read each time, so an edit to the schedule applies without a restart; a config
/// that cannot be read is shown by the popover, and the check waits for it to be fixed.
pub(crate) fn schedule(app: AppHandle) {
    thread::spawn(move || {
        loop {
            thread::sleep(SCHEDULE_CHECK);
            let runner = app.state::<Runner>();
            let Ok(config) = Config::load(&runner.data_dir().config_file(), runner.home()) else {
                continue;
            };
            let on_disk = match last_sweep_started(runner.data_dir()) {
                Ok(on_disk) => on_disk,
                Err(e) => {
                    // Under one lock, so a running sweep's status is never overwritten. The
                    // failure shows until the next sweep sets the status again.
                    let mut shared = runner.lock();
                    if !matches!(shared.status, Status::Sweeping { .. }) {
                        shared.status = Status::Failed {
                            error: format!("cannot check the schedule: {e}"),
                        };
                    }
                    drop(shared);
                    changed(&app);
                    continue;
                }
            };
            let last = on_disk.max(runner.lock().started);
            if config.schedule.due(last, Timestamp::now()) {
                // Refused only when a sweep from a click is already running; this check is
                // then skipped.
                start(&app).ok();
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_notification_names_up_to_three_alerts() {
        assert_eq!(notification(&[]), None);
        let one = vec!["mac: CVE-1".to_owned()];
        assert_eq!(
            notification(&one),
            Some((
                "1 new critical or high finding".to_owned(),
                "mac: CVE-1".to_owned()
            ))
        );
        let five: Vec<String> = (1..=5).map(|n| format!("mac: CVE-{n}")).collect();
        let (title, body) = notification(&five).unwrap();
        assert_eq!(title, "5 new critical or high findings");
        assert_eq!(body, "mac: CVE-1\nmac: CVE-2\nmac: CVE-3\nand 2 more");
        let (_, body) = notification(&five[..3]).unwrap();
        assert!(!body.contains("more"), "{body}");
    }
}
