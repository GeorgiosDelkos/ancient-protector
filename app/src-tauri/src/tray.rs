//! The menu-bar icon: its colour shows the worst open finding, a running sweep, or a failure,
//! and a left click shows or hides the popover under it.

use std::sync::Mutex;
use std::sync::MutexGuard;
use std::sync::PoisonError;
use std::time::Duration;
use std::time::Instant;

use ancient_protector_core::Config;
use ancient_protector_core::Severity;
use ancient_protector_core::latest;
use tauri::AppHandle;
use tauri::Emitter as _;
use tauri::Manager as _;
use tauri::Window;
use tauri::image::Image;
use tauri::tray::MouseButton;
use tauri::tray::MouseButtonState;
use tauri::tray::TrayIconBuilder;
use tauri::tray::TrayIconEvent;
use tauri_plugin_positioner::Position;
use tauri_plugin_positioner::WindowExt as _;

use crate::runner::Runner;
use crate::runner::Status;

const TRAY_ID: &str = "main";
const POPOVER: &str = "popover";

/// How soon after the popover hid on losing focus a tray click counts as the same gesture.
/// Clicking the icon while the popover is open first takes focus from it, which hides it,
/// and then delivers the click, which would show it again. Arbitrary: longer than the gap
/// between the two events, shorter than a deliberate second click.
const CLICK_AFTER_BLUR: Duration = Duration::from_millis(300);

/// When the popover last hid because it lost focus.
#[derive(Debug, Default)]
pub(crate) struct Popover {
    hidden_on_blur: Mutex<Option<Instant>>,
}

impl Popover {
    /// The time is a plain value; a poisoned lock still holds a valid one.
    fn last_blur(&self) -> MutexGuard<'_, Option<Instant>> {
        self.hidden_on_blur
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

/// Hides the popover because it lost focus, as a menu closes.
pub(crate) fn hide_on_blur(window: &Window) {
    *window.state::<Popover>().last_blur() = Some(Instant::now());
    // Best effort: a window that will not hide stays until the next click.
    drop(window.hide());
}

/// The icon for each state, 44 by 44 pixels: the menu bar's 22 points at 2x.
#[derive(Debug, Clone, Copy)]
enum Look {
    Clean,
    Low,
    Medium,
    High,
    Sweeping,
    Failed,
}

impl Look {
    fn png(self) -> &'static [u8] {
        match self {
            Self::Clean => include_bytes!("../icons/tray-clean.png"),
            Self::Low => include_bytes!("../icons/tray-low.png"),
            Self::Medium => include_bytes!("../icons/tray-medium.png"),
            Self::High => include_bytes!("../icons/tray-high.png"),
            Self::Sweeping => include_bytes!("../icons/tray-sweeping.png"),
            Self::Failed => include_bytes!("../icons/tray-failed.png"),
        }
    }

    fn tooltip(self) -> &'static str {
        match self {
            Self::Clean => "Ancient Protector: nothing open",
            Self::Low => "Ancient Protector: low findings open",
            Self::Medium => "Ancient Protector: medium findings open",
            Self::High => "Ancient Protector: critical or high findings open",
            Self::Sweeping => "Ancient Protector: sweeping",
            Self::Failed => "Ancient Protector: the last sweep failed",
        }
    }

    fn image(self) -> Image<'static> {
        Image::from_bytes(self.png()).expect("the tray icons are valid PNGs built into the app")
    }
}

pub(crate) fn create(app: &AppHandle) -> tauri::Result<()> {
    let look = look(app);
    TrayIconBuilder::with_id(TRAY_ID)
        .icon(look.image())
        .tooltip(look.tooltip())
        .on_tray_icon_event(|tray, event| {
            let app = tray.app_handle();
            tauri_plugin_positioner::on_tray_event(app, &event);
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                toggle(app);
            }
        })
        .build(app)?;
    Ok(())
}

/// Sets the icon for the current state.
pub(crate) fn refresh(app: &AppHandle) {
    let Some(tray) = app.tray_by_id(TRAY_ID) else {
        return;
    };
    let look = look(app);
    // Best effort: a stale icon is corrected by the next change.
    drop(tray.set_icon(Some(look.image())));
    drop(tray.set_tooltip(Some(look.tooltip())));
}

/// While a sweep runs this returns at once; only an idle app reads the config and reports,
/// which keeps the refresh on every progress step cheap.
fn look(app: &AppHandle) -> Look {
    let runner = app.state::<Runner>();
    match runner.status() {
        Status::Sweeping { .. } => return Look::Sweeping,
        Status::Failed { .. } => return Look::Failed,
        Status::Idle => {}
    }
    let Ok(config) = Config::load(&runner.data_dir().config_file(), runner.home()) else {
        return Look::Failed;
    };
    let Ok(targets) = latest(runner.data_dir(), &config) else {
        return Look::Failed;
    };
    let worst = targets
        .iter()
        .flat_map(|t| &t.open)
        .map(|o| o.severity)
        .min();
    match worst {
        None => Look::Clean,
        Some(Severity::Low) => Look::Low,
        Some(Severity::Medium) => Look::Medium,
        Some(Severity::High | Severity::Critical) => Look::High,
    }
}

fn toggle(app: &AppHandle) {
    let Some(window) = app.get_webview_window(POPOVER) else {
        return;
    };
    if window.is_visible().unwrap_or(false) {
        drop(window.hide());
        return;
    }
    let just_hidden = app
        .state::<Popover>()
        .last_blur()
        .is_some_and(|at| at.elapsed() < CLICK_AFTER_BLUR);
    if just_hidden {
        return;
    }
    // Best effort: a popover that fails to move still shows.
    drop(window.move_window(Position::TrayBottomCenter));
    drop(window.show());
    drop(window.set_focus());
    // The popover asks for fresh data whenever it is shown. Only the event: refreshing the icon
    // here would read every report on the main thread, where tray clicks arrive.
    drop(app.emit("changed", ()));
}
