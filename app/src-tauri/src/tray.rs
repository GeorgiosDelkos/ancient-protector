//! The menu-bar icon: its colour shows the worst open finding, a running sweep, or a failure,
//! and a left click shows or hides the popover under it.

use ancient_protector_core::Config;
use ancient_protector_core::Severity;
use ancient_protector_core::latest;
use tauri::AppHandle;
use tauri::Manager as _;
use tauri::image::Image;
use tauri::tray::MouseButton;
use tauri::tray::MouseButtonState;
use tauri::tray::TrayIconBuilder;
use tauri::tray::TrayIconEvent;
use tauri_plugin_positioner::Position;
use tauri_plugin_positioner::WindowExt as _;

use crate::runner;
use crate::runner::Runner;
use crate::runner::Status;

const TRAY_ID: &str = "main";
const POPOVER: &str = "popover";

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
    // Best effort: a popover that fails to move still shows.
    drop(window.move_window(Position::TrayBottomCenter));
    drop(window.show());
    drop(window.set_focus());
    // The popover asks for fresh data whenever it is shown.
    runner::changed(app);
}
