//! System tray state controller and close-to-tray policy.

#![forbid(unsafe_code)]

use std::sync::RwLock;

use serde::{Deserialize, Serialize};

/// Visual tray icon & tooltip state reflecting vault lock and background sync status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrayVisualState {
    Locked,
    Unlocked { item_count: usize },
    Syncing,
}

/// Actions triggered from the desktop system tray context menu.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrayMenuAction {
    ShowHideWindow,
    LockVaultNow,
    SyncNow,
    QuitApplication,
}

/// Tracks tray status, tooltip label, window visibility, and close-to-tray preference.
#[derive(Debug)]
pub struct SystemTrayController {
    state: RwLock<TrayVisualState>,
    window_visible: RwLock<bool>,
    minimize_to_tray_on_close: RwLock<bool>,
    quit_requested: RwLock<bool>,
}

impl Default for SystemTrayController {
    fn default() -> Self {
        Self::new(true)
    }
}

impl SystemTrayController {
    pub fn new(minimize_to_tray_on_close: bool) -> Self {
        Self {
            state: RwLock::new(TrayVisualState::Locked),
            window_visible: RwLock::new(true),
            minimize_to_tray_on_close: RwLock::new(minimize_to_tray_on_close),
            quit_requested: RwLock::new(false),
        }
    }

    pub fn set_state(&self, next: TrayVisualState) {
        if let Ok(mut guard) = self.state.write() {
            *guard = next;
        }
    }

    pub fn state(&self) -> TrayVisualState {
        self.state
            .read()
            .map(|guard| *guard)
            .unwrap_or(TrayVisualState::Locked)
    }

    pub fn tooltip(&self) -> String {
        match self.state() {
            TrayVisualState::Locked => "Anvil — Coffre verrouillé".to_owned(),
            TrayVisualState::Unlocked { item_count } => {
                format!("Anvil — Déverrouillé ({item_count} fiches)")
            }
            TrayVisualState::Syncing => "Anvil — Synchronisation chiffrée en cours".to_owned(),
        }
    }

    pub fn is_window_visible(&self) -> bool {
        self.window_visible.read().map(|v| *v).unwrap_or(true)
    }

    pub fn is_quit_requested(&self) -> bool {
        self.quit_requested.read().map(|v| *v).unwrap_or(false)
    }

    pub fn set_minimize_to_tray_on_close(&self, enabled: bool) {
        if let Ok(mut guard) = self.minimize_to_tray_on_close.write() {
            *guard = enabled;
        }
    }

    /// Handles clicking the custom titlebar close button (`X`).
    /// Returns `true` when the window should hide to tray instead of terminating the process.
    pub fn handle_window_close_request(&self) -> bool {
        let to_tray = self
            .minimize_to_tray_on_close
            .read()
            .map(|v| *v)
            .unwrap_or(true);
        if to_tray {
            if let Ok(mut vis) = self.window_visible.write() {
                *vis = false;
            }
            true
        } else {
            if let Ok(mut quit) = self.quit_requested.write() {
                *quit = true;
            }
            false
        }
    }

    pub fn dispatch_menu_action(&self, action: TrayMenuAction) {
        match action {
            TrayMenuAction::ShowHideWindow => {
                if let Ok(mut vis) = self.window_visible.write() {
                    *vis = !*vis;
                }
            }
            TrayMenuAction::LockVaultNow => {
                self.set_state(TrayVisualState::Locked);
            }
            TrayMenuAction::SyncNow => {
                self.set_state(TrayVisualState::Syncing);
            }
            TrayMenuAction::QuitApplication => {
                if let Ok(mut quit) = self.quit_requested.write() {
                    *quit = true;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{SystemTrayController, TrayMenuAction, TrayVisualState};

    #[test]
    fn tray_transitions_between_locked_unlocked_and_close_to_tray() {
        let tray = SystemTrayController::new(true);
        assert_eq!(tray.state(), TrayVisualState::Locked);
        assert!(tray.handle_window_close_request());
        assert!(!tray.is_window_visible());
        assert!(!tray.is_quit_requested());

        tray.dispatch_menu_action(TrayMenuAction::ShowHideWindow);
        assert!(tray.is_window_visible());

        tray.set_state(TrayVisualState::Unlocked { item_count: 14 });
        assert!(tray.tooltip().contains("14"));

        tray.dispatch_menu_action(TrayMenuAction::LockVaultNow);
        assert_eq!(tray.state(), TrayVisualState::Locked);

        tray.dispatch_menu_action(TrayMenuAction::QuitApplication);
        assert!(tray.is_quit_requested());
    }
}
