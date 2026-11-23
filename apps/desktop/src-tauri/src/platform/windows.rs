//! Windows custom chrome hit-testing (`WM_NCHITTEST` + Windows 11 Snap Layouts)
//! and OS session lock/suspend event monitoring (`WTSRegisterSessionNotification`).

use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Platform hook and window subclassing errors.
#[derive(Debug, Error)]
pub enum PlatformError {
    #[error("invalid native window handle")]
    InvalidWindowHandle,
    #[error("failed to install Win32 subclass handler")]
    SubclassInstallFailed,
    #[error("failed to register WTS session lock notification")]
    SessionNotificationFailed,
    #[error("platform hooks are unsupported on this target")]
    UnsupportedPlatform,
}

/// Win32 `WM_NCHITTEST` return codes controlling frameless window interaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(isize)]
pub enum Win32HitZone {
    Client = 1,
    Caption = 2,
    MinButton = 8,
    MaxButton = 9,
    Left = 10,
    Right = 11,
    Top = 12,
    TopLeft = 13,
    TopRight = 14,
    Bottom = 15,
    BottomLeft = 16,
    BottomRight = 17,
    Close = 20,
}

/// Bounding rectangle in physical screen coordinates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowRect {
    pub left: i32,
    pub top: i32,
    pub right: i32,
    pub bottom: i32,
}

impl WindowRect {
    pub const fn width(self) -> i32 {
        self.right.saturating_sub(self.left)
    }

    pub const fn height(self) -> i32 {
        self.bottom.saturating_sub(self.top)
    }
}

/// Interactive window-relative sub-rectangle that must remain clickable (`HTCLIENT`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExclusionRect {
    pub x: i32,
    pub y: i32,
    pub width: i32,
    pub height: i32,
}

impl ExclusionRect {
    pub const fn contains(self, rel_x: i32, rel_y: i32) -> bool {
        rel_x >= self.x
            && rel_x < self.x.saturating_add(self.width)
            && rel_y >= self.y
            && rel_y < self.y.saturating_add(self.height)
    }
}

/// Geometry parameters matching `CustomTitlebar` (`40px` bar, `46px` per caption button, `6px` resize frame).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TitlebarHitConfig {
    pub titlebar_height: i32,
    pub resize_border: i32,
    pub button_width: i32,
    pub controls_width: i32,
    pub exclusions: Vec<ExclusionRect>,
}

impl Default for TitlebarHitConfig {
    fn default() -> Self {
        Self {
            titlebar_height: 40,
            resize_border: 6,
            button_width: 46,
            controls_width: 138,
            exclusions: Vec::new(),
        }
    }
}

impl TitlebarHitConfig {
    /// Creates the default frameless window config with an interactive search input rect.
    pub fn with_centered_search(window_width: i32, search_width: i32) -> Self {
        let clamped_w = search_width.min(window_width.saturating_sub(360)).max(160);
        let search_x = (window_width - clamped_w) / 2;
        Self {
            exclusions: vec![ExclusionRect {
                x: search_x,
                y: 5,
                width: clamped_w,
                height: 30,
            }],
            ..Self::default()
        }
    }
}

/// Computes the exact `WM_NCHITTEST` hit zone for a frameless window.
///
/// Returning `Win32HitZone::MaxButton` (`HTMAXBUTTON = 9`) over the maximize button allows
/// Windows 11 to trigger native Snap Layouts automatically on hover without stealing clicks.
pub fn compute_hit_zone(
    rect: WindowRect,
    cursor_x: i32,
    cursor_y: i32,
    is_maximized: bool,
    cfg: &TitlebarHitConfig,
) -> Win32HitZone {
    let width = rect.width();
    let height = rect.height();
    if width <= 0 || height <= 0 {
        return Win32HitZone::Client;
    }

    let rel_x = cursor_x.saturating_sub(rect.left);
    let rel_y = cursor_y.saturating_sub(rect.top);

    if rel_x < 0 || rel_y < 0 || rel_x >= width || rel_y >= height {
        return Win32HitZone::Client;
    }

    if !is_maximized && cfg.resize_border > 0 {
        let border = cfg.resize_border;
        let on_left = rel_x < border;
        let on_right = rel_x >= width.saturating_sub(border);
        let on_top = rel_y < border;
        let on_bottom = rel_y >= height.saturating_sub(border);

        match (on_left, on_right, on_top, on_bottom) {
            (true, _, true, _) => return Win32HitZone::TopLeft,
            (_, true, true, _) => return Win32HitZone::TopRight,
            (true, _, _, true) => return Win32HitZone::BottomLeft,
            (_, true, _, true) => return Win32HitZone::BottomRight,
            (true, false, false, false) => return Win32HitZone::Left,
            (false, true, false, false) => return Win32HitZone::Right,
            (false, false, true, false) => return Win32HitZone::Top,
            (false, false, false, true) => return Win32HitZone::Bottom,
            _ => {}
        }
    }

    if rel_y < cfg.titlebar_height {
        let controls_start = width.saturating_sub(cfg.controls_width);
        if rel_x >= controls_start {
            let max_start = width.saturating_sub(cfg.button_width.saturating_mul(2));
            let close_start = width.saturating_sub(cfg.button_width);
            if rel_x >= close_start {
                return Win32HitZone::Close;
            }
            if rel_x >= max_start {
                return Win32HitZone::MaxButton;
            }
            return Win32HitZone::MinButton;
        }

        if cfg
            .exclusions
            .iter()
            .any(|box_rect| box_rect.contains(rel_x, rel_y))
        {
            return Win32HitZone::Client;
        }

        return Win32HitZone::Caption;
    }

    Win32HitZone::Client
}

/// System session transition events that require immediate vault locking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OsSessionLockEvent {
    SessionLock,
    ConsoleDisconnect,
    PowerSuspend,
}

type SessionLockCallback = Arc<dyn Fn(OsSessionLockEvent) + Send + Sync>;

/// Dispatches OS lock and suspend events (`Win+L`, sleep, switch user) to vault listeners.
#[derive(Default)]
pub struct OsSessionLockMonitor {
    listeners: RwLock<Vec<SessionLockCallback>>,
}

impl std::fmt::Debug for OsSessionLockMonitor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let count = self.listeners.read().map(|l| l.len()).unwrap_or(0);
        f.debug_struct("OsSessionLockMonitor")
            .field("listeners", &count)
            .finish()
    }
}

impl OsSessionLockMonitor {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn subscribe<F>(&self, callback: F)
    where
        F: Fn(OsSessionLockEvent) + Send + Sync + 'static,
    {
        if let Ok(mut guard) = self.listeners.write() {
            guard.push(Arc::new(callback));
        }
    }

    pub fn trigger(&self, event: OsSessionLockEvent) {
        let snapshot: Vec<SessionLockCallback> = self
            .listeners
            .read()
            .map(|guard| guard.clone())
            .unwrap_or_default();
        for cb in snapshot {
            cb(event);
        }
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
mod native {
    use std::ffi::c_void;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::{
        OsSessionLockEvent, OsSessionLockMonitor, PlatformError, TitlebarHitConfig, WindowRect,
        compute_hit_zone,
    };

    type Hwnd = isize;
    type Uint = u32;
    type Wparam = usize;
    type Lparam = isize;
    type Lresult = isize;
    type Bool = i32;
    type Dword = u32;
    type UintPtr = usize;
    type DwordPtr = usize;

    const WM_NCDESTROY: Uint = 0x0082;
    const WM_NCHITTEST: Uint = 0x0084;
    const WM_POWERBROADCAST: Uint = 0x0218;
    const WM_WTSSESSION_CHANGE: Uint = 0x02B1;

    const PBT_APMSUSPEND: Wparam = 0x0004;
    const WTS_CONSOLE_DISCONNECT: Wparam = 0x0002;
    const WTS_SESSION_LOCK: Wparam = 0x0007;
    const NOTIFY_FOR_THIS_SESSION: Dword = 0;

    const ANVIL_SUBCLASS_ID: UintPtr = 0x414E_564C;

    #[repr(C)]
    struct Rect {
        left: i32,
        top: i32,
        right: i32,
        bottom: i32,
    }

    type SubclassProc = unsafe extern "system" fn(
        hwnd: Hwnd,
        msg: Uint,
        wparam: Wparam,
        lparam: Lparam,
        u_id_subclass: UintPtr,
        dw_ref_data: DwordPtr,
    ) -> Lresult;

    #[link(name = "comctl32")]
    unsafe extern "system" {
        fn SetWindowSubclass(
            hwnd: Hwnd,
            pfn_subclass: Option<SubclassProc>,
            u_id_subclass: UintPtr,
            dw_ref_data: DwordPtr,
        ) -> Bool;
        fn RemoveWindowSubclass(
            hwnd: Hwnd,
            pfn_subclass: Option<SubclassProc>,
            u_id_subclass: UintPtr,
        ) -> Bool;
        fn DefSubclassProc(hwnd: Hwnd, msg: Uint, wparam: Wparam, lparam: Lparam) -> Lresult;
    }

    #[link(name = "wtsapi32")]
    unsafe extern "system" {
        fn WTSRegisterSessionNotification(hwnd: Hwnd, dw_flags: Dword) -> Bool;
        fn WTSUnRegisterSessionNotification(hwnd: Hwnd) -> Bool;
    }

    #[link(name = "user32")]
    unsafe extern "system" {
        fn IsWindow(hwnd: Hwnd) -> Bool;
        fn IsZoomed(hwnd: Hwnd) -> Bool;
        fn GetWindowRect(hwnd: Hwnd, lp_rect: *mut Rect) -> Bool;
    }

    struct SubclassState {
        config: TitlebarHitConfig,
        monitor: Arc<OsSessionLockMonitor>,
        cleaned_up: AtomicBool,
    }

    impl SubclassState {
        fn cleanup(&self, hwnd: Hwnd, state_ptr: *mut SubclassState) {
            if !self.cleaned_up.swap(true, Ordering::AcqRel) {
                // SAFETY: `hwnd` was validated when installed; unregistering removes our WTS
                // listener and window subclass before freeing `state_ptr`.
                unsafe {
                    let _ = WTSUnRegisterSessionNotification(hwnd);
                    let _ =
                        RemoveWindowSubclass(hwnd, Some(anvil_subclass_proc), ANVIL_SUBCLASS_ID);
                    drop(Box::from_raw(state_ptr));
                }
            }
        }
    }

    unsafe extern "system" fn anvil_subclass_proc(
        hwnd: Hwnd,
        msg: Uint,
        wparam: Wparam,
        lparam: Lparam,
        _u_id_subclass: UintPtr,
        dw_ref_data: DwordPtr,
    ) -> Lresult {
        let state_ptr = dw_ref_data as *mut SubclassState;
        if state_ptr.is_null() {
            // SAFETY: Forwarding unhandled messages when no ref data is present preserves default behavior.
            return unsafe { DefSubclassProc(hwnd, msg, wparam, lparam) };
        }

        // SAFETY: `dw_ref_data` points to the heap-allocated `SubclassState` owned until `cleanup`.
        let state = unsafe { &*state_ptr };

        match msg {
            WM_NCHITTEST => {
                let mut raw_rect = Rect {
                    left: 0,
                    top: 0,
                    right: 0,
                    bottom: 0,
                };
                // SAFETY: `raw_rect` is stack-allocated and writable for `GetWindowRect`.
                let ok = unsafe { GetWindowRect(hwnd, &mut raw_rect) };
                if ok != 0 {
                    // SAFETY: `IsZoomed` reads the native HWND maximize state safely.
                    let maximized = unsafe { IsZoomed(hwnd) != 0 };
                    let low = (lparam as usize & 0xFFFF) as u16;
                    let high = ((lparam as usize >> 16) & 0xFFFF) as u16;
                    let cursor_x = i32::from(i16::from_ne_bytes(low.to_ne_bytes()));
                    let cursor_y = i32::from(i16::from_ne_bytes(high.to_ne_bytes()));

                    let zone = compute_hit_zone(
                        WindowRect {
                            left: raw_rect.left,
                            top: raw_rect.top,
                            right: raw_rect.right,
                            bottom: raw_rect.bottom,
                        },
                        cursor_x,
                        cursor_y,
                        maximized,
                        &state.config,
                    );
                    return zone as isize;
                }
            }
            WM_WTSSESSION_CHANGE => {
                if wparam == WTS_SESSION_LOCK {
                    state.monitor.trigger(OsSessionLockEvent::SessionLock);
                } else if wparam == WTS_CONSOLE_DISCONNECT {
                    state.monitor.trigger(OsSessionLockEvent::ConsoleDisconnect);
                }
            }
            WM_POWERBROADCAST if wparam == PBT_APMSUSPEND => {
                state.monitor.trigger(OsSessionLockEvent::PowerSuspend);
            }
            WM_NCDESTROY => {
                // SAFETY: Always pass `WM_NCDESTROY` down the subclass chain before tearing down `state_ptr`.
                let res = unsafe { DefSubclassProc(hwnd, msg, wparam, lparam) };
                state.cleanup(hwnd, state_ptr);
                return res;
            }
            _ => {}
        }

        // SAFETY: Forward remaining window messages to the base subclass handler.
        unsafe { DefSubclassProc(hwnd, msg, wparam, lparam) }
    }

    /// RAII guard unregistering Win32 subclass and WTS notifications on drop.
    pub struct Win32WindowHookGuard {
        hwnd: Hwnd,
        state_ptr: *mut c_void,
    }

    // SAFETY: Cleanup only passes an opaque HWND and pointer synchronized via `AtomicBool`.
    unsafe impl Send for Win32WindowHookGuard {}
    // SAFETY: Cleanup operations use atomic exchange before touching Win32 or freeing state.
    unsafe impl Sync for Win32WindowHookGuard {}

    impl Drop for Win32WindowHookGuard {
        fn drop(&mut self) {
            let ptr = self.state_ptr.cast::<SubclassState>();
            if !ptr.is_null() {
                // SAFETY: `state_ptr` remains valid while `cleaned_up` is false.
                let state = unsafe { &*ptr };
                state.cleanup(self.hwnd, ptr);
            }
        }
    }

    /// Installs custom hit-testing (`HTMAXBUTTON` + 6px border) and `WTSRegisterSessionNotification` on `hwnd`.
    pub fn install_window_hooks(
        hwnd: isize,
        config: TitlebarHitConfig,
        monitor: Arc<OsSessionLockMonitor>,
    ) -> Result<Win32WindowHookGuard, PlatformError> {
        if hwnd == 0 {
            return Err(PlatformError::InvalidWindowHandle);
        }

        // SAFETY: `IsWindow` checks whether the provided OS window handle refers to a live window.
        if unsafe { IsWindow(hwnd) } == 0 {
            return Err(PlatformError::InvalidWindowHandle);
        }

        let state_box = Box::new(SubclassState {
            config,
            monitor,
            cleaned_up: AtomicBool::new(false),
        });
        let state_ptr = Box::into_raw(state_box);

        // SAFETY: `hwnd` is a verified window handle and `state_ptr` stays valid until cleanup.
        let sub_ok = unsafe {
            SetWindowSubclass(
                hwnd,
                Some(anvil_subclass_proc),
                ANVIL_SUBCLASS_ID,
                state_ptr as DwordPtr,
            )
        };
        if sub_ok == 0 {
            // SAFETY: Registration failed so ownership of `state_ptr` returns immediately to free it.
            unsafe {
                drop(Box::from_raw(state_ptr));
            }
            return Err(PlatformError::SubclassInstallFailed);
        }

        // SAFETY: `hwnd` is registered with `NOTIFY_FOR_THIS_SESSION` to receive `WM_WTSSESSION_CHANGE`.
        let wts_ok = unsafe { WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION) };
        if wts_ok == 0 {
            // SAFETY: Clean up the installed subclass and free `state_ptr` on WTS failure.
            unsafe {
                let _ = RemoveWindowSubclass(hwnd, Some(anvil_subclass_proc), ANVIL_SUBCLASS_ID);
                drop(Box::from_raw(state_ptr));
            }
            return Err(PlatformError::SessionNotificationFailed);
        }

        Ok(Win32WindowHookGuard {
            hwnd,
            state_ptr: state_ptr.cast::<c_void>(),
        })
    }
}

#[cfg(windows)]
pub use native::{Win32WindowHookGuard, install_window_hooks};

#[cfg(not(windows))]
pub struct Win32WindowHookGuard;

#[cfg(not(windows))]
pub fn install_window_hooks(
    _hwnd: isize,
    _config: TitlebarHitConfig,
    _monitor: Arc<OsSessionLockMonitor>,
) -> Result<Win32WindowHookGuard, PlatformError> {
    Err(PlatformError::UnsupportedPlatform)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::{
        OsSessionLockEvent, OsSessionLockMonitor, PlatformError, TitlebarHitConfig, Win32HitZone,
        WindowRect, compute_hit_zone, install_window_hooks,
    };

    #[test]
    fn snap_layout_and_resize_hit_testing() {
        let rect = WindowRect {
            left: 100,
            top: 50,
            right: 1340,
            bottom: 850,
        };
        let cfg = TitlebarHitConfig::with_centered_search(rect.width(), 340);

        assert_eq!(
            compute_hit_zone(rect, 1280, 65, false, &cfg),
            Win32HitZone::MaxButton
        );
        assert_eq!(
            compute_hit_zone(rect, 1320, 65, false, &cfg),
            Win32HitZone::Close
        );
        assert_eq!(
            compute_hit_zone(rect, 1220, 65, false, &cfg),
            Win32HitZone::MinButton
        );
        assert_eq!(
            compute_hit_zone(rect, 720, 68, false, &cfg),
            Win32HitZone::Client
        );
        assert_eq!(
            compute_hit_zone(rect, 240, 70, false, &cfg),
            Win32HitZone::Caption
        );

        assert_eq!(
            compute_hit_zone(rect, 102, 200, false, &cfg),
            Win32HitZone::Left
        );
        assert_eq!(
            compute_hit_zone(rect, 102, 52, false, &cfg),
            Win32HitZone::TopLeft
        );
        assert_eq!(
            compute_hit_zone(rect, 1338, 848, false, &cfg),
            Win32HitZone::BottomRight
        );

        assert_eq!(
            compute_hit_zone(rect, 102, 200, true, &cfg),
            Win32HitZone::Client
        );
        assert_eq!(
            compute_hit_zone(rect, 1280, 52, true, &cfg),
            Win32HitZone::MaxButton
        );
    }

    #[test]
    fn os_session_lock_monitor_invokes_all_subscribers() {
        let monitor = Arc::new(OsSessionLockMonitor::new());
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = Arc::clone(&counter);

        monitor.subscribe(move |evt| {
            if matches!(evt, OsSessionLockEvent::SessionLock) {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            }
        });

        monitor.trigger(OsSessionLockEvent::SessionLock);
        monitor.trigger(OsSessionLockEvent::PowerSuspend);
        assert_eq!(counter.load(Ordering::SeqCst), 1);

        let err = install_window_hooks(0, TitlebarHitConfig::default(), monitor)
            .err()
            .unwrap_or(PlatformError::UnsupportedPlatform);
        assert!(matches!(
            err,
            PlatformError::InvalidWindowHandle | PlatformError::UnsupportedPlatform
        ));
    }
}
