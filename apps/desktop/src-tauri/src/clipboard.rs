//! Secure volatile clipboard manager with Win32 history exclusion and SHA-256 timed auto-clear.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::Zeroize;

/// Default auto-clear timeout after copying any username, password, or TOTP secret.
pub const DEFAULT_CLIPBOARD_CLEAR_TTL: Duration = Duration::from_secs(30);

/// Typed clipboard backend and synchronization errors.
#[derive(Debug, Error)]
pub enum ClipboardError {
    #[error("clipboard is locked by another application")]
    AccessBusy,
    #[error("Win32 clipboard operation failed")]
    PlatformFailure,
}

/// Receipt emitted to UI toast notifications without echoing sensitive values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ClipboardCopyReceipt {
    pub label: String,
    pub clear_after_seconds: u64,
    pub expires_at_ms: u64,
}

/// Abstract OS clipboard operations for deterministic testing and native Win32 exclusion.
pub trait ClipboardBackend: Send + Sync + std::fmt::Debug {
    fn write_secret(&self, text: &str) -> Result<(), ClipboardError>;
    fn read_text(&self) -> Result<Option<String>, ClipboardError>;
    fn clear(&self) -> Result<(), ClipboardError>;
}

/// In-memory clipboard backend for isolated integration tests.
#[derive(Debug, Default)]
pub struct MemoryClipboardBackend {
    value: Mutex<Option<String>>,
}

impl MemoryClipboardBackend {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ClipboardBackend for MemoryClipboardBackend {
    fn write_secret(&self, text: &str) -> Result<(), ClipboardError> {
        let mut guard = self
            .value
            .lock()
            .map_err(|_| ClipboardError::PlatformFailure)?;
        *guard = Some(text.to_owned());
        Ok(())
    }

    fn read_text(&self) -> Result<Option<String>, ClipboardError> {
        let guard = self
            .value
            .lock()
            .map_err(|_| ClipboardError::PlatformFailure)?;
        Ok(guard.clone())
    }

    fn clear(&self) -> Result<(), ClipboardError> {
        let mut guard = self
            .value
            .lock()
            .map_err(|_| ClipboardError::PlatformFailure)?;
        if let Some(mut existing) = guard.take() {
            existing.zeroize();
        }
        Ok(())
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
mod native {
    use std::ffi::c_void;
    use std::ptr::copy_nonoverlapping;

    use super::{ClipboardBackend, ClipboardError};

    type Bool = i32;
    type Handle = isize;
    type Hwnd = isize;
    type Uint = u32;

    const CF_UNICODETEXT: Uint = 13;
    const GMEM_MOVEABLE: Uint = 0x0002;

    #[link(name = "user32")]
    unsafe extern "system" {
        fn OpenClipboard(hwnd_new_owner: Hwnd) -> Bool;
        fn CloseClipboard() -> Bool;
        fn EmptyClipboard() -> Bool;
        fn SetClipboardData(u_format: Uint, h_mem: Handle) -> Handle;
        fn GetClipboardData(u_format: Uint) -> Handle;
        fn IsClipboardFormatAvailable(format: Uint) -> Bool;
        fn RegisterClipboardFormatW(lpsz_format: *const u16) -> Uint;
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GlobalAlloc(u_flags: Uint, dw_bytes: usize) -> Handle;
        fn GlobalFree(h_mem: Handle) -> Handle;
        fn GlobalLock(h_mem: Handle) -> *mut c_void;
        fn GlobalUnlock(h_mem: Handle) -> Bool;
        fn GlobalSize(h_mem: Handle) -> usize;
    }

    struct ClipboardLock;

    impl ClipboardLock {
        fn acquire() -> Result<Self, ClipboardError> {
            // SAFETY: Passing `0` opens the clipboard for the current task without owning HWND.
            let opened = unsafe { OpenClipboard(0) };
            if opened == 0 {
                return Err(ClipboardError::AccessBusy);
            }
            Ok(Self)
        }
    }

    impl Drop for ClipboardLock {
        fn drop(&mut self) {
            // SAFETY: Matches a successful `OpenClipboard` call on this thread.
            unsafe {
                let _ = CloseClipboard();
            }
        }
    }

    fn set_global_bytes(format: Uint, bytes: &[u8]) -> Result<(), ClipboardError> {
        if format == 0 {
            return Err(ClipboardError::PlatformFailure);
        }
        // SAFETY: `GlobalAlloc` allocates `bytes.len()` moveable bytes managed by Win32 clipboard.
        let hmem = unsafe { GlobalAlloc(GMEM_MOVEABLE, bytes.len()) };
        if hmem == 0 {
            return Err(ClipboardError::PlatformFailure);
        }

        // SAFETY: `hmem` is a valid unlocked handle returned by `GlobalAlloc`.
        let ptr = unsafe { GlobalLock(hmem) };
        if ptr.is_null() {
            // SAFETY: `hmem` has not been transferred to Windows yet, so freeing avoids a leak.
            unsafe {
                let _ = GlobalFree(hmem);
            }
            return Err(ClipboardError::PlatformFailure);
        }

        // SAFETY: `ptr` points to a writable buffer of at least `bytes.len()` bytes.
        unsafe {
            copy_nonoverlapping(bytes.as_ptr(), ptr.cast::<u8>(), bytes.len());
            let _ = GlobalUnlock(hmem);
        }

        // SAFETY: Clipboard is currently open and owned by this thread.
        let handle = unsafe { SetClipboardData(format, hmem) };
        if handle == 0 {
            // SAFETY: Windows did not take ownership of `hmem` on failure.
            unsafe {
                let _ = GlobalFree(hmem);
            }
            return Err(ClipboardError::PlatformFailure);
        }

        Ok(())
    }

    fn register_format(name: &str) -> Uint {
        let mut wide: Vec<u16> = name.encode_utf16().collect();
        wide.push(0);
        // SAFETY: `wide` is NUL-terminated UTF-16 valid for the call duration.
        unsafe { RegisterClipboardFormatW(wide.as_ptr()) }
    }

    /// Win32 clipboard writer marking secrets ineligible for `Win+V` history and cloud sync.
    #[derive(Debug, Default)]
    pub struct Win32ClipboardBackend;

    impl Win32ClipboardBackend {
        pub fn new() -> Self {
            Self
        }
    }

    impl ClipboardBackend for Win32ClipboardBackend {
        fn write_secret(&self, text: &str) -> Result<(), ClipboardError> {
            let _lock = ClipboardLock::acquire()?;
            // SAFETY: Clipboard is held by `_lock`.
            if unsafe { EmptyClipboard() } == 0 {
                return Err(ClipboardError::PlatformFailure);
            }

            let mut utf16: Vec<u16> = text.encode_utf16().collect();
            utf16.push(0);
            let mut raw = Vec::with_capacity(utf16.len().saturating_mul(2));
            for unit in utf16 {
                raw.extend_from_slice(&unit.to_le_bytes());
            }

            set_global_bytes(CF_UNICODETEXT, &raw)?;

            let zero_dword = 0u32.to_le_bytes();
            let exclude_monitor = register_format("ExcludeClipboardContentFromMonitorProcessing");
            let exclude_history = register_format("CanIncludeInClipboardHistory");
            let exclude_cloud = register_format("CanUploadToCloudClipboard");

            if exclude_monitor != 0 {
                set_global_bytes(exclude_monitor, &zero_dword)?;
            }
            if exclude_history != 0 {
                set_global_bytes(exclude_history, &zero_dword)?;
            }
            if exclude_cloud != 0 {
                set_global_bytes(exclude_cloud, &zero_dword)?;
            }

            Ok(())
        }

        fn read_text(&self) -> Result<Option<String>, ClipboardError> {
            // SAFETY: Querying format availability does not require holding the clipboard.
            if unsafe { IsClipboardFormatAvailable(CF_UNICODETEXT) } == 0 {
                return Ok(None);
            }

            let _lock = ClipboardLock::acquire()?;
            // SAFETY: `GetClipboardData` returns a system-owned handle valid until `CloseClipboard`.
            let hmem = unsafe { GetClipboardData(CF_UNICODETEXT) };
            if hmem == 0 {
                return Ok(None);
            }

            // SAFETY: `hmem` is a valid global handle while `_lock` keeps the clipboard open.
            let byte_len = unsafe { GlobalSize(hmem) };
            // SAFETY: Lock handle for read-only inspection.
            let ptr = unsafe { GlobalLock(hmem) };
            if ptr.is_null() {
                return Ok(None);
            }

            let slice = if byte_len < 2 {
                Vec::new()
            } else {
                // SAFETY: `GlobalSize` guarantees at least `byte_len` readable bytes at `ptr`.
                let raw = unsafe { std::slice::from_raw_parts(ptr.cast::<u8>(), byte_len) };
                let (pairs, _) = raw.as_chunks::<2>();
                let mut units = Vec::with_capacity(pairs.len());
                for &[lo, hi] in pairs {
                    let unit = u16::from_le_bytes([lo, hi]);
                    if unit == 0 {
                        break;
                    }
                    units.push(unit);
                }
                units
            };

            // SAFETY: Pair with successful `GlobalLock`.
            unsafe {
                let _ = GlobalUnlock(hmem);
            }

            if slice.is_empty() {
                return Ok(Some(String::new()));
            }
            Ok(Some(String::from_utf16_lossy(&slice)))
        }

        fn clear(&self) -> Result<(), ClipboardError> {
            let _lock = ClipboardLock::acquire()?;
            // SAFETY: Empties clipboard while held by `_lock`.
            if unsafe { EmptyClipboard() } == 0 {
                return Err(ClipboardError::PlatformFailure);
            }
            Ok(())
        }
    }
}

#[cfg(windows)]
pub use native::Win32ClipboardBackend;

/// Manages sensitive clipboard copies using SHA-256 verification and automatic timeout purge.
#[derive(Debug)]
pub struct SecureClipboardManager {
    backend: Arc<dyn ClipboardBackend>,
    last_hash: Mutex<Option<[u8; 32]>>,
    generation: AtomicU64,
}

impl SecureClipboardManager {
    pub fn new(backend: Arc<dyn ClipboardBackend>) -> Self {
        Self {
            backend,
            last_hash: Mutex::new(None),
            generation: AtomicU64::new(0),
        }
    }

    #[cfg(windows)]
    pub fn native_windows() -> Arc<Self> {
        Arc::new(Self::new(Arc::new(Win32ClipboardBackend::new())))
    }

    #[cfg(not(windows))]
    pub fn native_windows() -> Arc<Self> {
        Arc::new(Self::new(Arc::new(MemoryClipboardBackend::new())))
    }

    /// Copies a secret and schedules automatic purge after `ttl` if a Tokio runtime is active.
    pub fn copy_secret(
        self: &Arc<Self>,
        label: &str,
        secret: &str,
        ttl: Duration,
    ) -> Result<ClipboardCopyReceipt, ClipboardError> {
        let digest = sha256_bytes(secret.as_bytes());
        self.backend.write_secret(secret)?;

        let copy_gen = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
        if let Ok(mut guard) = self.last_hash.lock() {
            *guard = Some(digest);
        }

        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let manager = Arc::clone(self);
            handle.spawn(async move {
                tokio::time::sleep(ttl).await;
                if manager.generation.load(Ordering::SeqCst) == copy_gen {
                    let _ = manager.clear_if_unchanged();
                }
            });
        }

        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let ttl_ms = ttl.as_millis() as u64;

        Ok(ClipboardCopyReceipt {
            label: label.to_owned(),
            clear_after_seconds: ttl.as_secs().max(1),
            expires_at_ms: now_ms.saturating_add(ttl_ms),
        })
    }

    /// Clears the OS clipboard ONLY when its current content still hashes to our copied secret.
    pub fn clear_if_unchanged(&self) -> Result<bool, ClipboardError> {
        let expected = {
            let guard = self
                .last_hash
                .lock()
                .map_err(|_| ClipboardError::PlatformFailure)?;
            match *guard {
                Some(hash) => hash,
                None => return Ok(false),
            }
        };

        let current = match self.backend.read_text()? {
            Some(text) => text,
            None => {
                self.forget_hash();
                return Ok(false);
            }
        };

        let actual = sha256_bytes(current.as_bytes());
        self.forget_hash();

        if bool::from(actual.ct_eq(&expected)) {
            self.backend.clear()?;
            return Ok(true);
        }
        Ok(false)
    }

    /// Immediately clears if unchanged (e.g. on vault lock).
    pub fn clear_on_lock(&self) -> Result<bool, ClipboardError> {
        self.clear_if_unchanged()
    }

    fn forget_hash(&self) {
        if let Ok(mut guard) = self.last_hash.lock()
            && let Some(ref mut existing) = *guard
        {
            existing.zeroize();
            *guard = None;
        }
    }
}

fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use super::{ClipboardBackend, MemoryClipboardBackend, SecureClipboardManager};

    #[test]
    fn clear_if_unchanged_purges_matching_secret_only() {
        let backend = Arc::new(MemoryClipboardBackend::new());
        let manager = Arc::new(SecureClipboardManager::new(
            Arc::clone(&backend) as Arc<dyn ClipboardBackend>
        ));

        let receipt = manager
            .copy_secret("Password", "S3cr3t!Vault#9", Duration::from_secs(30))
            .ok();
        assert!(receipt.is_some());
        assert_eq!(
            backend.read_text().ok().flatten().as_deref(),
            Some("S3cr3t!Vault#9")
        );

        let cleared = manager.clear_if_unchanged().ok();
        assert_eq!(cleared, Some(true));
        assert_eq!(backend.read_text().ok().flatten(), None);

        let _ = manager
            .copy_secret("Password", "FirstSecret", Duration::from_secs(30))
            .ok();
        let _ = backend.write_secret("UserCopiedNotes").ok();
        let skipped = manager.clear_if_unchanged().ok();
        assert_eq!(skipped, Some(false));
        assert_eq!(
            backend.read_text().ok().flatten().as_deref(),
            Some("UserCopiedNotes")
        );
    }
}
