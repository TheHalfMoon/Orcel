//! What the shell counted, written once on exit to stdout.
//!
//! The counts are taken on the Rust side only; no probe is compiled into the
//! page. `SG119-IPC commands=<n> web_messages=<m>`: `n` is every command
//! request that reached the Rust invoke handler (A2 registers no command, so
//! each is refused there), `m` every web message the shell's own WebView2
//! `WebMessageReceived` handler saw (Tauri's `postMessage` fallback would
//! arrive there). The native test requires `n` above zero and `m` zero.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

static COMMANDS: AtomicU64 = AtomicU64::new(0);
static WEB_MESSAGES: AtomicU64 = AtomicU64::new(0);
static NEW_WINDOW_REQUESTS: AtomicU64 = AtomicU64::new(0);
static DOWNLOAD_REQUESTS: AtomicU64 = AtomicU64::new(0);
static ORDER: Mutex<Vec<&'static str>> = Mutex::new(Vec::new());
static REFUSED_NAVIGATIONS: Mutex<Vec<String>> = Mutex::new(Vec::new());
static WEBVIEW2_VERSION: Mutex<String> = Mutex::new(String::new());

/// At most this many refused navigations are kept for the exit report.
const REFUSALS_KEPT: usize = 64;

pub(crate) fn command() {
    COMMANDS.fetch_add(1, Ordering::SeqCst);
}

pub(crate) fn web_message() {
    WEB_MESSAGES.fetch_add(1, Ordering::SeqCst);
}

pub(crate) fn new_window_request() {
    NEW_WINDOW_REQUESTS.fetch_add(1, Ordering::SeqCst);
}

pub(crate) fn download_request() {
    DOWNLOAD_REQUESTS.fetch_add(1, Ordering::SeqCst);
}

/// One step of the window's creation order.
pub(crate) fn step(name: &'static str) {
    if let Ok(mut order) = ORDER.lock() {
        order.push(name);
    }
}

pub(crate) fn refused_navigation(description: String) {
    if let Ok(mut refused) = REFUSED_NAVIGATIONS.lock() {
        if refused.len() < REFUSALS_KEPT {
            refused.push(description);
        }
    }
}

pub(crate) fn webview2_version(version: String) {
    if let Ok(mut slot) = WEBVIEW2_VERSION.lock() {
        *slot = version
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '.')
            .take(32)
            .collect();
    }
}

/// The steps so far, for the shell's own ordering decisions and the report.
pub fn steps() -> Vec<&'static str> {
    ORDER.lock().map(|order| order.clone()).unwrap_or_default()
}

/// The exit report, one line each.
pub fn lines() -> Vec<String> {
    let refused = REFUSED_NAVIGATIONS
        .lock()
        .map(|refused| refused.clone())
        .unwrap_or_default();
    let version = WEBVIEW2_VERSION
        .lock()
        .map(|version| version.clone())
        .unwrap_or_default();
    let mut lines = vec![
        format!("SG119-ORDER {}", steps().join(" ")),
        format!(
            "SG119-WEBVIEW2 version={}",
            if version.is_empty() {
                "unknown"
            } else {
                &version
            }
        ),
    ];
    lines.extend(refused.iter().map(|url| format!("SG119-NAV-REFUSED {url}")));
    lines.push(format!("SG119-NAV refused={}", refused.len()));
    let requests = NEW_WINDOW_REQUESTS.load(Ordering::SeqCst);
    lines.push(format!(
        "SG119-NEWWINDOW requests={requests} denied={requests}"
    ));
    let downloads = DOWNLOAD_REQUESTS.load(Ordering::SeqCst);
    lines.push(format!(
        "SG119-DOWNLOAD requests={downloads} refused={downloads}"
    ));
    lines.push(format!(
        "SG119-IPC commands={} web_messages={}",
        COMMANDS.load(Ordering::SeqCst),
        WEB_MESSAGES.load(Ordering::SeqCst)
    ));
    lines
}
