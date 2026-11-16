//! SG-000119 slice A2: the Orcel Control Room shell skeleton (Windows).
//!
//! A lean Tauri 2 window: no Vite, no Tauri CLI, no React, no plugin, the
//! configuration written from scratch. It shows a static "not connected"
//! page (slice A4 builds the view) and, since slice A3, serves exactly five
//! read-only commands over `orcel-app-api-client` ([`commands`]). The
//! preparation packet is
//! `docs/orcel/implementation-readiness/prep/SG-000119.md`.
//!
//! What A2 holds:
//!
//! - **Refusals before anything starts:** any `WEBVIEW2_*` environment
//!   variable in any letter case ([`environment`]); a second instance or a
//!   squatted name ([`single_instance`]).
//! - **A hidden window, hardened, asserted, reloaded, then shown**
//!   ([`shell`], [`hardening`]): devtools off three ways, default context
//!   menus, browser accelerator keys, the status bar, general autofill,
//!   password autosave, host objects, the built-in error page and web
//!   messages off, each read back; the explicit browser arguments; an
//!   explicit user data folder.
//! - **Exact-origin navigation** ([`navigation`]), new windows denied through
//!   Tauri's `on_new_window`, every download refused.
//! - **Configuration** (`tauri.conf.json`): the recorded CSP, embedded assets,
//!   no asset protocol, a frozen prototype, `useHttpsScheme`, no drag and
//!   drop, no `devUrl`, bundling off; one capability file for the `main`
//!   window granting exactly the five commands' permissions.
//! - **The five commands** ([`commands`], A3): `app_status`,
//!   `app_capabilities`, `app_events`, `app_tasks` and `app_task`, each over
//!   the A1 client and returning only its sanitiser's output.
//! - **Rust-side IPC counting** ([`report`]): `SG119-IPC commands=<n>
//!   web_messages=<m>` on exit.

#[cfg(not(windows))]
compile_error!(
    "SG-000119 qualifies the Control Room shell on Windows only (founder decision 2); \
     macOS and Linux are later, independently qualified stages"
);

pub mod commands;
pub mod environment;
pub mod hardening;
pub mod navigation;
pub mod report;
pub mod shell;
pub mod single_instance;

pub use shell::{run, Hooks};
