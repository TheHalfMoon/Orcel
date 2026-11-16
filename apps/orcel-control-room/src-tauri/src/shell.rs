//! The shell: refusals before anything starts, then one hidden window that
//! is hardened, asserted, reloaded and only then shown.
//!
//! Order (prep packet, "Web view hardening"):
//!
//! 1. Any `WEBVIEW2_*` environment variable, in any letter case, stops
//!    startup ([`crate::environment`]).
//! 2. The single-instance mutex ([`crate::single_instance`]).
//! 3. The `main` window is built from `tauri.conf.json` with `visible(false)`,
//!    `.devtools(false)`, the explicit browser arguments, an explicit user
//!    data folder, exact-origin navigation, new windows denied and downloads
//!    refused.
//! 4. Through the platform web view handle: the Rust-side web message counter
//!    is registered, the WebView2 settings are applied, read back and
//!    asserted (a mismatch closes the window with the setting named).
//! 5. The page is reloaded (a fresh navigation to the asset page), so nothing
//!    loaded before the settings survives.
//! 6. Only when that navigation completes is the window shown.
//!
//! On exit the shell writes its report ([`crate::report`]), including
//! `SG119-IPC commands=<n> web_messages=<m>`.

use crate::commands::{Orceld, Source};
use crate::hardening;
use crate::navigation;
use crate::report;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tauri::webview::{DownloadEvent, NewWindowResponse};
use tauri::{Manager, RunEvent, WebviewWindow, WebviewWindowBuilder};
use webview2_com::Microsoft::Web::WebView2::Win32::{
    ICoreWebView2, ICoreWebView2NavigationCompletedEventArgs,
    ICoreWebView2NavigationStartingEventArgs, ICoreWebView2Settings, COREWEBVIEW2_WEB_ERROR_STATUS,
};
use webview2_com::{
    take_pwstr, NavigationCompletedEventHandler, NavigationStartingEventHandler,
    WebMessageReceivedEventHandler,
};
use windows_core::{BOOL, HSTRING, PWSTR};

/// The window's label in `tauri.conf.json` and the capability file.
pub const MAIN_WINDOW: &str = "main";
/// The window's title, which UI Automation finds it by.
pub const TITLE: &str = "Orcel Control Room";

/// Exit codes.
pub mod exit {
    /// A `WEBVIEW2_*` environment variable is set.
    pub const ENVIRONMENT: i32 = 2;
    /// Another instance of this user is open.
    pub const ALREADY_OPEN: i32 = 3;
    /// The single-instance name is held under a DACL refusing this user.
    pub const NAME_HELD: i32 = 4;
    /// The WebView2 settings readback did not match, or the reload failed.
    pub const HARDENING: i32 = 5;
    /// Anything else stopped startup.
    pub const STARTUP: i32 = 6;
}

/// Runs after the settings are applied and before they are read back.
pub type AfterApply = Box<dyn FnOnce(&ICoreWebView2Settings) + Send>;
/// Runs on the main thread once the window is shown.
pub type AfterShow = Box<dyn FnOnce(WebviewWindow) + Send>;

/// Callbacks the native tests use; the shell binary passes none.
#[derive(Default)]
pub struct Hooks {
    /// See [`AfterApply`].
    pub after_apply: Option<AfterApply>,
    /// See [`AfterShow`].
    pub after_show: Option<AfterShow>,
}

/// Set once the post-settings reload has been asked for.
static RELOAD_REQUESTED: AtomicBool = AtomicBool::new(false);
/// The WebView2 navigation id of the latest navigation to the asset page
/// that started after the reload was asked for (0: none yet).
static RELOAD_NAVIGATION: AtomicU64 = AtomicU64::new(0);
/// Set once the window is shown.
static SHOWN: AtomicBool = AtomicBool::new(false);

/// Runs the shell; the process exit code.
pub fn run(hooks: Hooks) -> i32 {
    if let Err(name) = crate::environment::check() {
        eprintln!(
            "Orcel Control Room refuses to start: the environment sets {name}, which WebView2 \
             would honour. Unset every WEBVIEW2_* variable and start it again."
        );
        return exit::ENVIRONMENT;
    }
    let _instance = match crate::single_instance::acquire() {
        Ok(instance) => instance,
        Err(refusal) => {
            eprintln!("{refusal}");
            return match refusal {
                crate::single_instance::Refusal::AlreadyOpen => exit::ALREADY_OPEN,
                crate::single_instance::Refusal::NameHeldByAnother => exit::NAME_HELD,
                crate::single_instance::Refusal::Os(_) => exit::STARTUP,
            };
        }
    };
    // A3: exactly the five read-only commands, over this user's orceld
    // (`crate::commands`); the ACL refuses every other command before it
    // reaches Rust's handlers.
    let source: Arc<dyn Source> = Arc::new(Orceld::for_this_user());
    let app = crate::commands::register(tauri::Builder::default(), source)
        .setup(move |app| {
            if let Err(reason) = open_main_window(app, hooks) {
                eprintln!("Orcel Control Room could not open its window: {reason}");
                app.handle().exit(exit::STARTUP);
            }
            Ok(())
        })
        .build(crate::commands::context());
    let app = match app {
        Ok(app) => app,
        Err(error) => {
            eprintln!("Orcel Control Room could not start: {error}");
            return exit::STARTUP;
        }
    };
    app.run_return(|handle, event| {
        crate::commands::on_run_event(handle, &event);
        if let RunEvent::Exit = event {
            for line in report::lines() {
                println!("{line}");
            }
        }
    })
}

fn open_main_window(app: &mut tauri::App, hooks: Hooks) -> Result<(), String> {
    let config = app
        .config()
        .app
        .windows
        .iter()
        .find(|window| window.label == MAIN_WINDOW)
        .cloned()
        .ok_or("tauri.conf.json declares no main window")?;
    // The view's cache only, under the Control Room's own per-user folder
    // (%LOCALAPPDATA%\ai.orcel.control-room), outside orceld's state root
    // (%USERPROFILE%\.orcel). No Orcel state is kept there.
    let data_folder = app
        .path()
        .app_local_data_dir()
        .map_err(|error| format!("no per-user data folder: {error}"))?
        .join("WebView2");
    let window = WebviewWindowBuilder::from_config(app.handle(), &config)
        .map_err(|error| error.to_string())?
        .visible(false)
        .devtools(false)
        .additional_browser_args(hardening::BROWSER_ARGS)
        .data_directory(data_folder)
        .on_navigation(|url| {
            let allowed = navigation::allowed(url);
            if !allowed {
                report::refused_navigation(navigation::describe(url));
            }
            allowed
        })
        .on_new_window(|_, _| {
            report::new_window_request();
            NewWindowResponse::Deny
        })
        .on_download(|_, event| {
            if let DownloadEvent::Requested { .. } = event {
                report::download_request();
            }
            false
        })
        .build()
        .map_err(|error| error.to_string())?;
    report::step("created-hidden");
    let hardened = window.clone();
    window
        .with_webview(move |webview| {
            if let Err(reason) = harden(&webview, hardened.clone(), hooks) {
                refuse(&hardened, &reason);
            }
        })
        .map_err(|error| error.to_string())
}

/// Closes the window and the app with a stated reason.
fn refuse(window: &WebviewWindow, reason: &str) {
    eprintln!("Orcel Control Room closed its window: {reason}");
    report::step("refused");
    let _ = window.destroy();
    window.app_handle().exit(exit::HARDENING);
}

fn harden(
    webview: &tauri::webview::PlatformWebview,
    window: WebviewWindow,
    hooks: Hooks,
) -> Result<(), String> {
    // SAFETY: COM calls on the web view's own thread (with_webview runs on
    // the main thread), on interfaces the controller hands out.
    unsafe {
        let core: ICoreWebView2 = webview
            .controller()
            .CoreWebView2()
            .map_err(|error| format!("no ICoreWebView2: {error}"))?;
        let mut token = 0i64;
        core.add_WebMessageReceived(
            &WebMessageReceivedEventHandler::create(Box::new(|_, _| {
                report::web_message();
                Ok(())
            })),
            &mut token,
        )
        .map_err(|error| format!("the web message counter could not be registered: {error}"))?;
        report::step("web-message-counter");

        let settings = core
            .Settings()
            .map_err(|error| format!("no ICoreWebView2Settings: {error}"))?;
        hardening::apply(&settings)?;
        report::step("settings-applied");
        if let Some(after_apply) = hooks.after_apply {
            after_apply(&settings);
        }
        let read = hardening::read_back(&settings)?;
        let mismatches = hardening::mismatches(&read);
        if !mismatches.is_empty() {
            return Err(format!(
                "the WebView2 settings readback did not match: {}",
                mismatches.join("; ")
            ));
        }
        report::step("readback-ok");

        let mut version = PWSTR::null();
        if webview
            .environment()
            .BrowserVersionString(&mut version)
            .is_ok()
        {
            report::webview2_version(take_pwstr(version));
        }

        core.add_NavigationStarting(
            &NavigationStartingEventHandler::create(Box::new(
                |_, args: Option<ICoreWebView2NavigationStartingEventArgs>| {
                    let Some(args) = args else {
                        return Ok(());
                    };
                    if !RELOAD_REQUESTED.load(Ordering::SeqCst) || SHOWN.load(Ordering::SeqCst) {
                        return Ok(());
                    }
                    // Tauri's own first navigation is to the origin's root;
                    // the reload is to the page itself. Its event may arrive
                    // after the reload was asked for, so the reload is
                    // recognised by its URI, and the latest one counts.
                    let mut uri = PWSTR::null();
                    args.Uri(&mut uri)?;
                    if take_pwstr(uri) == navigation::ASSET_PAGE {
                        let mut id = 0u64;
                        args.NavigationId(&mut id)?;
                        RELOAD_NAVIGATION.store(id, Ordering::SeqCst);
                        report::step("reload-navigation-started");
                    }
                    Ok(())
                },
            )),
            &mut token,
        )
        .map_err(|error| format!("the navigation tracker could not be registered: {error}"))?;

        let mut after_show = hooks.after_show;
        let shown = window.clone();
        core.add_NavigationCompleted(
            &NavigationCompletedEventHandler::create(Box::new(
                move |_, args: Option<ICoreWebView2NavigationCompletedEventArgs>| {
                    let Some(args) = args else {
                        return Ok(());
                    };
                    let mut id = 0u64;
                    args.NavigationId(&mut id)?;
                    if SHOWN.load(Ordering::SeqCst) {
                        return Ok(());
                    }
                    let reload = RELOAD_NAVIGATION.load(Ordering::SeqCst);
                    if reload == 0 || id != reload {
                        // A navigation from before the reload ended (the
                        // reload supersedes it); it never shows the window.
                        report::step("earlier-navigation-ended");
                        return Ok(());
                    }
                    let mut success = BOOL::default();
                    args.IsSuccess(&mut success)?;
                    if !success.as_bool() {
                        let mut status = COREWEBVIEW2_WEB_ERROR_STATUS::default();
                        let _ = args.WebErrorStatus(&mut status);
                        refuse(
                            &shown,
                            &format!(
                                "the page did not load after the settings were applied (WebView2 \
                                 error status {})",
                                status.0
                            ),
                        );
                        return Ok(());
                    }
                    report::step("reload-completed");
                    if !is_visible(&shown) {
                        report::step("hidden-before-show");
                    }
                    SHOWN.store(true, Ordering::SeqCst);
                    if let Err(error) = shown.show() {
                        refuse(&shown, &format!("the window could not be shown: {error}"));
                        return Ok(());
                    }
                    report::step("shown");
                    if let Some(after_show) = after_show.take() {
                        after_show(shown.clone());
                    }
                    Ok(())
                },
            )),
            &mut token,
        )
        .map_err(|error| format!("the reload tracker could not be registered: {error}"))?;

        RELOAD_REQUESTED.store(true, Ordering::SeqCst);
        report::step("reload-started");
        core.Navigate(&HSTRING::from(navigation::ASSET_PAGE))
            .map_err(|error| format!("the reload could not start: {error}"))?;
    }
    // A window that never finishes its reload is closed, not left hidden.
    std::thread::spawn(move || {
        std::thread::sleep(SHOW_DEADLINE);
        if !SHOWN.load(Ordering::SeqCst) {
            refuse(&window, "the page did not finish loading in time");
        }
    });
    Ok(())
}

/// How long the hidden window may take to reload before it is closed.
const SHOW_DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);

/// Whether the window is visible on screen, read from Windows directly.
fn is_visible(window: &WebviewWindow) -> bool {
    use windows_sys::Win32::UI::WindowsAndMessaging::IsWindowVisible;
    match window.hwnd() {
        // SAFETY: a plain query on the window's own handle.
        Ok(hwnd) => unsafe { IsWindowVisible(hwnd.0 as isize) != 0 },
        Err(_) => false,
    }
}
