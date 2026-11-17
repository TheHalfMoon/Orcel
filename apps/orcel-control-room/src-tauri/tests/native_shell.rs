//! SG-000119 A2 native Windows tests: the real window on WebView2.
//!
//! The test binary is its own driver (`harness = false`): Tauri's event loop
//! must own a process's main thread and starts once per process, so each
//! window scenario runs in a child process. Two kinds of child:
//!
//! - **the shell binary itself** (`orcel-control-room-shell.exe`, nothing
//!   added): a `WEBVIEW2_*` variable stops it; a held or squatted mutex
//!   stops it; its window opens hidden, is found by name only after the
//!   reload, a second instance exits, and it closes on `WM_CLOSE` with its
//!   exit report;
//! - **this test binary with `--sg119-scenario`**, which runs the same
//!   `run` with test hooks: after the window is shown, scripts are evaluated
//!   from Rust (nothing is added to the page) to call a command, open new
//!   windows, navigate off the origin and start a download; or a setting is
//!   flipped before the readback.
//!
//! Every count comes from the shell's own exit report (`SG119-*` lines),
//! counted on the Rust side.

use orcel_control_room_shell::{run, shell, single_instance, Hooks};
use std::io::Read;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{BOOL, HWND, LPARAM};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    EnumWindows, GetClassNameW, GetWindowTextW, GetWindowThreadProcessId, IsWindowVisible,
    PostMessageW, WM_CLOSE,
};

const SCENARIO: &str = "--sg119-scenario";
const SHELL: &str = env!("CARGO_BIN_EXE_orcel-control-room-shell");

/// Off-origin navigations the probe scenario tries, and how the shell
/// reports each refusal (scheme, userinfo marker, host and port).
const NAVIGATIONS: [(&str, &str); 7] = [
    // An asset opened as a page: on the origin but not one of the two pages
    // (the refusal line never carries the path).
    (
        "https://tauri.localhost/style.css",
        "https://tauri.localhost",
    ),
    (
        "https://tauri.localhost.evil/",
        "https://tauri.localhost.evil",
    ),
    ("http://tauri.localhost/", "http://tauri.localhost"),
    (
        "https://tauri.localhost:8443/",
        "https://tauri.localhost:8443",
    ),
    (
        "https://user@tauri.localhost/",
        "https://<userinfo>@tauri.localhost",
    ),
    ("https://ipc.localhost/", "https://ipc.localhost"),
    ("http://127.0.0.1/", "http://127.0.0.1"),
];
/// Navigations Chromium may stop before the shell sees them; either way the
/// page must stay on the asset origin.
const BLOCKED_ANYWAY: [&str; 2] = ["file:///C:/Windows/win.ini", "data:text/html,x"];
const COMMAND_CALLS: usize = 3;
/// SG-000119 A4: the view's own calls when it loads (app_status,
/// app_capabilities, app_tasks and app_events, once each). Without an orceld
/// it makes no other: it reads again only once orceld answers.
const PAGE_CALLS: usize = 4;

/// Whether this user's own orceld answers (on a developer's PC it may; on a
/// CI runner it does not). When it does, the view also reads the tasks and
/// events it reports, so the shell serves more than the calls counted here.
fn this_users_orceld_answers() -> bool {
    orcel_app_api_client::AppApiClient::for_this_user()
        .map(|client| client.status().is_ok())
        .unwrap_or(false)
}

/// `SG119-IPC commands=<n> web_messages=0`, with `n` exactly `expected`
/// (at least `expected` while this user's orceld answers).
fn assert_ipc(finished: &Finished, expected: usize) {
    let line = finished.line("SG119-IPC ");
    let served: usize = line
        .strip_prefix("SG119-IPC commands=")
        .and_then(|rest| rest.strip_suffix(" web_messages=0"))
        .and_then(|n| n.parse().ok())
        .unwrap_or_else(|| panic!("{line}"));
    if this_users_orceld_answers() {
        assert!(served >= expected, "{line}: at least {expected} expected");
    } else {
        assert_eq!(served, expected, "{line}");
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if let Some(at) = args.iter().position(|arg| arg == SCENARIO) {
        let code = match args.get(at + 1).map(String::as_str) {
            Some("probes") => scenario_probes(),
            Some("tamper") => scenario_tamper(),
            other => {
                eprintln!("unknown scenario {other:?}");
                64
            }
        };
        std::process::exit(code);
    }
    if args.iter().any(|arg| arg == "--list") {
        return;
    }
    let cases: [(&str, fn()); 6] = [
        (
            "a_webview2_variable_in_any_case_stops_startup",
            environment_override,
        ),
        ("a_second_instance_exits_already_open", second_instance),
        (
            "a_squatted_name_exits_with_the_squatter_message",
            squatted_name,
        ),
        (
            "the_real_window_shows_after_the_reload_and_closes",
            real_window,
        ),
        ("probes_ipc_new_windows_navigation_and_downloads", probes),
        ("a_settings_mismatch_closes_the_window", settings_mismatch),
    ];
    let mut failed = Vec::new();
    for (name, case) in cases {
        println!("test {name} ...");
        match std::panic::catch_unwind(case) {
            Ok(()) => println!("test {name} ... ok"),
            Err(_) => {
                println!("test {name} ... FAILED");
                failed.push(name);
            }
        }
    }
    println!(
        "test result: {}. {} passed; {} failed",
        if failed.is_empty() { "ok" } else { "FAILED" },
        cases.len() - failed.len(),
        failed.len()
    );
    if !failed.is_empty() {
        std::process::exit(1);
    }
}

// ---------------------------------------------------------------------------
// Child processes

struct Finished {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

impl Finished {
    fn lines(&self, prefix: &str) -> Vec<&str> {
        self.stdout
            .lines()
            .filter(|line| line.starts_with(prefix))
            .collect()
    }

    fn line(&self, prefix: &str) -> &str {
        let lines = self.lines(prefix);
        assert_eq!(
            lines.len(),
            1,
            "one {prefix} line expected in:\n{}",
            self.stdout
        );
        lines[0]
    }

    fn order(&self) -> Vec<&str> {
        self.line("SG119-ORDER ")["SG119-ORDER ".len()..]
            .split(' ')
            .collect()
    }

    fn show(&self, label: &str) {
        println!("--- {label}: exit {:?}", self.code);
        for line in self.stdout.lines().chain(self.stderr.lines()) {
            println!("    {line}");
        }
    }
}

fn spawn(command: &mut Command) -> Child {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn the child")
}

fn shell_command() -> Command {
    let mut command = Command::new(SHELL);
    // A child must not inherit a WEBVIEW2_* variable from the test's own
    // environment by accident.
    for (name, _) in std::env::vars_os() {
        if orcel_control_room_shell::environment::names_webview2(&name) {
            command.env_remove(name);
        }
    }
    command
}

fn scenario_command(name: &str) -> Command {
    let mut command = Command::new(std::env::current_exe().expect("this test binary"));
    command.args([SCENARIO, name]);
    command
}

/// Waits for `child` up to `limit`, killing it after that.
fn finish(mut child: Child, limit: Duration) -> Finished {
    let mut out = child.stdout.take().expect("stdout");
    let mut err = child.stderr.take().expect("stderr");
    let out = std::thread::spawn(move || {
        let mut text = String::new();
        let _ = out.read_to_string(&mut text);
        text
    });
    let err = std::thread::spawn(move || {
        let mut text = String::new();
        let _ = err.read_to_string(&mut text);
        text
    });
    let start = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll the child") {
            break Some(status);
        }
        if start.elapsed() > limit {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let finished = Finished {
        code: status.and_then(|status| status.code()),
        stdout: out.join().unwrap_or_default(),
        stderr: err.join().unwrap_or_default(),
    };
    assert!(status.is_some(), "the child did not exit within {limit:?}");
    finished
}

// ---------------------------------------------------------------------------
// Windows of a process

struct Search {
    pids: Vec<u32>,
    title: Option<String>,
    found: Vec<TopLevel>,
}

struct TopLevel {
    hwnd: HWND,
    pid: u32,
    title: String,
    class: String,
    visible: bool,
}

/// tao's hidden helper window: a 14x14 top-level window per event loop that
/// never shows content. It is not a window the page could have opened.
const TAO_EVENT_TARGET: &str = "Tao Thread Event Target";

fn text_of(read: impl FnOnce(&mut [u16]) -> i32) -> String {
    let mut buffer = [0u16; 256];
    let length = read(&mut buffer);
    String::from_utf16_lossy(&buffer[..length.clamp(0, 256) as usize])
}

unsafe extern "system" fn collect(hwnd: HWND, data: LPARAM) -> BOOL {
    // SAFETY: `data` is the &mut Search passed to EnumWindows below.
    let search = unsafe { &mut *(data as *mut Search) };
    let mut pid = 0u32;
    // SAFETY: plain queries on a window handle EnumWindows hands out; each
    // buffer holds 256 UTF-16 units.
    unsafe { GetWindowThreadProcessId(hwnd, &mut pid) };
    if search.pids.contains(&pid) {
        let title = text_of(|buffer| unsafe { GetWindowTextW(hwnd, buffer.as_mut_ptr(), 256) });
        let class = text_of(|buffer| unsafe { GetClassNameW(hwnd, buffer.as_mut_ptr(), 256) });
        // SAFETY: plain query.
        let visible = unsafe { IsWindowVisible(hwnd) } != 0;
        if search.title.as_deref().is_none_or(|wanted| wanted == title) {
            search.found.push(TopLevel {
                hwnd,
                pid,
                title,
                class,
                visible,
            });
        }
    }
    1
}

/// Top-level windows of the processes `pids` (titled `title`, if given).
fn windows_of(pids: &[u32], title: Option<&str>) -> Vec<TopLevel> {
    let mut search = Search {
        pids: pids.to_vec(),
        title: title.map(str::to_owned),
        found: Vec::new(),
    };
    // SAFETY: `search` outlives the call; `collect` only reads it through
    // the pointer during the call.
    unsafe { EnumWindows(Some(collect), &mut search as *mut Search as LPARAM) };
    search.found
}

/// `pid` and every process descended from it (the WebView2 browser and its
/// renderers are children of the shell: a popup WebView2 opened itself would
/// belong to one of them).
fn process_tree(pid: u32) -> Vec<u32> {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    let mut pairs = Vec::new();
    // SAFETY: a process snapshot walked once and closed.
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        assert_ne!(snapshot, INVALID_HANDLE_VALUE);
        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut more = Process32FirstW(snapshot, &mut entry) != 0;
        while more {
            pairs.push((entry.th32ProcessID, entry.th32ParentProcessID));
            more = Process32NextW(snapshot, &mut entry) != 0;
        }
        CloseHandle(snapshot);
    }
    let mut tree = vec![pid];
    let mut grew = true;
    while grew {
        grew = false;
        for (child, parent) in &pairs {
            if tree.contains(parent) && !tree.contains(child) {
                tree.push(*child);
                grew = true;
            }
        }
    }
    tree
}

/// Visible top-level windows of `pid` and its descendants, tao's helper
/// window aside, each printed.
fn visible_toplevel_count(pid: u32) -> usize {
    let windows: Vec<TopLevel> = windows_of(&process_tree(pid), None)
        .into_iter()
        .filter(|window| window.visible && window.class != TAO_EVENT_TARGET)
        .collect();
    for window in &windows {
        eprintln!(
            "    visible top-level window: pid {} class {} title {:?}",
            window.pid, window.class, window.title
        );
    }
    windows.len()
}

/// Kills a child still running when a case fails.
struct Running(Option<Child>);

impl Running {
    fn take(mut self) -> Child {
        self.0.take().expect("the child")
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// UI Automation, read-only: the name of the first top-level element named
/// `name` among the desktop's children, if any (no keystroke, no click).
fn ui_automation_finds(name: &str) -> bool {
    let script = format!(
        "Add-Type -AssemblyName UIAutomationClient; Add-Type -AssemblyName UIAutomationTypes; \
         $c = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::NameProperty, '{name}'); \
         $e = [System.Windows.Automation.AutomationElement]::RootElement.FindFirst([System.Windows.Automation.TreeScope]::Children, $c); \
         if ($e) {{ 'FOUND ' + $e.Current.Name + ' ' + $e.Current.ControlType.ProgrammaticName }} else {{ 'MISSING' }}"
    );
    let output = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
        .expect("run powershell");
    let text = String::from_utf8_lossy(&output.stdout);
    println!("    UI Automation: {}", text.trim());
    text.trim_start().starts_with(&format!("FOUND {name}"))
}

// ---------------------------------------------------------------------------
// Cases

fn environment_override() {
    let finished = finish(
        spawn(shell_command().env("WebView2_User_Data_Folder", r"C:\sg119-unused")),
        Duration::from_secs(30),
    );
    finished.show("shell with WebView2_User_Data_Folder set");
    assert_eq!(finished.code, Some(shell::exit::ENVIRONMENT));
    assert!(
        finished
            .stderr
            .contains("refuses to start: the environment sets WebView2_User_Data_Folder"),
        "{}",
        finished.stderr
    );
    assert!(finished.stdout.is_empty(), "no window, no report");
}

fn second_instance() {
    let held = single_instance::acquire().expect("the test takes the shell's mutex");
    let finished = finish(spawn(&mut shell_command()), Duration::from_secs(30));
    drop(held);
    finished.show("shell while the mutex is held");
    assert_eq!(finished.code, Some(shell::exit::ALREADY_OPEN));
    assert!(finished
        .stderr
        .contains("Orcel Control Room is already open"));
    assert!(finished.stdout.is_empty(), "no window, no report");
}

/// The real name, created first under a protected empty DACL: what another
/// account's mutex looks like to this user.
fn squatted_name() {
    use windows_sys::Win32::Foundation::{CloseHandle, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::System::Threading::CreateMutexW;
    let wide = |text: &str| -> Vec<u16> { text.encode_utf16().chain(Some(0)).collect() };
    let sid = orcel_app_api_client::this_user_sid().expect("this user's SID");
    let name = wide(&single_instance::mutex_name(&sid));
    let sddl = wide("D:P");
    let mut descriptor = std::ptr::null_mut();
    // SAFETY: plain Win32 calls; the descriptor is freed and the handle
    // closed below.
    let handle = unsafe {
        assert_ne!(
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                std::ptr::null_mut()
            ),
            0
        );
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        };
        let handle = CreateMutexW(&attributes, 0, name.as_ptr());
        LocalFree(descriptor);
        handle
    };
    assert_ne!(handle, 0, "the squatter mutex is created");
    let finished = finish(spawn(&mut shell_command()), Duration::from_secs(30));
    // SAFETY: the handle was created above and is closed once.
    unsafe { CloseHandle(handle) };
    finished.show("shell while the name is squatted");
    assert_eq!(finished.code, Some(shell::exit::NAME_HELD));
    assert!(finished
        .stderr
        .contains("another program holds the Control Room's name; it may be another account"));
    assert!(finished.stdout.is_empty(), "no window, no report");
}

fn real_window() {
    let child = Running(Some(spawn(&mut shell_command())));
    let pid = child.0.as_ref().expect("the child").id();
    let start = Instant::now();
    let hwnd = loop {
        let found = windows_of(&[pid], Some(shell::TITLE));
        if let Some(window) = found.first().filter(|window| window.visible) {
            break window.hwnd;
        }
        assert!(
            start.elapsed() < Duration::from_secs(60),
            "no visible '{}' window from pid {pid}",
            shell::TITLE
        );
        std::thread::sleep(Duration::from_millis(100));
    };
    println!("    visible after {:?}", start.elapsed());
    assert!(
        ui_automation_finds(shell::TITLE),
        "UI Automation finds the window by name"
    );
    assert_eq!(
        visible_toplevel_count(pid),
        1,
        "one visible top-level window"
    );

    let second = finish(spawn(&mut shell_command()), Duration::from_secs(30));
    second.show("a second shell beside the first");
    assert_eq!(second.code, Some(shell::exit::ALREADY_OPEN));
    assert!(second.stderr.contains("Orcel Control Room is already open"));

    // SAFETY: posting WM_CLOSE to the shell's own window.
    assert_ne!(unsafe { PostMessageW(hwnd, WM_CLOSE, 0, 0) }, 0);
    let finished = finish(child.take(), Duration::from_secs(30));
    finished.show("the real shell, closed by WM_CLOSE");
    assert_eq!(finished.code, Some(0));
    assert_order(&finished);
    let version = finished.line("SG119-WEBVIEW2 version=");
    assert_ne!(version, "SG119-WEBVIEW2 version=unknown");
    // The view's own reads on load, each through the custom protocol.
    assert_ipc(&finished, PAGE_CALLS);
    assert_eq!(finished.line("SG119-NAV "), "SG119-NAV refused=0");
}

/// Created hidden, hardened, asserted, reloaded, then shown; the window was
/// not visible before the show.
fn assert_order(finished: &Finished) {
    let order = finished.order();
    let position = |step: &str| {
        order
            .iter()
            .position(|item| *item == step)
            .unwrap_or_else(|| panic!("no {step} in {order:?}"))
    };
    let sequence = [
        "created-hidden",
        "web-message-counter",
        "settings-applied",
        "readback-ok",
        "reload-started",
        "reload-navigation-started",
        "reload-completed",
        "hidden-before-show",
        "shown",
    ];
    for pair in sequence.windows(2) {
        assert!(
            position(pair[0]) < position(pair[1]),
            "{} before {} in {order:?}",
            pair[0],
            pair[1]
        );
    }
    assert!(!order.contains(&"refused"), "{order:?}");
}

fn probes() {
    let finished = finish(
        spawn(&mut scenario_command("probes")),
        Duration::from_secs(180),
    );
    finished.show("probe scenario");
    assert_eq!(finished.code, Some(0));
    assert_order(&finished);
    // Every command call reached Rust through the custom protocol; none came
    // as a web message.
    assert_ipc(&finished, COMMAND_CALLS + PAGE_CALLS);
    // window.open twice and a target=_blank link: each request denied, no
    // window opened.
    assert_eq!(
        finished.line("SG119-NEWWINDOW "),
        "SG119-NEWWINDOW requests=3 denied=3"
    );
    let refused: Vec<&str> = finished
        .lines("SG119-NAV-REFUSED ")
        .into_iter()
        .map(|line| &line["SG119-NAV-REFUSED ".len()..])
        .collect();
    for (_, described) in NAVIGATIONS {
        assert!(
            refused.contains(&described),
            "{described} not refused: {refused:?}"
        );
    }
    let downloads = finished.line("SG119-DOWNLOAD ");
    assert!(
        downloads.starts_with("SG119-DOWNLOAD requests=") && !downloads.contains("requests=0 "),
        "{downloads}"
    );
    let probe = finished.line("SG119-PROBE ");
    assert!(
        probe.starts_with("SG119-PROBE url=https://tauri.localhost/index.html "),
        "{probe}"
    );
    assert!(
        probe.ends_with(" webview_windows=1 visible_toplevel=1"),
        "{probe}"
    );
}

fn settings_mismatch() {
    let finished = finish(
        spawn(&mut scenario_command("tamper")),
        Duration::from_secs(60),
    );
    finished.show("tamper scenario");
    assert_eq!(finished.code, Some(shell::exit::HARDENING));
    assert!(
        finished
            .stderr
            .contains("the WebView2 settings readback did not match: AreDevToolsEnabled is true, expected false"),
        "{}",
        finished.stderr
    );
    let order = finished.order();
    assert!(order.contains(&"refused"), "{order:?}");
    assert!(
        !order.contains(&"readback-ok") && !order.contains(&"shown"),
        "{order:?}"
    );
}

// ---------------------------------------------------------------------------
// Scenarios (in a child process)

fn scenario_probes() -> i32 {
    run(Hooks {
        after_apply: None,
        after_show: Some(Box::new(|window| {
            std::thread::spawn(move || probe(window));
        })),
    })
}

/// How long the probe waits for the shell to record one awaited event. Eleven
/// waits at most, so a run where every one times out still exits (and reports)
/// within the parent's limit.
const EVENT_WAIT: Duration = Duration::from_secs(10);

/// Waits until the shell's own report (read in this process: the same
/// counters the exit report prints) satisfies `seen`, polling for up to
/// [`EVENT_WAIT`]. On a timeout it says so on stderr and goes on; the parent's
/// assertions on the exit report then fail with the counts as they were.
fn wait_for(what: &str, seen: impl Fn(&[String]) -> bool) {
    let start = Instant::now();
    loop {
        if seen(&orcel_control_room_shell::report::lines()) {
            return;
        }
        if start.elapsed() > EVENT_WAIT {
            eprintln!("probe: {what} not seen within {EVENT_WAIT:?}");
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// The number right after `prefix` in the report line starting with it, or
/// zero.
fn reported(lines: &[String], prefix: &str) -> usize {
    lines
        .iter()
        .find_map(|line| line.strip_prefix(prefix))
        .and_then(|rest| rest.split(' ').next())
        .and_then(|n| n.parse().ok())
        .unwrap_or(0)
}

/// Each step waits until the shell has recorded what it expects before the
/// next starts, so the report the parent reads is complete when the window
/// closes, however slowly WebView2 runs.
fn probe(window: tauri::WebviewWindow) {
    let pause = |ms: u64| std::thread::sleep(Duration::from_millis(ms));
    let eval = |script: &str| {
        if let Err(error) = window.eval(script) {
            eprintln!("eval failed: {error}");
        }
    };
    // The view's own calls when it loads.
    wait_for("the page's own command calls", |lines| {
        reported(lines, "SG119-IPC commands=") >= PAGE_CALLS
    });
    // A3: each served command call is counted; a command the ACL refuses is
    // not (it never reaches a handler). Without orceld, app_status answers a
    // typed "unavailable".
    for _ in 0..COMMAND_CALLS {
        eval("window.__TAURI__.core.invoke('app_status').catch(function () {});");
    }
    eval("window.__TAURI__.core.invoke('sg119_native_probe').catch(function () {});");
    wait_for("the probe's command calls", |lines| {
        reported(lines, "SG119-IPC commands=") >= PAGE_CALLS + COMMAND_CALLS
    });
    // Nothing counts the refused sg119_native_probe (it never reaches a
    // handler); give it a moment to be refused before the page moves on.
    pause(500);
    eval("window.open('https://tauri.localhost/index.html');");
    eval("window.open('https://example.invalid/');");
    eval(
        "(function () { var a = document.createElement('a'); a.href = 'https://tauri.localhost/index.html'; \
         a.target = '_blank'; a.textContent = 'x'; document.body.appendChild(a); a.click(); a.remove(); })();",
    );
    wait_for("three new-window requests", |lines| {
        reported(lines, "SG119-NEWWINDOW requests=") >= 3
    });
    // One navigation at a time: the next starts only once the shell has
    // refused this one, so a later assignment to `location` cannot supersede
    // an attempt before its NavigationStarting reached the shell.
    for (url, described) in NAVIGATIONS {
        eval(&format!("window.location.href = '{url}';"));
        let refusal = format!("SG119-NAV-REFUSED {described}");
        wait_for(&format!("the refusal of {url}"), |lines| {
            lines.contains(&refusal)
        });
    }
    // Chromium may stop these before the shell sees them, so there is no
    // event to wait for; the page must stay on the asset origin either way.
    for url in BLOCKED_ANYWAY {
        eval(&format!("window.location.href = '{url}';"));
        pause(800);
    }
    eval(
        "(function () { var a = document.createElement('a'); \
         a.href = URL.createObjectURL(new Blob(['sg119'], { type: 'text/plain' })); \
         a.download = 'sg119-download-probe.txt'; document.body.appendChild(a); a.click(); a.remove(); })();",
    );
    wait_for("the download request", |lines| {
        reported(lines, "SG119-DOWNLOAD requests=") >= 1
    });
    // Let the refused download settle before the URL is read.
    pause(500);
    let url = window
        .url()
        .map(|url| url.to_string())
        .unwrap_or_else(|error| format!("unreadable:{error}"));
    let webview_windows = {
        use tauri::Manager;
        window.app_handle().webview_windows().len()
    };
    println!(
        "SG119-PROBE url={url} webview_windows={webview_windows} visible_toplevel={}",
        visible_toplevel_count(std::process::id())
    );
    use tauri::Manager;
    window.app_handle().exit(0);
}

fn scenario_tamper() -> i32 {
    run(Hooks {
        after_apply: Some(Box::new(|settings| {
            // SAFETY: a plain COM setter on the live settings object.
            let _ = unsafe { settings.SetAreDevToolsEnabled(true) };
        })),
        after_show: None,
    })
}
