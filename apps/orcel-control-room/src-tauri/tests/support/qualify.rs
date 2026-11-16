//! SG-000119 A5 helpers shared by `native_qualify` and `native_live`
//! (included with `#[path]`; not a test target of its own).
//!
//! Read-only by construction: process and window queries, a token's
//! integrity, a named pipe opened under a renderer's own token, and a UI
//! Automation tree read through PowerShell. Nothing here sends a keystroke,
//! a mouse event or a focus change; the input helpers live in
//! `native_qualify.rs` behind `ORCEL_ALLOW_INPUT_TESTS=1`.
//!
//! Never print this user's SID: pipe names built here carry none, and the
//! security descriptor that does is never printed.

#![allow(dead_code)]

use serde_json::Value;
use std::collections::HashMap;
use std::process::Command;
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, BOOL, GENERIC_READ, GENERIC_WRITE, HANDLE, HWND,
    INVALID_HANDLE_VALUE, LPARAM, PSID,
};

/// Mandatory integrity RIDs.
pub const UNTRUSTED: u32 = 0x0000;
pub const LOW: u32 = 0x1000;
pub const MEDIUM: u32 = 0x2000;

/// `ERROR_ACCESS_DENIED`.
pub const ACCESS_DENIED: u32 = 5;

pub fn rid_name(rid: u32) -> String {
    match rid {
        0x0000 => "untrusted".into(),
        0x1000 => "low".into(),
        0x2000 => "medium".into(),
        0x2100 => "medium-plus".into(),
        0x3000 => "high".into(),
        0x4000 => "system".into(),
        other => format!("0x{other:x}"),
    }
}

pub fn error_name(code: u32) -> String {
    match code {
        0 => "opened".into(),
        2 => "ERROR_FILE_NOT_FOUND".into(),
        5 => "ERROR_ACCESS_DENIED".into(),
        231 => "ERROR_PIPE_BUSY".into(),
        1346 => "ERROR_BAD_IMPERSONATION_LEVEL".into(),
        other => format!("error {other}"),
    }
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(Some(0)).collect()
}

// ---------------------------------------------------------------------------
// Processes

#[derive(Clone, Debug)]
pub struct Proc {
    pub pid: u32,
    pub parent: u32,
    pub exe: String,
}

pub fn processes() -> Vec<Proc> {
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    let mut all = Vec::new();
    // SAFETY: a process snapshot walked once and closed.
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        assert_ne!(snapshot, INVALID_HANDLE_VALUE);
        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut more = Process32FirstW(snapshot, &mut entry) != 0;
        while more {
            let length = entry
                .szExeFile
                .iter()
                .position(|unit| *unit == 0)
                .unwrap_or(entry.szExeFile.len());
            all.push(Proc {
                pid: entry.th32ProcessID,
                parent: entry.th32ParentProcessID,
                exe: String::from_utf16_lossy(&entry.szExeFile[..length]),
            });
            more = Process32NextW(snapshot, &mut entry) != 0;
        }
        CloseHandle(snapshot);
    }
    all
}

/// `root` and every process descended from it.
pub fn tree(root: u32) -> Vec<Proc> {
    let all = processes();
    let mut pids = vec![root];
    let mut grew = true;
    while grew {
        grew = false;
        for proc in &all {
            if pids.contains(&proc.parent) && !pids.contains(&proc.pid) && proc.pid != 0 {
                pids.push(proc.pid);
                grew = true;
            }
        }
    }
    all.into_iter()
        .filter(|proc| pids.contains(&proc.pid))
        .collect()
}

/// Chromium's `--type=` for each process (from its command line, read
/// through WMI); only the type is kept, never the rest of the line.
pub fn process_types(pids: &[u32]) -> HashMap<u32, String> {
    if pids.is_empty() {
        return HashMap::new();
    }
    let filter = pids
        .iter()
        .map(|pid| format!("ProcessId = {pid}"))
        .collect::<Vec<_>>()
        .join(" OR ");
    let script = format!(
        "Get-CimInstance Win32_Process -Filter '{filter}' | ForEach-Object {{ \
         $t = 'browser'; if ($_.CommandLine -match '--type=([a-z-]+)') {{ $t = $Matches[1] }}; \
         \"$($_.ProcessId) $t\" }}"
    );
    let output = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
        .expect("run powershell");
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            let (pid, kind) = line.trim().split_once(' ')?;
            Some((pid.parse().ok()?, kind.to_owned()))
        })
        .collect()
}

/// What a token says about its sandbox.
#[derive(Clone, Copy, Debug)]
pub struct TokenFacts {
    pub integrity: u32,
    pub app_container: bool,
    pub restricted: bool,
}

/// # Safety
/// `token` must be a token handle opened with `TOKEN_QUERY`.
unsafe fn token_facts(token: HANDLE) -> Result<TokenFacts, String> {
    use windows_sys::Win32::Security::{
        GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, IsTokenRestricted,
        TokenIntegrityLevel, TokenIsAppContainer, TOKEN_MANDATORY_LABEL,
    };
    let mut buffer = [0u64; 32];
    let mut length = 0u32;
    if GetTokenInformation(
        token,
        TokenIntegrityLevel,
        buffer.as_mut_ptr().cast(),
        std::mem::size_of_val(&buffer) as u32,
        &mut length,
    ) == 0
    {
        return Err(format!("TokenIntegrityLevel: error {}", GetLastError()));
    }
    let label = &*(buffer.as_ptr() as *const TOKEN_MANDATORY_LABEL);
    let sid: PSID = label.Label.Sid;
    let count = *GetSidSubAuthorityCount(sid);
    let integrity = *GetSidSubAuthority(sid, u32::from(count.saturating_sub(1)));
    let mut container = 0u32;
    let app_container = GetTokenInformation(
        token,
        TokenIsAppContainer,
        (&mut container as *mut u32).cast(),
        4,
        &mut length,
    ) != 0
        && container != 0;
    Ok(TokenFacts {
        integrity,
        app_container,
        restricted: IsTokenRestricted(token) != 0,
    })
}

/// The token facts of process `pid` (`PROCESS_QUERY_LIMITED_INFORMATION`).
pub fn process_token(pid: u32) -> Result<TokenFacts, String> {
    use windows_sys::Win32::Security::TOKEN_QUERY;
    use windows_sys::Win32::System::Threading::{
        OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    // SAFETY: handles opened here are closed here.
    unsafe {
        let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if process == 0 {
            return Err(format!("OpenProcess: error {}", GetLastError()));
        }
        let mut token = 0;
        let opened = OpenProcessToken(process, TOKEN_QUERY, &mut token);
        let error = GetLastError();
        CloseHandle(process);
        if opened == 0 {
            return Err(format!("OpenProcessToken: error {error}"));
        }
        let facts = token_facts(token);
        CloseHandle(token);
        facts
    }
}

/// What happened when a pipe was opened under a borrowed token.
#[derive(Clone, Copy, Debug)]
pub struct PipeProbe {
    /// The thread's token while the open ran (read back, so the probe knows
    /// the impersonation took effect at the renderer's integrity).
    pub thread: TokenFacts,
    /// 0 when the open succeeded, otherwise the Win32 error.
    pub open: u32,
}

/// Opens `pipe` exactly as orceld's clients do (read and write,
/// identification-only) on a fresh thread impersonating process `pid`'s own
/// token, then reverts. The pipe is closed at once if it opens.
pub fn open_pipe_as(pid: u32, pipe: &str) -> Result<PipeProbe, String> {
    use windows_sys::Win32::Security::{
        DuplicateTokenEx, SecurityImpersonation, TokenImpersonation, TOKEN_DUPLICATE,
        TOKEN_IMPERSONATE, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::{
        OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    // SAFETY: handles opened here are closed here.
    let borrowed = unsafe {
        let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if process == 0 {
            return Err(format!("OpenProcess: error {}", GetLastError()));
        }
        let mut token = 0;
        let opened = OpenProcessToken(process, TOKEN_QUERY | TOKEN_DUPLICATE, &mut token);
        let error = GetLastError();
        CloseHandle(process);
        if opened == 0 {
            return Err(format!("OpenProcessToken: error {error}"));
        }
        let mut duplicate = 0;
        let made = DuplicateTokenEx(
            token,
            TOKEN_IMPERSONATE | TOKEN_QUERY,
            std::ptr::null(),
            SecurityImpersonation,
            TokenImpersonation,
            &mut duplicate,
        );
        let error = GetLastError();
        CloseHandle(token);
        if made == 0 {
            return Err(format!("DuplicateTokenEx: error {error}"));
        }
        duplicate
    };
    let name = wide(pipe);
    let result = std::thread::spawn(move || {
        use windows_sys::Win32::Security::RevertToSelf;
        use windows_sys::Win32::System::Threading::{
            GetCurrentThread, OpenThreadToken, SetThreadToken,
        };
        // SAFETY: the impersonation is confined to this thread and reverted
        // before it ends; handles are closed here.
        unsafe {
            if SetThreadToken(std::ptr::null(), borrowed) == 0 {
                return Err(format!("SetThreadToken: error {}", GetLastError()));
            }
            let mut thread_token = 0;
            let facts =
                if OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut thread_token) != 0 {
                    let facts = token_facts(thread_token);
                    CloseHandle(thread_token);
                    facts
                } else {
                    Err(format!("OpenThreadToken: error {}", GetLastError()))
                };
            let open = open_pipe(&name);
            RevertToSelf();
            facts.map(|thread| PipeProbe { thread, open })
        }
    })
    .join()
    .map_err(|_| "the probe thread panicked".to_owned());
    // SAFETY: the duplicate made above, closed once.
    unsafe { CloseHandle(borrowed) };
    result?
}

/// Opens `pipe` as this process, as orceld's clients do; 0 when it opened.
pub fn open_pipe_as_self(pipe: &str) -> u32 {
    open_pipe(&wide(pipe))
}

fn open_pipe(name: &[u16]) -> u32 {
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, OPEN_EXISTING, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT,
    };
    // SAFETY: `name` is NUL-terminated; the handle, if any, is closed.
    unsafe {
        let handle = CreateFileW(
            name.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            std::ptr::null(),
            OPEN_EXISTING,
            SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
            0,
        );
        if handle == INVALID_HANDLE_VALUE {
            GetLastError()
        } else {
            CloseHandle(handle);
            0
        }
    }
}

/// orceld's pipe security descriptor, `{sid}` standing for this user's SID.
/// [`assert_orceld_pipe_sddl_matches`] reads orceld's source and fails if
/// orceld's own `sddl` function builds anything else.
pub const ORCELD_PIPE_SDDL: &str = "D:P(A;;GA;;;{sid})S:(ML;;NWNR;;;ME)";

/// Fails unless `crates/orceld/src/app_api.rs` builds exactly
/// [`ORCELD_PIPE_SDDL`] in its `sddl` function (the test's copy cannot drift).
pub fn assert_orceld_pipe_sddl_matches() {
    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../crates/orceld/src/app_api.rs");
    let text = std::fs::read_to_string(&source)
        .unwrap_or_else(|error| panic!("read {}: {error}", source.display()));
    let start = text
        .find("fn sddl(sid: &str) -> String {")
        .expect("orceld's app_api.rs defines fn sddl(sid: &str) -> String");
    let body = &text[start..];
    // The function ends at the first line holding only its closing brace
    // (the descriptor's own `{sid}` braces are inside the string).
    let body = &body[..body.find("\n    }").expect("the function's end")];
    let built: Vec<&str> = body
        .split("format!(\"")
        .skip(1)
        .filter_map(|rest| rest.split_once("\")").map(|(literal, _)| literal))
        .collect();
    assert_eq!(
        built,
        [ORCELD_PIPE_SDDL],
        "the test's copy of orceld's pipe descriptor differs from orceld's sddl()"
    );
}

/// A pipe served by this test under orceld's own security descriptor
/// (`D:P(A;;GA;;;<this user>)S:(ML;;NWNR;;;ME)`, `crates/orceld/src/app_api.rs`),
/// with a name that carries no SID.
pub struct OrceldStylePipe(HANDLE);

impl OrceldStylePipe {
    pub fn create(name: &str) -> Self {
        use windows_sys::Win32::Foundation::LocalFree;
        use windows_sys::Win32::Security::Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
        };
        use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX,
        };
        use windows_sys::Win32::System::Pipes::{
            CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE,
            PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
        };
        assert_orceld_pipe_sddl_matches();
        let sid = orcel_app_api_client::this_user_sid().expect("this user's SID");
        let sddl = wide(&ORCELD_PIPE_SDDL.replace("{sid}", &sid));
        let name = wide(name);
        let mut descriptor = std::ptr::null_mut();
        // SAFETY: plain Win32 calls; the descriptor is freed below.
        unsafe {
            assert_ne!(
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl.as_ptr(),
                    SDDL_REVISION_1,
                    &mut descriptor,
                    std::ptr::null_mut()
                ),
                0,
                "orceld's security descriptor converts"
            );
            let attributes = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: descriptor,
                bInheritHandle: 0,
            };
            let handle = CreateNamedPipeW(
                name.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                PIPE_UNLIMITED_INSTANCES,
                4096,
                4096,
                0,
                &attributes,
            );
            let error = GetLastError();
            LocalFree(descriptor);
            assert_ne!(
                handle, INVALID_HANDLE_VALUE,
                "the test pipe is created (error {error})"
            );
            OrceldStylePipe(handle)
        }
    }
}

impl Drop for OrceldStylePipe {
    fn drop(&mut self) {
        // SAFETY: the server handle created above, closed once.
        unsafe { CloseHandle(self.0) };
    }
}

/// One line per process of the shell's tree: its executable, Chromium type,
/// token facts and, for every process below Medium integrity, what opening
/// `pipe` under its own token gave. Returns the lines and the sandboxed
/// probes as (type, facts, probe).
pub fn probe_tree(
    shell_pid: u32,
    pipe: &str,
) -> (Vec<String>, Vec<(String, TokenFacts, PipeProbe)>) {
    let procs = tree(shell_pid);
    let types = process_types(&procs.iter().map(|proc| proc.pid).collect::<Vec<_>>());
    let mut lines = Vec::new();
    let mut probes = Vec::new();
    for proc in &procs {
        let kind = if proc.pid == shell_pid {
            "shell".to_owned()
        } else {
            types
                .get(&proc.pid)
                .cloned()
                .unwrap_or_else(|| "unknown".into())
        };
        match process_token(proc.pid) {
            Ok(facts) => {
                let mut line = format!(
                    "exe={} type={kind} integrity={} appcontainer={} restricted={}",
                    proc.exe,
                    rid_name(facts.integrity),
                    facts.app_container,
                    facts.restricted
                );
                if facts.integrity < MEDIUM {
                    match open_pipe_as(proc.pid, pipe) {
                        Ok(probe) => {
                            line.push_str(&format!(
                                " impersonated={} open={}",
                                rid_name(probe.thread.integrity),
                                error_name(probe.open)
                            ));
                            probes.push((kind.clone(), facts, probe));
                        }
                        Err(error) => line.push_str(&format!(" probe-failed={error}")),
                    }
                }
                lines.push(line);
            }
            Err(error) => lines.push(format!("exe={} type={kind} token={error}", proc.exe)),
        }
    }
    (lines, probes)
}

// ---------------------------------------------------------------------------
// Windows

pub struct TopLevel {
    pub hwnd: HWND,
    pub pid: u32,
    pub title: String,
    pub class: String,
    pub visible: bool,
}

/// tao's hidden helper window (14 by 14, never content).
pub const TAO_EVENT_TARGET: &str = "Tao Thread Event Target";

struct Search {
    pids: Vec<u32>,
    found: Vec<TopLevel>,
}

fn text_of(read: impl FnOnce(&mut [u16]) -> i32) -> String {
    let mut buffer = [0u16; 256];
    let length = read(&mut buffer);
    String::from_utf16_lossy(&buffer[..length.clamp(0, 256) as usize])
}

unsafe extern "system" fn collect(hwnd: HWND, data: LPARAM) -> BOOL {
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        GetClassNameW, GetWindowTextW, GetWindowThreadProcessId, IsWindowVisible,
    };
    // SAFETY: `data` is the &mut Search passed to EnumWindows below.
    let search = unsafe { &mut *(data as *mut Search) };
    let mut pid = 0u32;
    // SAFETY: plain queries on a handle EnumWindows hands out.
    unsafe { GetWindowThreadProcessId(hwnd, &mut pid) };
    if search.pids.contains(&pid) {
        search.found.push(TopLevel {
            hwnd,
            pid,
            title: text_of(|buffer| unsafe { GetWindowTextW(hwnd, buffer.as_mut_ptr(), 256) }),
            class: text_of(|buffer| unsafe { GetClassNameW(hwnd, buffer.as_mut_ptr(), 256) }),
            // SAFETY: plain query.
            visible: unsafe { IsWindowVisible(hwnd) } != 0,
        });
    }
    1
}

/// Top-level windows of the processes `pids`.
pub fn windows_of(pids: &[u32]) -> Vec<TopLevel> {
    use windows_sys::Win32::UI::WindowsAndMessaging::EnumWindows;
    let mut search = Search {
        pids: pids.to_vec(),
        found: Vec::new(),
    };
    // SAFETY: `search` outlives the call.
    unsafe { EnumWindows(Some(collect), &mut search as *mut Search as LPARAM) };
    search.found
}

/// Visible top-level windows of `pid`'s whole process tree (the WebView2
/// browser included), tao's helper aside, as `class "title"` strings.
pub fn visible_windows(pid: u32) -> Vec<String> {
    let pids: Vec<u32> = tree(pid).iter().map(|proc| proc.pid).collect();
    windows_of(&pids)
        .into_iter()
        .filter(|window| window.visible && window.class != TAO_EVENT_TARGET)
        .map(|window| format!("{} {:?}", window.class, window.title))
        .collect()
}

// ---------------------------------------------------------------------------
// UI Automation (read-only)

/// The UI Automation tree under the top-level window named `title` that
/// process `pid` owns, read through PowerShell's managed UI Automation client
/// with no keystroke, click or focus change: one object per element, in
/// tree order (control view), with `ct` (control type), `lct` (localized
/// control type), `name`, `focusable`, `offscreen`, `expand` (the
/// ExpandCollapse pattern is available), `invoke`, `value` and `depth`.
/// `Value::Null` when the window is not found within `wait_ms`.
pub fn uia_tree(pid: u32, title: &str, wait_ms: u32) -> Value {
    let script = format!(
        r#"$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes
$A = [System.Windows.Automation.AutomationElement]
$condition = New-Object System.Windows.Automation.AndCondition(
  (New-Object System.Windows.Automation.PropertyCondition($A::ProcessIdProperty, {pid})),
  (New-Object System.Windows.Automation.PropertyCondition($A::NameProperty, '{title}')))
$clock = [Diagnostics.Stopwatch]::StartNew()
$window = $null
while (-not $window -and $clock.ElapsedMilliseconds -lt {wait_ms}) {{
  $window = $A::RootElement.FindFirst([System.Windows.Automation.TreeScope]::Children, $condition)
  if (-not $window) {{ Start-Sleep -Milliseconds 100 }}
}}
if (-not $window) {{ 'null'; exit 0 }}
$walker = [System.Windows.Automation.TreeWalker]::ControlViewWalker
$out = New-Object System.Collections.Generic.List[object]
function Visit($element, [int]$depth) {{
  if ($out.Count -ge 800 -or $depth -gt 60) {{ return }}
  $c = $element.Current
  $out.Add([pscustomobject][ordered]@{{
    ct = $c.ControlType.ProgrammaticName.Replace('ControlType.', '')
    lct = $c.LocalizedControlType
    name = $(if ($c.Name.Length -gt 300) {{ $c.Name.Substring(0, 300) }} else {{ $c.Name }})
    focusable = $c.IsKeyboardFocusable
    offscreen = $c.IsOffscreen
    pid = $c.ProcessId
    expand = [bool]$element.GetCurrentPropertyValue($A::IsExpandCollapsePatternAvailableProperty)
    invoke = [bool]$element.GetCurrentPropertyValue($A::IsInvokePatternAvailableProperty)
    value = [bool]$element.GetCurrentPropertyValue($A::IsValuePatternAvailableProperty)
    depth = $depth
  }})
  $child = $walker.GetFirstChild($element)
  while ($child) {{
    Visit $child ($depth + 1)
    $child = $walker.GetNextSibling($child)
  }}
}}
Visit $window 0
ConvertTo-Json -InputObject $out.ToArray() -Compress -Depth 3
"#,
        title = title.replace('\'', "''"),
    );
    let output = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
        .expect("run powershell");
    let text = String::from_utf8_lossy(&output.stdout);
    let text = text.trim().trim_start_matches('\u{feff}');
    serde_json::from_str(text).unwrap_or_else(|error| {
        panic!(
            "UI Automation output is not JSON ({error}): {}\n{}",
            &text[..text.len().min(2000)],
            String::from_utf8_lossy(&output.stderr)
        )
    })
}
