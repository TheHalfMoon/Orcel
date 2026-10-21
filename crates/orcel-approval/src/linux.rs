// SPDX-License-Identifier: FSL-1.1-MIT
// Portions copyright (c) 2026 Cua AI, Inc.; modifications copyright Orcel.

//! XP-10 approvals on Linux: the SOFT dialog and STRONG presence.
//!
//! SOFT: orceld spawns the GTK4 helper `orcel-approval-helper-linux` from a
//! pinned location (next to the running orceld binary, else
//! [`SYSTEM_HELPER_PATH`]; never `PATH`) with a cleared environment. The
//! request, which carries a fresh channel nonce from orceld, goes in on the
//! helper's stdin and the answer comes back on its stdout; both are pipes
//! orceld creates and owns. An answer is accepted only when it is exactly
//! one line, `orcel-approval-helper/1 <nonce> <sha256> approve|deny`, with
//! this request's nonce and the SHA-256 of the exact request bytes orceld
//! wrote, which the helper hashes over the bytes it parsed and displayed.
//! So a request swapped in on the helper's stdin by a same-uid process
//! (which could read the nonce from `/proc/<pid>/fd/0`), anything else the
//! helper (or something it loads) prints, an answer for another request, a
//! replayed answer, a crash, a timeout or silence fails closed. The helper
//! only reports what the person clicked; the broker records it for the
//! prompt it asked about and the ledger binds it to the request's nonce and
//! digest, as for the Windows and macOS dialogs.
//!
//! STRONG: polkit `auth_self` for [`POLKIT_ACTION_ID`]
//! (`distribution/linux/ai.orcel.approve.policy`: `allow_any=no`,
//! `allow_inactive=no`, `allow_active=auth_self`), asked through polkit's
//! `CheckAuthorization` D-Bus method by the pinned, root-owned
//! `/usr/bin/pkcheck` for this process (id, start time and uid) with
//! `--allow-user-interaction` and no internal text agent. polkit takes
//! `--detail` only from root, so its prompt can show only the action's
//! static message; the STRONG flow therefore shows the full request in the
//! helper first (workspace, action, target, summary, digest, nonce) and
//! asks polkit only after the person approved it there. Either step failing
//! fails the whole STRONG approval; STRONG never degrades to SOFT.
//!
//! Every path but an interactive, local, active graphical login session
//! fails closed before anything is shown: a CI runner, an SSH login, or a
//! logind session that is not active, is remote, is not X11 or Wayland, or
//! cannot be read. The display must belong to that session: on X11,
//! `DISPLAY` must be the session's logind `Display`; on Wayland,
//! `WAYLAND_DISPLAY` must name a socket under `/run/user/<uid>` owned by
//! this user. The helper is given only the verified display's variables.
//! No environment variable can approve; the ones read here can only make
//! approvals unavailable.
//!
//! Residual risks (S-04), as on Windows and macOS: a same-uid process can
//! run its own Wayland compositor socket in `/run/user/<uid>` and point
//! `WAYLAND_DISPLAY` at it (for example with `systemctl --user
//! set-environment`), then approve the SOFT dialog there; on X11 a same-uid
//! process can click Approve with XTest. Neither can supply the password
//! or fingerprint polkit asks for, so STRONG still requires the person.
//!
//! Provenance (T-CUA-20, COPY_ADAPT, Linux path): `pkcheck_outcome` and
//! `proc_start_time` are adapted from cua@a802eaf26ca97616a6bf0de6a29729a9346fbb1f
//! `libs/cua/crates/cua-teleport/src/biometric.rs`
//! (blob 3fa6cc4132ef2d57ce8b57740fbeb9fb8b6f37cf), FSL-1.1-MIT, used under
//! FD-04; notice in `docs/orcel/notices/cua-FSL-1.1-MIT.txt`. Orcel's
//! modifications:
//! - both donor bypass variables are not taken: no environment variable
//!   skips, downgrades or answers STRONG;
//! - `pkcheck` runs from the pinned `/usr/bin/pkcheck`, which must be a
//!   root-owned file that nobody else can write, with a cleared
//!   environment, instead of whatever `pkcheck` is first on `PATH`;
//! - an action that is not installed, or a session that is not an active
//!   local graphical one, is `unavailable` before polkit is asked;
//! - exit 1 with an error on stderr (for example an unregistered action or
//!   a D-Bus failure) is a failure, not the person's refusal, and a reply
//!   that does not arrive in `STRONG_VERIFY_TIMEOUT_MS` is a timeout (the
//!   donor called it cancelled);
//! - the GTK helper confirmation before polkit is new Orcel code.

// Off Linux this module is compiled only into tests, which run its pure
// rules (session classification, helper protocol, pkcheck mapping, the
// STRONG flow) on every OS.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use crate::presence_unix::SessionState;
use crate::soft_macos::{dialog_body, display_field, DIALOG_HEADER};
use crate::{
    ApprovalClass, ApprovalDecision, ApprovalError, ApprovalPrompt, InputLeaseGuard,
    PresenceAttestation, PresenceContext, PresenceError,
};

/// The method name the ledger records for a Linux STRONG approval.
pub const POLKIT_PRESENCE_METHOD: &str = "linux-polkit-auth-self";
/// The polkit action `distribution/linux/ai.orcel.approve.policy` defines.
pub const POLKIT_ACTION_ID: &str = "ai.orcel.approve.strong";
/// Where packages install the policy (XP-17); STRONG is unavailable
/// without it.
pub const POLKIT_POLICY_PATH: &str = "/usr/share/polkit-1/actions/ai.orcel.approve.policy";
/// The helper's file name, looked up next to orceld first.
pub const HELPER_FILE_NAME: &str = "orcel-approval-helper-linux";
/// Where packages install the helper when it is not next to orceld.
pub const SYSTEM_HELPER_PATH: &str = "/usr/libexec/orcel/orcel-approval-helper-linux";
/// The helper protocol; the helper refuses any other.
pub const HELPER_PROTOCOL: &str = "orcel-approval-helper/1";

const PKCHECK_PATH: &str = "/usr/bin/pkcheck";
const LOGINCTL_PATHS: [&str; 2] = ["/usr/bin/loginctl", "/bin/loginctl"];
const STRONG_HEADER: &str = "Orcel approval STRONG";
/// How long the helper shows a dialog before it answers deny by itself.
const HELPER_DIALOG_TIMEOUT_SECS: u64 = 120;
/// orceld stops waiting this long after the helper's own timeout.
const HELPER_GRACE_SECS: u64 = 10;
/// The longest answer accepted; a real one is about 60 bytes.
const MAX_ANSWER_BYTES: usize = 256;
/// The channel nonce is this many random bytes, sent as lowercase hex.
const CHANNEL_NONCE_BYTES: usize = 16;

/// The only variables the helper inherits: what GTK needs to reach the
/// person's display and session bus. Loader, module and debug variables
/// (`LD_*`, `GTK_MODULES`, `GTK_DEBUG`, `GTK_PATH`, ...) are not passed.
pub(crate) const HELPER_ENV_ALLOWLIST: [&str; 7] = [
    "WAYLAND_DISPLAY",
    "DISPLAY",
    "XAUTHORITY",
    "XDG_RUNTIME_DIR",
    "DBUS_SESSION_BUS_ADDRESS",
    "HOME",
    "LANG",
];

// ---------------------------------------------------------------------------
// Session classification (pure)
// ---------------------------------------------------------------------------

/// What logind reports for the session approvals would be shown in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LogindSession {
    pub active: bool,
    pub remote: bool,
    /// `Type`: `x11`, `wayland`, `tty`, `mir`, `unspecified`.
    pub kind: String,
    /// `Class`: `user`, `greeter`, `lock-screen`, `background`, ...
    pub class: String,
    /// `Display`: the X11 display of an X11 session (empty otherwise).
    pub display: String,
}

/// Everything the session decision depends on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SessionFacts {
    /// `CI` or `GITHUB_ACTIONS` is set: nobody is at the keyboard.
    pub automation: bool,
    /// `SSH_CONNECTION`, `SSH_CLIENT` or `SSH_TTY` is set.
    pub ssh: bool,
    /// A non-empty `WAYLAND_DISPLAY`.
    pub wayland_display: Option<String>,
    /// Whether `WAYLAND_DISPLAY` names a socket under `/run/user/<uid>`
    /// that this user owns.
    pub wayland_socket_owned: bool,
    /// A non-empty `DISPLAY`.
    pub x_display: Option<String>,
    /// The logind session, or why it could not be read.
    pub logind: Result<LogindSession, String>,
}

/// The display server the helper may connect to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DisplayKind {
    X11,
    Wayland,
}

/// `:N` or `:N.S` (a local X display, no host part) as `:N`.
pub(crate) fn local_x_display(value: &str) -> Option<&str> {
    let rest = value.strip_prefix(':')?;
    let number = rest.split_once('.').map_or(rest, |(number, _)| number);
    (!number.is_empty() && number.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| &value[..number.len() + 1])
}

/// The display a person in this session would see, or `None` when there
/// is none that provably belongs to the active local session: on X11,
/// `DISPLAY` must be the session's own logind `Display`; on Wayland,
/// `WAYLAND_DISPLAY` must be this user's socket in its runtime directory.
pub(crate) fn session_display(facts: &SessionFacts) -> Option<DisplayKind> {
    if facts.automation || facts.ssh {
        return None;
    }
    let session = facts.logind.as_ref().ok()?;
    if !session.active || session.remote || session.class != "user" {
        return None;
    }
    match session.kind.as_str() {
        "x11" => {
            let env = local_x_display(facts.x_display.as_deref()?)?;
            let own = local_x_display(&session.display)?;
            (env == own).then_some(DisplayKind::X11)
        }
        "wayland" => (facts.wayland_display.is_some() && facts.wayland_socket_owned)
            .then_some(DisplayKind::Wayland),
        _ => None,
    }
}

/// Classifies the session. Only a local, active, graphical (X11 or
/// Wayland) user session whose display is verified, outside CI and SSH, is
/// interactive; everything else, including a probe failure, fails closed.
pub(crate) fn classify_session(facts: &SessionFacts) -> SessionState {
    if facts.automation {
        return SessionState::Automation;
    }
    match session_display(facts) {
        Some(_) => SessionState::Interactive,
        None => SessionState::NoGraphicSession,
    }
}

/// The socket `WAYLAND_DISPLAY` names, when it lies directly in this
/// user's runtime directory `/run/user/<euid>`.
pub(crate) fn wayland_socket_path(
    wayland_display: &str,
    runtime_dir: Option<&str>,
    euid: u32,
) -> Option<std::path::PathBuf> {
    let own = format!("/run/user/{euid}");
    let name = match wayland_display.strip_prefix(&format!("{own}/")) {
        Some(name) => name,
        None if wayland_display.starts_with('/') => return None,
        None if runtime_dir? == own => wayland_display,
        None => return None,
    };
    if name.is_empty() || name.contains('/') || name == "." || name == ".." {
        return None;
    }
    Some(std::path::Path::new(&own).join(name))
}

/// The variables the helper is given for `kind`: the verified display
/// only, plus what GTK needs to reach the session.
pub(crate) fn helper_env_names(kind: DisplayKind) -> Vec<&'static str> {
    HELPER_ENV_ALLOWLIST
        .iter()
        .copied()
        .filter(|name| match kind {
            DisplayKind::X11 => *name != "WAYLAND_DISPLAY",
            DisplayKind::Wayland => *name != "DISPLAY" && *name != "XAUTHORITY",
        })
        .collect()
}

/// Parses `loginctl show-session` output (`Key=value` lines). Every one of
/// `Active`, `Remote`, `Type`, `Class` and `Display` must be present
/// exactly once (`Display` may be empty), and the two booleans must be
/// `yes` or `no`.
pub(crate) fn parse_logind_properties(text: &str) -> Result<LogindSession, String> {
    let mut active = None;
    let mut remote = None;
    let mut kind = None;
    let mut class = None;
    let mut display = None;
    for line in text.lines() {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(format!("unexpected logind line {:?}", bounded(line)));
        };
        let slot = match key {
            "Active" => &mut active,
            "Remote" => &mut remote,
            "Type" => &mut kind,
            "Class" => &mut class,
            "Display" => &mut display,
            _ => continue,
        };
        if slot.replace(value.to_owned()).is_some() {
            return Err(format!("logind repeated {key}"));
        }
    }
    let flag = |name: &str, value: Option<String>| match value.as_deref() {
        Some("yes") => Ok(true),
        Some("no") => Ok(false),
        Some(other) => Err(format!("logind {name} is {:?}", bounded(other))),
        None => Err(format!("logind did not report {name}")),
    };
    Ok(LogindSession {
        active: flag("Active", active)?,
        remote: flag("Remote", remote)?,
        kind: kind.ok_or("logind did not report Type")?,
        class: class.ok_or("logind did not report Class")?,
        display: display.ok_or("logind did not report Display")?,
    })
}

fn bounded(text: &str) -> String {
    display_field(text, 80)
}

// ---------------------------------------------------------------------------
// Helper protocol (pure)
// ---------------------------------------------------------------------------

/// Lowercase hex of `bytes`.
pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The request orceld writes to the helper's stdin: one JSON object on one
/// line. `title` and `body` are already bounded and escaped.
pub(crate) fn encode_request(
    channel_nonce: &str,
    class: ApprovalClass,
    title: &str,
    body: &str,
    timeout_secs: u64,
) -> String {
    let mut line = serde_json::json!({
        "protocol": HELPER_PROTOCOL,
        "nonce": channel_nonce,
        "class": class.as_str(),
        "title": title,
        "body": body,
        "timeout_secs": timeout_secs,
    })
    .to_string();
    line.push('\n');
    line
}

/// Lowercase hex SHA-256 of the exact request bytes.
pub(crate) fn request_digest(request: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex(&Sha256::digest(request))
}

/// The one answer line the helper may print:
/// `orcel-approval-helper/1 <channel nonce> <request sha256> approve|deny`.
/// orceld only parses it; tests build answers with it.
#[cfg(test)]
pub(crate) fn answer_line(channel_nonce: &str, digest: &str, approved: bool) -> String {
    let verdict = if approved { "approve" } else { "deny" };
    format!("{HELPER_PROTOCOL} {channel_nonce} {digest} {verdict}\n")
}

/// Compares without stopping at the first differing byte.
fn same_bytes(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Parses everything the helper wrote to stdout. Exactly one line ending in
/// `\n`, no `\r`, at most [`MAX_ANSWER_BYTES`], the protocol name, this
/// request's channel nonce, the SHA-256 of the request bytes orceld sent
/// and `approve` or `deny`; anything else (a missing, forged or replayed
/// nonce, an answer about other request text, extra output, a partial
/// line) is refused.
pub(crate) fn parse_answer(
    output: &[u8],
    channel_nonce: &str,
    request_sha256: &str,
) -> Result<bool, String> {
    if output.is_empty() {
        return Err("the approval helper printed no answer".into());
    }
    if output.len() > MAX_ANSWER_BYTES {
        return Err("the approval helper printed more than one answer".into());
    }
    let text = std::str::from_utf8(output)
        .map_err(|_| String::from("the approval helper answer is not UTF-8"))?;
    let Some(line) = text.strip_suffix('\n') else {
        return Err("the approval helper answer is not a complete line".into());
    };
    if line.contains('\n') || line.contains('\r') {
        return Err("the approval helper printed more than one line".into());
    }
    let mut parts = line.split(' ');
    let (Some(protocol), Some(nonce), Some(digest), Some(verdict), None) = (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) else {
        return Err("the approval helper answer is malformed".into());
    };
    if protocol != HELPER_PROTOCOL {
        return Err("the approval helper answered in another protocol".into());
    }
    if channel_nonce.is_empty() || !same_bytes(nonce.as_bytes(), channel_nonce.as_bytes()) {
        return Err("the approval helper answer is not for this request".into());
    }
    if request_sha256.is_empty() || !same_bytes(digest.as_bytes(), request_sha256.as_bytes()) {
        return Err("the approval helper answered about text orceld did not send".into());
    }
    match verdict {
        "approve" => Ok(true),
        "deny" => Ok(false),
        _ => Err("the approval helper answer is malformed".into()),
    }
}

/// What one helper run produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum HelperOutcome {
    /// Exited 0 with a valid answer for this request.
    Answered(bool),
    /// Did not answer before the deadline; it was killed.
    TimedOut,
    /// Exited non-zero or by a signal (for example GTK could not open the
    /// display).
    Crashed(String),
    /// Exited 0 but its output was not a valid answer for this request.
    Malformed(String),
    /// Could not be found, verified or started.
    NotStarted(String),
}

/// SOFT: maps the helper's outcome to the broker's decision. Only a valid
/// `approve` for this request approves.
pub(crate) fn decide(
    prompt: &ApprovalPrompt,
    outcome: HelperOutcome,
) -> Result<ApprovalDecision, ApprovalError> {
    if prompt.approval_class != ApprovalClass::Soft {
        return Err(ApprovalError::unavailable(
            "the SOFT dialog never answers a STRONG request; STRONG requires presence verification",
        ));
    }
    match outcome {
        HelperOutcome::Answered(true) => Ok(ApprovalDecision::Approved),
        HelperOutcome::Answered(false) => Ok(ApprovalDecision::Denied),
        HelperOutcome::TimedOut => Err(ApprovalError::unavailable(
            "the Linux approval helper did not answer in time; SOFT approval fails closed",
        )),
        // #373 item 2: no answer is "unavailable", like the other outcomes
        // without one; only an explicit deny is "denied".
        HelperOutcome::Crashed(detail) => Err(ApprovalError::unavailable(format!(
            "the Linux approval helper exited without an answer ({detail}); SOFT approval fails closed"
        ))),
        HelperOutcome::Malformed(detail) => Err(ApprovalError::unavailable(format!(
            "{detail}; SOFT approval fails closed"
        ))),
        HelperOutcome::NotStarted(detail) => Err(ApprovalError::unavailable(format!(
            "the Linux approval helper is unavailable ({detail}); SOFT approval fails closed"
        ))),
    }
}

/// Refuses no graphical session and automation runners before anything is
/// shown.
pub(crate) fn session_gate(session: SessionState) -> Result<(), ApprovalError> {
    match session {
        SessionState::Interactive => Ok(()),
        SessionState::Automation => Err(ApprovalError::unavailable(
            "no person can answer the approval dialog on an automation runner; SOFT approval fails closed",
        )),
        SessionState::NoGraphicSession => Err(ApprovalError::unavailable(
            "no active local graphical login session (headless, SSH, inactive or remote) to show the approval dialog; SOFT approval fails closed",
        )),
    }
}

// ---------------------------------------------------------------------------
// STRONG (pure)
// ---------------------------------------------------------------------------

/// The text the helper shows before polkit is asked: the SOFT body's lines,
/// marked STRONG.
pub(crate) fn strong_body(ctx: &PresenceContext) -> String {
    let nonce_prefix: String = ctx.nonce.chars().take(8).collect();
    format!(
        "Orcel requests a local action that needs STRONG approval.\n\nWorkspace: {}\nAction: {}\nTarget: {}\n{}\nDigest: {}\nApproval: STRONG {} (single use, expires in 5 minutes)\n\nApprove this exact operation? Your system will then ask you to confirm it is you.",
        display_field(&ctx.workspace_id, 128),
        display_field(&ctx.action, 512),
        display_field(&ctx.target, 512),
        display_field(&ctx.summary, 1024),
        display_field(&ctx.digest, 128),
        display_field(&nonce_prefix, 8),
    )
}

/// What one `pkcheck` run reported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PolkitOutcome {
    /// The exit status (`None` for a signal), stderr, and whether orceld
    /// runs inside a logind session scope.
    Exited(Option<i32>, String, bool),
    /// No reply before the deadline; pkcheck was killed.
    TimedOut,
    /// pkcheck, the policy or this process's start time is missing or
    /// untrusted.
    NotAvailable(String),
}

/// `pkcheck`'s exit status (pkcheck(1)): 0 authorized, 1 not authorized,
/// 2 the challenge could not be made (no authentication agent), 3 the
/// person dismissed the dialog, 127 an error. An error or a signal is a
/// failure, never the person's refusal. A plain "not authorized" for a
/// process outside any login session (orceld as a systemd user service)
/// means polkit may not have found the active session to ask in: that is
/// unavailable, not the person's refusal.
pub(crate) fn pkcheck_outcome(
    code: Option<i32>,
    stderr: &str,
    in_session: bool,
) -> Result<(), PresenceError> {
    let detail = || {
        let line = stderr.lines().map(str::trim).find(|line| !line.is_empty());
        match (line, code) {
            (Some(line), _) => display_field(line, 300),
            (None, Some(code)) => format!("pkcheck exited with status {code}"),
            (None, None) => String::from("pkcheck was stopped by a signal"),
        }
    };
    match code {
        Some(0) => Ok(()),
        // Not authorized. polkit reports an unregistered action or a D-Bus
        // failure on stderr with status 1 on some versions: not a refusal.
        Some(1) if stderr.contains("Error") || stderr.contains("not registered") => {
            Err(PresenceError::unavailable(format!(
                "polkit could not check the Orcel action ({}); STRONG approval fails closed",
                detail()
            )))
        }
        Some(1) if !in_session => Err(PresenceError::unavailable(
            "polkit did not authorize orceld, which runs outside a login session (for example as a user service), so polkit may not have found the active session; STRONG approval fails closed",
        )),
        Some(1) => Err(PresenceError::denied(
            "polkit did not authorize the Orcel STRONG action; STRONG approval fails closed",
        )),
        Some(2) => Err(PresenceError::unavailable(
            "no polkit authentication agent can ask in this session; STRONG approval fails closed without SOFT downgrade",
        )),
        Some(3) => Err(PresenceError::cancelled(
            "the polkit authentication dialog was dismissed; STRONG approval fails closed",
        )),
        _ => Err(PresenceError::failed(format!(
            "polkit check failed ({}); STRONG approval fails closed",
            detail()
        ))),
    }
}

/// The process start time (clock ticks since boot) in a `/proc/<pid>/stat`
/// line: the 22nd field, counted after the process name, which may hold
/// spaces and parentheses itself. polkit names a process by id and start
/// time, so a recycled id is never mistaken for it.
pub(crate) fn proc_start_time(stat: &str) -> Option<u64> {
    let after_name = &stat[stat.rfind(')')? + 1..];
    // The fields after the name begin with the state (field 3).
    after_name.split_whitespace().nth(19)?.parse().ok()
}

/// The platform-independent STRONG flow: validate, gate on the session,
/// show the full request in the helper, ask polkit only after an approve
/// there, and bind a success to this context's nonce and digest.
pub(crate) fn verify_with(
    ctx: &PresenceContext,
    lease: &InputLeaseGuard,
    method: &'static str,
    session: SessionState,
    confirm: impl FnOnce(&str) -> HelperOutcome,
    authorize: impl FnOnce() -> PolkitOutcome,
) -> Result<PresenceAttestation, PresenceError> {
    if !lease.is_suspended() {
        return Err(PresenceError::invalid(
            "strong verification requires a suspended input lease",
        ));
    }
    if ctx.nonce.trim().is_empty() || ctx.digest.trim().is_empty() {
        return Err(PresenceError::invalid(
            "strong verification context is malformed",
        ));
    }
    match session {
        SessionState::Interactive => {}
        SessionState::Automation => {
            return Err(PresenceError::unavailable(
                "no person can answer a presence prompt on an automation runner; STRONG approval fails closed",
            ))
        }
        SessionState::NoGraphicSession => {
            return Err(PresenceError::unavailable(
                "no active local graphical login session (headless, SSH, inactive or remote); STRONG approval fails closed without SOFT downgrade",
            ))
        }
    }
    match confirm(&strong_body(ctx)) {
        HelperOutcome::Answered(true) => {}
        HelperOutcome::Answered(false) => {
            return Err(PresenceError::denied(
                "the STRONG request was denied in the Orcel approval dialog; STRONG approval fails closed",
            ))
        }
        HelperOutcome::TimedOut => {
            return Err(PresenceError::timeout(
                "the Orcel approval dialog did not answer in time; STRONG approval fails closed",
            ))
        }
        HelperOutcome::Crashed(detail) => {
            return Err(PresenceError::unavailable(format!(
                "the Linux approval helper exited without an answer ({detail}); STRONG approval fails closed"
            )))
        }
        HelperOutcome::Malformed(detail) => {
            return Err(PresenceError::invalid(format!(
                "{detail}; STRONG approval fails closed"
            )))
        }
        HelperOutcome::NotStarted(detail) => {
            return Err(PresenceError::unavailable(format!(
                "the Linux approval helper is unavailable ({detail}); STRONG approval fails closed"
            )))
        }
    }
    match authorize() {
        PolkitOutcome::Exited(code, stderr, in_session) => {
            pkcheck_outcome(code, &stderr, in_session)?
        }
        PolkitOutcome::TimedOut => {
            return Err(PresenceError::timeout(
                "strong user-presence verification timed out; STRONG approval fails closed",
            ))
        }
        PolkitOutcome::NotAvailable(detail) => {
            return Err(PresenceError::unavailable(format!(
                "polkit presence is unavailable ({detail}); STRONG approval fails closed without SOFT downgrade"
            )))
        }
    }
    Ok(PresenceAttestation {
        method: method.to_owned(),
        verified_at_ms: crate::now_ms(),
        nonce: ctx.nonce.clone(),
        digest: ctx.digest.clone(),
    })
}

/// Whether a file with this owner and mode may be executed or trusted:
/// owned by root (or, when `allow_owner` is set, by `euid`) and writable by
/// nobody else.
pub(crate) fn owner_and_mode_trusted(uid: u32, mode: u32, euid: u32, allow_owner: bool) -> bool {
    (uid == 0 || (allow_owner && uid == euid)) && mode & 0o022 == 0
}

/// The effective uid from a `/proc/self/status` text.
pub(crate) fn effective_uid(status: &str) -> Option<u32> {
    status_uid(status, 2)
}

/// The real uid from a `/proc/self/status` text.
pub(crate) fn real_uid(status: &str) -> Option<u32> {
    status_uid(status, 1)
}

fn status_uid(status: &str, field: usize) -> Option<u32> {
    let line = status.lines().find(|line| line.starts_with("Uid:"))?;
    line.split_whitespace().nth(field)?.parse().ok()
}

/// Whether a `/proc/self/cgroup` text puts the process in a logind session
/// scope (`.../session-<id>.scope`).
pub(crate) fn cgroup_in_session(cgroup: &str) -> bool {
    cgroup.lines().any(|line| {
        line.rsplit('/')
            .next()
            .is_some_and(|leaf| leaf.starts_with("session-") && leaf.ends_with(".scope"))
    })
}

// ---------------------------------------------------------------------------
// The Linux system: environment, logind, helper and pkcheck
// ---------------------------------------------------------------------------

/// The current session. Every state but `Interactive` fails closed.
#[cfg(target_os = "linux")]
pub(crate) fn session_state() -> SessionState {
    classify_session(&sys::session_facts())
}

/// The SOFT prompt the broker calls on Linux.
#[cfg(target_os = "linux")]
pub(crate) fn platform_prompt(prompt: &ApprovalPrompt) -> Result<ApprovalDecision, ApprovalError> {
    if prompt.approval_class != ApprovalClass::Soft {
        return Err(ApprovalError::unavailable(
            "the SOFT dialog never answers a STRONG request; STRONG requires presence verification",
        ));
    }
    let facts = sys::session_facts();
    session_gate(classify_session(&facts))?;
    let Some(kind) = session_display(&facts) else {
        return Err(ApprovalError::unavailable(
            "no verified display for the approval dialog; SOFT approval fails closed",
        ));
    };
    decide(
        prompt,
        sys::confirm_in_helper(
            ApprovalClass::Soft,
            DIALOG_HEADER,
            &dialog_body(prompt),
            kind,
        ),
    )
}

/// STRONG presence on Linux: the helper shows the full request, then polkit
/// `auth_self` asks the person to prove it is them.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, Default)]
pub struct PolkitPresenceVerifier;

#[cfg(target_os = "linux")]
impl PolkitPresenceVerifier {
    pub fn new() -> Self {
        Self
    }
}

#[cfg(target_os = "linux")]
impl crate::PresenceVerifier for PolkitPresenceVerifier {
    fn method(&self) -> &'static str {
        POLKIT_PRESENCE_METHOD
    }

    fn is_available(&self) -> bool {
        session_state() == SessionState::Interactive
            && sys::trusted_pkcheck().is_ok()
            && sys::policy_installed().is_ok()
            && sys::helper_path().is_ok()
    }

    fn verify(
        &self,
        ctx: &PresenceContext,
        lease: &InputLeaseGuard,
    ) -> Result<PresenceAttestation, PresenceError> {
        let facts = sys::session_facts();
        let kind = session_display(&facts);
        verify_with(
            ctx,
            lease,
            self.method(),
            classify_session(&facts),
            |body| match kind {
                Some(kind) => {
                    sys::confirm_in_helper(ApprovalClass::Strong, STRONG_HEADER, body, kind)
                }
                None => HelperOutcome::NotStarted(String::from("no verified display")),
            },
            sys::pkcheck,
        )
    }
}

#[cfg(target_os = "linux")]
pub(crate) mod sys {
    //! Everything here touches the host. Child processes start from absolute,
    //! verified paths with a cleared environment; their output is bounded
    //! and they are killed at their deadline.

    use std::ffi::OsString;
    use std::io::{Read, Write};
    use std::os::unix::fs::MetadataExt;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, ExitStatus, Stdio};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    use super::*;

    const POLL: Duration = Duration::from_millis(25);

    /// A finished tool's status, stdout and stderr.
    type ToolOutput = (ExitStatus, Vec<u8>, Vec<u8>);

    /// The facts [`classify_session`] decides on. The variables read here
    /// can only make approvals unavailable.
    pub(crate) fn session_facts() -> SessionFacts {
        let get = |name: &str| {
            std::env::var_os(name)
                .filter(|value| !value.is_empty())
                .map(|value| value.to_string_lossy().into_owned())
        };
        let set = |name: &str| get(name).is_some();
        let automation = set("CI") || set("GITHUB_ACTIONS");
        let ssh = set("SSH_CONNECTION") || set("SSH_CLIENT") || set("SSH_TTY");
        let wayland_display = get("WAYLAND_DISPLAY");
        let x_display = get("DISPLAY");
        let runtime_dir = get("XDG_RUNTIME_DIR");
        let wayland_socket_owned = wayland_display.as_deref().is_some_and(|display| {
            euid().ok().is_some_and(|euid| {
                wayland_socket_path(display, runtime_dir.as_deref(), euid)
                    .is_some_and(|path| owned_socket(&path, euid))
            })
        });
        let display = wayland_display.is_some() || x_display.is_some();
        // Nothing is asked of logind when the answer is already no.
        let logind = if automation || ssh || !display {
            Err(String::from("not probed"))
        } else {
            logind_session()
        };
        SessionFacts {
            automation,
            ssh,
            wayland_display,
            wayland_socket_owned,
            x_display,
            logind,
        }
    }

    /// A Unix socket (not a link to one) owned by `euid`.
    fn owned_socket(path: &Path, euid: u32) -> bool {
        use std::os::unix::fs::FileTypeExt;
        std::fs::symlink_metadata(path)
            .is_ok_and(|meta| meta.file_type().is_socket() && meta.uid() == euid)
    }

    /// The facts with the automation guard ignored, so CI can check that
    /// the real probe of a runner fails closed on its own.
    #[cfg(test)]
    pub(crate) fn session_facts_ignoring_automation() -> SessionFacts {
        let mut facts = session_facts();
        facts.automation = false;
        let display = facts.wayland_display.is_some() || facts.x_display.is_some();
        if facts.logind.is_err() && !facts.ssh && display {
            facts.logind = logind_session();
        }
        facts
    }

    fn euid() -> Result<u32, String> {
        std::fs::read_to_string("/proc/self/status")
            .ok()
            .as_deref()
            .and_then(effective_uid)
            .ok_or_else(|| String::from("cannot read this process's uid"))
    }

    /// The canonical path of `path` when it is a regular file whose owner and
    /// mode are trusted, in directories whose owners and modes are trusted
    /// up to `/`.
    pub(crate) fn trusted_file(path: &Path, allow_owner: bool) -> Result<PathBuf, String> {
        let euid = euid()?;
        let canonical =
            std::fs::canonicalize(path).map_err(|error| format!("{}: {error}", path.display()))?;
        let meta = std::fs::metadata(&canonical)
            .map_err(|error| format!("{}: {error}", canonical.display()))?;
        if !meta.is_file() || !owner_and_mode_trusted(meta.uid(), meta.mode(), euid, allow_owner) {
            return Err(format!(
                "{} is not a file owned by root{} that only its owner can write",
                canonical.display(),
                if allow_owner { " or this user" } else { "" }
            ));
        }
        for dir in canonical.ancestors().skip(1) {
            let meta =
                std::fs::metadata(dir).map_err(|error| format!("{}: {error}", dir.display()))?;
            if !owner_and_mode_trusted(meta.uid(), meta.mode(), euid, allow_owner) {
                return Err(format!("{} can be written by another user", dir.display()));
            }
        }
        Ok(canonical)
    }

    pub(crate) fn trusted_pkcheck() -> Result<PathBuf, String> {
        trusted_file(Path::new(PKCHECK_PATH), false)
    }

    pub(crate) fn policy_installed() -> Result<PathBuf, String> {
        trusted_file(Path::new(POLKIT_POLICY_PATH), false)
            .map_err(|error| format!("the Orcel polkit action is not installed ({error})"))
    }

    /// The helper next to the running orceld, else the system location.
    /// Never `PATH`, never an environment variable.
    pub(crate) fn helper_path() -> Result<PathBuf, String> {
        let mut tried = Vec::new();
        let sibling = std::env::current_exe()
            .ok()
            .and_then(|exe| std::fs::canonicalize(exe).ok())
            .and_then(|exe| exe.parent().map(|dir| dir.join(HELPER_FILE_NAME)));
        for candidate in sibling
            .into_iter()
            .chain(std::iter::once(PathBuf::from(SYSTEM_HELPER_PATH)))
        {
            if !candidate.exists() {
                continue;
            }
            match trusted_file(&candidate, true) {
                Ok(path) => return Ok(path),
                Err(error) => tried.push(error),
            }
        }
        if tried.is_empty() {
            Err(format!(
                "{HELPER_FILE_NAME} is not installed next to orceld or at {SYSTEM_HELPER_PATH}"
            ))
        } else {
            Err(tried.join("; "))
        }
    }

    fn channel_nonce() -> Result<String, String> {
        let mut bytes = [0u8; CHANNEL_NONCE_BYTES];
        std::fs::File::open("/dev/urandom")
            .and_then(|mut random| random.read_exact(&mut bytes))
            .map_err(|error| format!("cannot read /dev/urandom: {error}"))?;
        Ok(hex(&bytes))
    }

    /// The helper's environment: the allowlisted variables for the verified
    /// display only.
    fn helper_env(kind: DisplayKind) -> Vec<(OsString, OsString)> {
        helper_env_names(kind)
            .into_iter()
            .filter_map(|name| std::env::var_os(name).map(|value| (OsString::from(name), value)))
            .collect()
    }

    /// Shows `body` in the pinned helper and waits for its answer.
    pub(crate) fn confirm_in_helper(
        class: ApprovalClass,
        title: &str,
        body: &str,
        kind: DisplayKind,
    ) -> HelperOutcome {
        let path = match helper_path() {
            Ok(path) => path,
            Err(error) => return HelperOutcome::NotStarted(error),
        };
        run_helper(
            &path,
            class,
            title,
            body,
            HELPER_DIALOG_TIMEOUT_SECS,
            Duration::from_secs(HELPER_DIALOG_TIMEOUT_SECS + HELPER_GRACE_SECS),
            helper_env(kind),
        )
    }

    /// Runs the helper at `path`: the request on stdin with a fresh channel
    /// nonce, at most [`MAX_ANSWER_BYTES`] + 1 bytes read from stdout, killed
    /// at `deadline`.
    pub(crate) fn run_helper(
        path: &Path,
        class: ApprovalClass,
        title: &str,
        body: &str,
        dialog_timeout_secs: u64,
        deadline: Duration,
        env: Vec<(OsString, OsString)>,
    ) -> HelperOutcome {
        let nonce = match channel_nonce() {
            Ok(nonce) => nonce,
            Err(error) => return HelperOutcome::NotStarted(error),
        };
        let request = encode_request(&nonce, class, title, body, dialog_timeout_secs);
        let digest = request_digest(request.as_bytes());
        let mut child = match Command::new(path)
            .env_clear()
            .envs(env)
            .current_dir("/")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(child) => child,
            Err(error) => return HelperOutcome::NotStarted(format!("{}: {error}", path.display())),
        };
        if let Some(mut stdin) = child.stdin.take() {
            // A helper that exits without reading, or reads something else,
            // is judged by its exit status and its answer's digest below.
            let _ = stdin.write_all(request.as_bytes());
        }
        let output = read_bounded(&mut child, MAX_ANSWER_BYTES + 1);
        let status = match wait_until(&mut child, deadline) {
            Some(status) => status,
            None => return HelperOutcome::TimedOut,
        };
        if !status.success() {
            return HelperOutcome::Crashed(describe(status));
        }
        // The pipe closes when the helper exits; a descendant that kept it
        // open does not make orceld wait for it.
        match output.recv_timeout(Duration::from_secs(2)) {
            Ok(bytes) => match parse_answer(&bytes, &nonce, &digest) {
                Ok(approved) => HelperOutcome::Answered(approved),
                Err(error) => HelperOutcome::Malformed(error),
            },
            Err(_) => {
                HelperOutcome::Malformed(String::from("the approval helper left its output open"))
            }
        }
    }

    /// Reads up to `limit` bytes of the child's stdout on a thread.
    fn read_bounded(child: &mut Child, limit: usize) -> mpsc::Receiver<Vec<u8>> {
        let (tx, rx) = mpsc::channel();
        if let Some(stdout) = child.stdout.take() {
            std::thread::spawn(move || {
                let mut bytes = Vec::new();
                let _ = stdout.take(limit as u64).read_to_end(&mut bytes);
                let _ = tx.send(bytes);
            });
        }
        rx
    }

    /// Waits for the child until `deadline`; kills and reaps it after that.
    fn wait_until(child: &mut Child, deadline: Duration) -> Option<ExitStatus> {
        let started = Instant::now();
        loop {
            match child.try_wait() {
                Ok(Some(status)) => return Some(status),
                Ok(None) if started.elapsed() < deadline => std::thread::sleep(POLL),
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
            }
        }
    }

    fn describe(status: ExitStatus) -> String {
        use std::os::unix::process::ExitStatusExt;
        match (status.code(), status.signal()) {
            (Some(code), _) => format!("exit status {code}"),
            (None, Some(signal)) => format!("signal {signal}"),
            (None, None) => String::from("unknown exit"),
        }
    }

    /// Runs a pinned system tool with a cleared environment and returns its
    /// status and first `limit` bytes of stdout and stderr.
    fn run_tool(
        path: &Path,
        args: &[&str],
        deadline: Duration,
        limit: usize,
    ) -> Result<Option<ToolOutput>, String> {
        let mut child = Command::new(path)
            .args(args)
            .env_clear()
            .current_dir("/")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| format!("{}: {error}", path.display()))?;
        let stdout = read_bounded(&mut child, limit);
        let (tx, stderr) = mpsc::channel();
        if let Some(pipe) = child.stderr.take() {
            std::thread::spawn(move || {
                let mut bytes = Vec::new();
                let _ = pipe.take(limit as u64).read_to_end(&mut bytes);
                let _ = tx.send(bytes);
            });
        }
        let Some(status) = wait_until(&mut child, deadline) else {
            return Ok(None);
        };
        let grace = Duration::from_secs(2);
        Ok(Some((
            status,
            stdout.recv_timeout(grace).unwrap_or_default(),
            stderr.recv_timeout(grace).unwrap_or_default(),
        )))
    }

    /// The logind session approvals are shown in: the caller's session, or
    /// the user's graphical session when orceld runs as a user service.
    pub(crate) fn logind_session() -> Result<LogindSession, String> {
        let loginctl = LOGINCTL_PATHS
            .iter()
            .map(Path::new)
            .find(|path| path.exists())
            .ok_or_else(|| String::from("loginctl is not installed"))
            .and_then(|path| trusted_file(path, false))?;
        let args = [
            "show-session",
            "auto",
            "--property=Active",
            "--property=Remote",
            "--property=Type",
            "--property=Class",
            "--property=Display",
        ];
        match run_tool(&loginctl, &args, Duration::from_secs(5), 4096)? {
            Some((status, stdout, _)) if status.success() => {
                parse_logind_properties(&String::from_utf8_lossy(&stdout))
            }
            Some((status, _, stderr)) => Err(format!(
                "loginctl failed ({}): {}",
                describe(status),
                display_field(String::from_utf8_lossy(&stderr).trim(), 200)
            )),
            None => Err(String::from("loginctl did not answer")),
        }
    }

    /// Asks polkit, through the pinned `pkcheck`, whether this process may
    /// perform [`POLKIT_ACTION_ID`], letting the session's agent ask the
    /// person (`auth_self`). `--enable-internal-agent` is never passed, so
    /// no text agent is started.
    pub(crate) fn pkcheck() -> PolkitOutcome {
        let pkcheck = match trusted_pkcheck() {
            Ok(path) => path,
            Err(error) => return PolkitOutcome::NotAvailable(error),
        };
        if let Err(error) = policy_installed() {
            return PolkitOutcome::NotAvailable(error);
        }
        let Some(start) = std::fs::read_to_string("/proc/self/stat")
            .ok()
            .and_then(|stat| proc_start_time(&stat))
        else {
            return PolkitOutcome::NotAvailable(String::from(
                "cannot read this process's start time",
            ));
        };
        let Some(uid) = std::fs::read_to_string("/proc/self/status")
            .ok()
            .as_deref()
            .and_then(real_uid)
        else {
            return PolkitOutcome::NotAvailable(String::from("cannot read this process's uid"));
        };
        let in_session = std::fs::read_to_string("/proc/self/cgroup")
            .is_ok_and(|cgroup| cgroup_in_session(&cgroup));
        // pid, start time and uid: the form that is not racy (CVE-2013-4288).
        let subject = format!("{},{start},{uid}", std::process::id());
        let args = [
            "--action-id",
            POLKIT_ACTION_ID,
            "--allow-user-interaction",
            "--process",
            subject.as_str(),
        ];
        match run_tool(
            &pkcheck,
            &args,
            Duration::from_millis(crate::STRONG_VERIFY_TIMEOUT_MS),
            4096,
        ) {
            Ok(Some((status, _, stderr))) => PolkitOutcome::Exited(
                status.code(),
                String::from_utf8_lossy(&stderr).into_owned(),
                in_session,
            ),
            Ok(None) => PolkitOutcome::TimedOut,
            Err(error) => PolkitOutcome::NotAvailable(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FailureCode, PresenceFailureReason};

    const NONCE: &str = "0123456789abcdef0123456789abcdef";

    fn ctx() -> PresenceContext {
        PresenceContext::new("nonce-xp10-0001", "d".repeat(64), "default", "delete file")
            .with_details("/home/me/a.txt", "Remove one file")
    }

    fn lease() -> InputLeaseGuard {
        InputLeaseGuard::suspend_for_presence()
    }

    fn soft_prompt() -> ApprovalPrompt {
        ApprovalPrompt::new_with_clock(
            "default",
            "rev-1",
            "write file",
            "/home/me/a.txt",
            "Replace 3 lines",
            "e".repeat(64),
            5_000,
        )
    }

    fn graphical(kind: &str) -> SessionFacts {
        SessionFacts {
            automation: false,
            ssh: false,
            wayland_display: (kind == "wayland").then(|| "wayland-0".to_owned()),
            wayland_socket_owned: kind == "wayland",
            x_display: Some(":0".to_owned()),
            logind: Ok(LogindSession {
                active: true,
                remote: false,
                kind: kind.to_owned(),
                class: "user".to_owned(),
                display: if kind == "x11" {
                    ":0".to_owned()
                } else {
                    String::new()
                },
            }),
        }
    }

    #[test]
    fn xp10_only_an_active_local_graphical_session_is_interactive() {
        for kind in ["x11", "wayland"] {
            assert_eq!(
                classify_session(&graphical(kind)),
                SessionState::Interactive
            );
        }
        assert_eq!(session_display(&graphical("x11")), Some(DisplayKind::X11));
        assert_eq!(
            session_display(&graphical("wayland")),
            Some(DisplayKind::Wayland)
        );
        let mut automation = graphical("wayland");
        automation.automation = true;
        assert_eq!(classify_session(&automation), SessionState::Automation);

        let mut cases = Vec::new();
        let mut ssh = graphical("x11");
        ssh.ssh = true;
        cases.push(("ssh", ssh));
        let mut headless = graphical("x11");
        headless.x_display = None;
        cases.push(("x11 without DISPLAY", headless));
        let mut no_wayland = graphical("wayland");
        no_wayland.wayland_display = None;
        cases.push(("wayland without WAYLAND_DISPLAY", no_wayland));
        let mut failed = graphical("x11");
        failed.logind = Err("no session".into());
        cases.push(("logind failed", failed));
        for (name, edit) in [
            (
                "inactive",
                (|s: &mut LogindSession| s.active = false) as fn(&mut LogindSession),
            ),
            ("remote", |s| s.remote = true),
            ("tty", |s| s.kind = "tty".into()),
            ("unspecified", |s| s.kind = "unspecified".into()),
            ("greeter", |s| s.class = "greeter".into()),
            ("lock-screen", |s| s.class = "lock-screen".into()),
            ("background", |s| s.class = "background".into()),
        ] {
            for kind in ["x11", "wayland"] {
                let mut facts = graphical(kind);
                if let Ok(session) = facts.logind.as_mut() {
                    edit(session);
                }
                cases.push((name, facts));
            }
        }
        for (name, facts) in cases {
            assert_eq!(
                classify_session(&facts),
                SessionState::NoGraphicSession,
                "{name}"
            );
            assert_eq!(session_display(&facts), None, "{name}");
            let mut ci = facts.clone();
            ci.automation = true;
            assert_eq!(classify_session(&ci), SessionState::Automation, "{name}");
        }
    }

    /// S-04 (M2): the dialog may only go to the active session's own
    /// display. `systemctl --user set-environment DISPLAY=:99` pointing at
    /// a same-uid Xvfb is refused on X11; a Wayland socket that is not this
    /// user's, or not in its runtime directory, is refused.
    #[test]
    fn xp10_display_must_belong_to_the_active_session() {
        for (display, ok) in [
            (":0", true),
            (":0.0", true),
            (":0.1", true),
            (":99", false),
            (":1", false),
            ("localhost:0", false),
            ("evil.example:0", false),
            ("unix:0", false),
            (":", false),
            (":0x", false),
            ("", false),
        ] {
            let mut facts = graphical("x11");
            facts.x_display = Some(display.to_owned());
            assert_eq!(session_display(&facts).is_some(), ok, "DISPLAY={display}");
        }
        // logind reporting no Display for an X11 session is refused too.
        let mut facts = graphical("x11");
        if let Ok(session) = facts.logind.as_mut() {
            session.display = String::new();
        }
        assert_eq!(session_display(&facts), None);
        // A Wayland session never uses DISPLAY, and needs its own socket.
        let mut facts = graphical("wayland");
        facts.wayland_socket_owned = false;
        assert_eq!(session_display(&facts), None);

        assert_eq!(
            wayland_socket_path("wayland-0", Some("/run/user/1000"), 1000),
            Some(std::path::PathBuf::from("/run/user/1000/wayland-0"))
        );
        assert_eq!(
            wayland_socket_path("/run/user/1000/wayland-1", None, 1000),
            Some(std::path::PathBuf::from("/run/user/1000/wayland-1"))
        );
        for (display, runtime) in [
            ("wayland-0", Some("/tmp/evil")),
            ("wayland-0", None),
            ("wayland-0", Some("/run/user/1001")),
            ("/tmp/wayland-0", Some("/run/user/1000")),
            ("/run/user/1001/wayland-0", Some("/run/user/1000")),
            ("../1001/wayland-0", Some("/run/user/1000")),
            ("sub/wayland-0", Some("/run/user/1000")),
            ("/run/user/1000/../1001/w", Some("/run/user/1000")),
            ("..", Some("/run/user/1000")),
        ] {
            assert_eq!(
                wayland_socket_path(display, runtime, 1000),
                None,
                "{display} {runtime:?}"
            );
        }

        // The helper is given only the verified display's variables.
        let x11 = helper_env_names(DisplayKind::X11);
        assert!(x11.contains(&"DISPLAY") && x11.contains(&"XAUTHORITY"));
        assert!(!x11.contains(&"WAYLAND_DISPLAY"));
        let wayland = helper_env_names(DisplayKind::Wayland);
        assert!(wayland.contains(&"WAYLAND_DISPLAY"));
        assert!(!wayland.contains(&"DISPLAY") && !wayland.contains(&"XAUTHORITY"));
    }

    #[test]
    fn xp10_logind_properties_parse_strictly() {
        let good = "Active=yes\nRemote=no\nType=wayland\nClass=user\nDisplay=\n";
        assert_eq!(
            parse_logind_properties(good),
            Ok(LogindSession {
                active: true,
                remote: false,
                kind: "wayland".into(),
                class: "user".into(),
                display: String::new(),
            })
        );
        // CRLF and unknown keys are tolerated; order does not matter.
        let crlf = "Display=:0\r\nClass=user\r\nId=3\r\nType=x11\r\nRemote=yes\r\nActive=no\r\n";
        let session = parse_logind_properties(crlf).expect("crlf");
        assert!(!session.active && session.remote && session.kind == "x11");
        assert_eq!(session.display, ":0");
        for bad in [
            "",
            "Active=yes\nRemote=no\nType=x11\nDisplay=:0\n",
            "Active=yes\nRemote=no\nType=x11\nClass=user\n",
            "Active=maybe\nRemote=no\nType=x11\nClass=user\nDisplay=\n",
            "Active=yes\nActive=yes\nRemote=no\nType=x11\nClass=user\nDisplay=\n",
            "Active=yes\nRemote=no\nType=x11\nClass=user\nDisplay=\ngarbage\n",
            "Active=yes\nRemote=\nType=x11\nClass=user\nDisplay=\n",
        ] {
            assert!(parse_logind_properties(bad).is_err(), "{bad:?}");
        }
    }

    const DIGEST: &str = "aa00000000000000000000000000000000000000000000000000000000000000";

    #[test]
    fn xp10_answer_must_carry_this_requests_nonce_and_digest() {
        let ok = |nonce: &str, approved| answer_line(nonce, DIGEST, approved);
        assert_eq!(
            parse_answer(ok(NONCE, true).as_bytes(), NONCE, DIGEST),
            Ok(true)
        );
        assert_eq!(
            parse_answer(ok(NONCE, false).as_bytes(), NONCE, DIGEST),
            Ok(false)
        );
        let other = "fedcba9876543210fedcba9876543210";
        let other_digest = format!("bb{}", &DIGEST[2..]);
        let refused: Vec<Vec<u8>> = vec![
            // Missing nonce or digest.
            format!("{HELPER_PROTOCOL} {DIGEST} approve\n").into_bytes(),
            format!("{HELPER_PROTOCOL} {NONCE} approve\n").into_bytes(),
            format!("{HELPER_PROTOCOL}  {DIGEST} approve\n").into_bytes(),
            format!("{HELPER_PROTOCOL} {NONCE}  approve\n").into_bytes(),
            b"approve\n".to_vec(),
            // Spoofed or replayed from another request.
            ok(other, true).into_bytes(),
            ok(&NONCE[..31], true).into_bytes(),
            ok(&format!("{NONCE}0"), true).into_bytes(),
            ok(&NONCE.to_uppercase(), true).into_bytes(),
            // The right nonce about other text (a substituted request).
            answer_line(NONCE, &other_digest, true).into_bytes(),
            answer_line(NONCE, &DIGEST.to_uppercase(), true).into_bytes(),
            answer_line(NONCE, &DIGEST[..63], true).into_bytes(),
            // A second answer appended, or noise before the answer.
            format!("{}{}", ok(NONCE, false), ok(NONCE, true)).into_bytes(),
            format!("Gtk-WARNING\n{}", ok(NONCE, true)).into_bytes(),
            // Partial, CRLF, padded or unknown verdicts.
            ok(NONCE, true).trim_end().as_bytes().to_vec(),
            format!("{HELPER_PROTOCOL} {NONCE} {DIGEST} approve\r\n").into_bytes(),
            format!("{HELPER_PROTOCOL} {NONCE} {DIGEST} approve \n").into_bytes(),
            format!("{HELPER_PROTOCOL} {NONCE} {DIGEST} Approve\n").into_bytes(),
            format!("{HELPER_PROTOCOL} {NONCE} {DIGEST} yes\n").into_bytes(),
            format!("orcel-approval-helper/2 {NONCE} {DIGEST} approve\n").into_bytes(),
            // Not UTF-8, empty, or too long.
            vec![0xff, 0xfe, b'\n'],
            Vec::new(),
            format!("{}{}", " ".repeat(MAX_ANSWER_BYTES), ok(NONCE, true)).into_bytes(),
        ];
        for output in refused {
            assert!(
                parse_answer(&output, NONCE, DIGEST).is_err(),
                "{:?}",
                String::from_utf8_lossy(&output)
            );
        }
        // Empty expectations never match empty fields.
        let blank = format!("{HELPER_PROTOCOL}   approve\n");
        assert!(parse_answer(blank.as_bytes(), "", "").is_err());
        assert!(parse_answer(ok(NONCE, true).as_bytes(), NONCE, "").is_err());
    }

    #[test]
    fn xp10_request_is_one_json_line_with_the_nonce() {
        let line = encode_request(NONCE, ApprovalClass::Soft, DIALOG_HEADER, "a\nb", 120);
        assert!(line.ends_with('\n'));
        assert_eq!(line.matches('\n').count(), 1, "{line}");
        let value: serde_json::Value = serde_json::from_str(line.trim_end()).expect("json");
        assert_eq!(value["protocol"], HELPER_PROTOCOL);
        assert_eq!(value["nonce"], NONCE);
        assert_eq!(value["class"], "SOFT");
        assert_eq!(value["body"], "a\nb");
        assert_eq!(value["timeout_secs"], 120);
        assert_eq!(hex(&[0, 1, 0xab, 0xff]), "0001abff");
        assert_eq!(
            request_digest(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    /// The helper's own protocol module (`apps/orcel-approval-helper-linux`)
    /// accepts what orceld sends and answers what orceld accepts, and a
    /// request substituted with the same nonce (M1) yields an answer orceld
    /// refuses.
    #[test]
    fn xp10_helper_protocol_matches_orceld() {
        use crate::linux_helper_protocol as helper;
        let body = dialog_body(&soft_prompt());
        let line = encode_request(NONCE, ApprovalClass::Soft, DIALOG_HEADER, &body, 120);
        let sent = request_digest(line.as_bytes());
        let request = helper::parse_request(line.as_bytes()).expect("helper accepts");
        assert_eq!(request.nonce, NONCE);
        assert_eq!(request.body, body);
        assert_eq!(request.title, DIALOG_HEADER);
        assert_eq!(request.timeout_secs, 120);
        assert_eq!(helper::PROTOCOL, HELPER_PROTOCOL);
        assert_eq!(helper::request_digest(line.as_bytes()), sent);
        for approved in [true, false] {
            let answer = helper::answer_line(&request.nonce, &sent, approved);
            assert_eq!(answer, answer_line(NONCE, &sent, approved));
            assert_eq!(parse_answer(answer.as_bytes(), NONCE, &sent), Ok(approved));
        }
        // Substitution: a same-uid process reads the real request (and its
        // nonce) from the helper's stdin and feeds a benign one with the
        // same nonce. The helper shows and hashes the benign bytes, so its
        // answer cannot match what orceld sent.
        let benign = encode_request(
            NONCE,
            ApprovalClass::Soft,
            DIALOG_HEADER,
            "Orcel requests a local action.\n\nAction: read a file",
            120,
        );
        let shown = helper::parse_request(benign.as_bytes()).expect("benign parses");
        assert_eq!(shown.nonce, NONCE);
        let answer = helper::answer_line(
            &shown.nonce,
            &helper::request_digest(benign.as_bytes()),
            true,
        );
        assert!(parse_answer(answer.as_bytes(), NONCE, &sent).is_err());
        // The helper refuses requests it cannot show safely.
        for bad in [
            line.replace(HELPER_PROTOCOL, "orcel-approval-helper/0"),
            line.replace(NONCE, "short"),
            line.replace(NONCE, &NONCE.to_uppercase()),
            line.replace("\"timeout_secs\":120", "\"timeout_secs\":0"),
            line.replace("\"timeout_secs\":120", "\"timeout_secs\":100000"),
            String::from("{}"),
            String::from("not json"),
        ] {
            assert!(helper::parse_request(bad.as_bytes()).is_err(), "{bad}");
        }
        let huge = encode_request(NONCE, ApprovalClass::Soft, "t", &"x".repeat(20_000), 120);
        assert!(helper::parse_request(huge.as_bytes()).is_err());
    }

    #[test]
    fn xp10_soft_decisions_fail_closed() {
        let prompt = soft_prompt();
        assert_eq!(
            decide(&prompt, HelperOutcome::Answered(true)).expect("approved"),
            ApprovalDecision::Approved
        );
        assert_eq!(
            decide(&prompt, HelperOutcome::Answered(false)).expect("denied"),
            ApprovalDecision::Denied
        );
        let cases = [
            (HelperOutcome::TimedOut, FailureCode::ApprovalUnavailable),
            (
                HelperOutcome::Crashed("signal 11".into()),
                FailureCode::ApprovalUnavailable,
            ),
            (
                HelperOutcome::Malformed("forged".into()),
                FailureCode::ApprovalUnavailable,
            ),
            (
                HelperOutcome::NotStarted("missing".into()),
                FailureCode::ApprovalUnavailable,
            ),
        ];
        for (outcome, code) in cases {
            assert_eq!(
                decide(&prompt, outcome.clone()).expect_err("closed").code,
                code,
                "{outcome:?}"
            );
        }
        let strong = prompt.with_class(ApprovalClass::Strong);
        assert_eq!(
            decide(&strong, HelperOutcome::Answered(true))
                .expect_err("strong")
                .code,
            FailureCode::ApprovalUnavailable
        );
        assert!(session_gate(SessionState::Interactive).is_ok());
        for session in [SessionState::Automation, SessionState::NoGraphicSession] {
            assert_eq!(
                session_gate(session).expect_err("closed").code,
                FailureCode::ApprovalUnavailable
            );
        }
    }

    #[test]
    fn xp10_strong_success_needs_the_dialog_and_polkit_and_is_bound() {
        let ctx = ctx();
        let mut shown = String::new();
        let attestation = verify_with(
            &ctx,
            &lease(),
            POLKIT_PRESENCE_METHOD,
            SessionState::Interactive,
            |body| {
                shown = body.to_owned();
                HelperOutcome::Answered(true)
            },
            || PolkitOutcome::Exited(Some(0), String::new(), true),
        )
        .expect("verified");
        assert_eq!(attestation.nonce, ctx.nonce);
        assert_eq!(attestation.digest, ctx.digest);
        assert_eq!(attestation.method, POLKIT_PRESENCE_METHOD);
        for line in [
            "\nWorkspace: default\n",
            "\nAction: delete file\n",
            "\nTarget: /home/me/a.txt\n",
            "\nRemove one file\n",
            &format!("\nDigest: {}\n", ctx.digest),
            "Approval: STRONG nonce-xp",
        ] {
            assert!(shown.contains(line), "{line:?} in {shown}");
        }
    }

    #[test]
    fn xp10_polkit_is_not_asked_unless_the_dialog_approved() {
        let outcomes = [
            (
                HelperOutcome::Answered(false),
                PresenceFailureReason::Denied,
            ),
            (HelperOutcome::TimedOut, PresenceFailureReason::Timeout),
            (
                HelperOutcome::Crashed("exit status 1".into()),
                PresenceFailureReason::Unavailable,
            ),
            (
                HelperOutcome::Malformed("forged".into()),
                PresenceFailureReason::InvalidResponse,
            ),
            (
                HelperOutcome::NotStarted("missing".into()),
                PresenceFailureReason::Unavailable,
            ),
        ];
        for (outcome, reason) in outcomes {
            let mut asked = false;
            let error = verify_with(
                &ctx(),
                &lease(),
                POLKIT_PRESENCE_METHOD,
                SessionState::Interactive,
                |_| outcome.clone(),
                || {
                    asked = true;
                    PolkitOutcome::Exited(Some(0), String::new(), true)
                },
            )
            .expect_err("fails closed");
            assert!(!asked, "{outcome:?} must not reach polkit");
            assert_eq!(error.reason, reason, "{outcome:?}");
        }
    }

    #[test]
    fn xp10_polkit_challenge_denial_no_agent_and_errors_fail_closed() {
        let cases = [
            (Some(1), "", PresenceFailureReason::Denied),
            (Some(2), "", PresenceFailureReason::Unavailable),
            (Some(3), "", PresenceFailureReason::Cancelled),
            (
                Some(1),
                "Error checking for authorization ai.orcel.approve.strong: GDBus.Error",
                PresenceFailureReason::Unavailable,
            ),
            (
                Some(1),
                "Action ai.orcel.approve.strong is not registered",
                PresenceFailureReason::Unavailable,
            ),
            (Some(127), "Error: refused", PresenceFailureReason::Failed),
            (Some(4), "", PresenceFailureReason::Failed),
            (None, "", PresenceFailureReason::Failed),
        ];
        // orceld outside a login session (a user service): a plain "not
        // authorized" may mean polkit found no session to ask in.
        assert_eq!(
            pkcheck_outcome(Some(1), "", false)
                .expect_err("closed")
                .reason,
            PresenceFailureReason::Unavailable
        );
        assert!(pkcheck_outcome(Some(0), "", false).is_ok());
        assert_eq!(
            pkcheck_outcome(Some(3), "", false)
                .expect_err("closed")
                .reason,
            PresenceFailureReason::Cancelled
        );
        for (code, stderr, reason) in cases {
            let error = verify_with(
                &ctx(),
                &lease(),
                POLKIT_PRESENCE_METHOD,
                SessionState::Interactive,
                |_| HelperOutcome::Answered(true),
                || PolkitOutcome::Exited(code, stderr.to_owned(), true),
            )
            .expect_err("fails closed");
            assert_eq!(error.reason, reason, "{code:?} {stderr}");
        }
        for (outcome, reason) in [
            (PolkitOutcome::TimedOut, PresenceFailureReason::Timeout),
            (
                PolkitOutcome::NotAvailable("no pkcheck".into()),
                PresenceFailureReason::Unavailable,
            ),
        ] {
            let error = verify_with(
                &ctx(),
                &lease(),
                POLKIT_PRESENCE_METHOD,
                SessionState::Interactive,
                |_| HelperOutcome::Answered(true),
                || outcome.clone(),
            )
            .expect_err("fails closed");
            assert_eq!(error.reason, reason, "{outcome:?}");
        }
    }

    #[test]
    fn xp10_no_session_inactive_or_remote_never_prompts() {
        for session in [SessionState::NoGraphicSession, SessionState::Automation] {
            let asked = std::cell::Cell::new(false);
            let error = verify_with(
                &ctx(),
                &lease(),
                POLKIT_PRESENCE_METHOD,
                session,
                |_| {
                    asked.set(true);
                    HelperOutcome::Answered(true)
                },
                || {
                    asked.set(true);
                    PolkitOutcome::Exited(Some(0), String::new(), true)
                },
            )
            .expect_err("fails closed");
            assert!(!asked.get(), "{session:?}");
            assert_eq!(error.reason, PresenceFailureReason::Unavailable);
            assert_eq!(error.code, FailureCode::ApprovalUnavailable);
        }
        let mut released = lease();
        released.suspended = false;
        let error = verify_with(
            &ctx(),
            &released,
            POLKIT_PRESENCE_METHOD,
            SessionState::Interactive,
            |_| HelperOutcome::Answered(true),
            || PolkitOutcome::Exited(Some(0), String::new(), true),
        )
        .expect_err("lease");
        assert_eq!(error.reason, PresenceFailureReason::InvalidResponse);
    }

    #[test]
    fn xp10_strong_body_escapes_and_bounds_hostile_fields() {
        let hostile = PresenceContext::new(
            "abcdefgh-rest",
            "0123456789abcdef",
            "ws\u{2067}",
            "rm\nApproval: STRONG trusted\u{202e}\u{200b}\u{e0041}",
        )
        .with_details("t".repeat(5_000), "line1\r\nline2\u{2028}");
        let body = strong_body(&hostile);
        let benign = strong_body(&ctx());
        assert_eq!(body.lines().count(), benign.lines().count());
        for ch in [
            '\u{202e}',
            '\u{200b}',
            '\u{e0041}',
            '\u{2067}',
            '\u{2028}',
            '\r',
        ] {
            assert!(!body.contains(ch), "{ch:?}");
        }
        assert!(
            body.contains("Action: rm\\u{a}Approval: STRONG trusted\\u{202e}\\u{200b}\\u{e0041}\n")
        );
        assert!(body.contains(&format!(
            "Target: {} [4488 more characters not shown]\n",
            "t".repeat(512)
        )));
        assert!(body.contains("line1\\u{d}\\u{a}line2\\u{2028}\n"));
        assert!(body.chars().count() < 3_000);
    }

    #[test]
    fn xp10_pkcheck_subject_and_file_trust_rules() {
        let stat =
            "4242 (orc el) d) S 1 4242 4242 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 3 0 987654 1000 10";
        assert_eq!(proc_start_time(stat), Some(987654));
        assert_eq!(proc_start_time("no name here"), None);
        assert_eq!(proc_start_time("1 (x) S 1"), None);
        let status = "Name:\torceld\nUid:\t1000\t1001\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\n";
        assert_eq!(effective_uid(status), Some(1001));
        assert_eq!(effective_uid("Name:\tx\n"), None);
        assert_eq!(real_uid(status), Some(1000));
        assert_eq!(real_uid("Uid:\t\n"), None);
        assert!(cgroup_in_session(
            "0::/user.slice/user-1000.slice/session-3.scope\n"
        ));
        assert!(!cgroup_in_session(
            "0::/user.slice/user-1000.slice/user@1000.service/app.slice/orceld.service\n"
        ));
        assert!(!cgroup_in_session("0::/session-3.scope/child\n"));
        assert!(!cgroup_in_session(""));
        // root-owned 0755 is trusted; group or world write never is.
        assert!(owner_and_mode_trusted(0, 0o100755, 1000, false));
        assert!(!owner_and_mode_trusted(0, 0o100775, 1000, false));
        assert!(!owner_and_mode_trusted(0, 0o100757, 1000, true));
        // A user-owned file is trusted only where the user's own files are.
        assert!(!owner_and_mode_trusted(1000, 0o100755, 1000, false));
        assert!(owner_and_mode_trusted(1000, 0o100755, 1000, true));
        assert!(!owner_and_mode_trusted(1001, 0o100755, 1000, true));
        // /tmp (1777) can be written by everyone.
        assert!(!owner_and_mode_trusted(0, 0o041777, 1000, true));
    }

    /// S-04 / T-CUA-35: the shipped polkit action requires the person's own
    /// credentials in an active session every time and grants nothing to an
    /// inactive or remote one.
    #[test]
    fn xp10_polkit_policy_is_auth_self_for_active_sessions_only() {
        let policy = include_str!("../../../distribution/linux/ai.orcel.approve.policy")
            .replace("\r\n", "\n");
        let body = policy
            .split_once("-->")
            .map(|(_, rest)| rest)
            .expect("the header comment ends");
        assert_eq!(body.matches("<action id=").count(), 1);
        assert!(body.contains(&format!("<action id=\"{POLKIT_ACTION_ID}\">")));
        assert!(body.contains("<allow_any>no</allow_any>"));
        assert!(body.contains("<allow_inactive>no</allow_inactive>"));
        assert!(body.contains("<allow_active>auth_self</allow_active>"));
        for forbidden in ["yes", "auth_admin", "_keep", "annotate", "exec.path"] {
            assert!(!body.contains(forbidden), "{forbidden}");
        }
        // XML comments may not contain a double hyphen.
        let comment = policy.split_once("<!--").expect("comment").1;
        let comment = comment.split_once("-->").expect("comment end").0;
        assert!(!comment.contains("--"));
        assert!(POLKIT_POLICY_PATH.ends_with("/ai.orcel.approve.policy"));
    }

    /// No variable can approve: the shipped code reads only the automation,
    /// SSH and display variables (each can only make approvals
    /// unavailable), passes the helper a fixed allowlist, and never reads a
    /// variable that names a helper, a tool or an answer.
    #[test]
    fn xp10_no_environment_variable_can_approve() {
        // A Windows checkout may have CRLF line endings.
        let source = include_str!("linux.rs").replace("\r\n", "\n");
        let (shipped, tests) = source
            .split_once("#[cfg(test)]\nmod tests {")
            .expect("the test module marker is present");
        assert!(tests.contains("fn xp10_no_environment_variable_can_approve"));
        assert!(!shipped.contains("fn xp10_"));
        let donor_prefix = ["CUA", "_ENV"].concat();
        assert!(!shipped.contains(&donor_prefix));
        assert!(!shipped.contains("SENSITIVE"));
        assert!(!shipped.contains("env::vars"));
        assert!(!shipped.contains("env::var("));
        assert!(!shipped.contains("--enable-internal-agent\""));
        let reads: Vec<&str> = shipped
            .lines()
            .filter(|line| line.contains("env::var_os"))
            .collect();
        assert_eq!(reads.len(), 2, "{reads:?}");
        assert!(
            reads[0].contains("std::env::var_os(name)") && !reads[0].contains("filter_map"),
            "{reads:?}"
        );
        assert!(shipped.contains("let get = |name: &str| {"));
        assert!(shipped.contains("let set = |name: &str| get(name).is_some();"));
        assert!(reads[1].contains("HELPER_ENV_ALLOWLIST") || reads[1].contains("filter_map"));
        let mut names: Vec<&str> = ["set(\"", "get(\""]
            .iter()
            .flat_map(|marker| shipped.split(marker).skip(1))
            .filter_map(|rest| rest.split('"').next())
            .collect();
        names.sort_unstable();
        assert_eq!(
            names,
            [
                "CI",
                "DISPLAY",
                "GITHUB_ACTIONS",
                "SSH_CLIENT",
                "SSH_CONNECTION",
                "SSH_TTY",
                "WAYLAND_DISPLAY",
                "XDG_RUNTIME_DIR"
            ]
        );
        for name in HELPER_ENV_ALLOWLIST {
            assert!(
                !name.starts_with("LD_") && !name.starts_with("GTK"),
                "{name}"
            );
        }
        // Commands start from absolute paths only.
        assert!(!shipped.contains("Command::new(\""));
    }

    /// Linux only: the real helper runner against scripted helpers. A
    /// forged or replayed nonce, extra output, a crash, silence and a hang
    /// all fail closed; only the request's own nonce approves.
    #[cfg(target_os = "linux")]
    mod runner {
        use super::super::sys;
        use super::super::*;
        use std::os::unix::fs::PermissionsExt;
        use std::path::PathBuf;
        use std::time::{Duration, Instant};

        /// `sys::run_helper`, retried when exec fails with ETXTBSY: a script
        /// written moments ago can still be open for writing in a child
        /// another test thread forked and has not yet exec'd.
        fn run_helper(
            path: &std::path::Path,
            class: ApprovalClass,
            title: &str,
            body: &str,
            dialog_timeout_secs: u64,
            deadline: Duration,
            env: Vec<(std::ffi::OsString, std::ffi::OsString)>,
        ) -> HelperOutcome {
            for _ in 0..20 {
                let outcome = sys::run_helper(
                    path,
                    class,
                    title,
                    body,
                    dialog_timeout_secs,
                    deadline,
                    env.clone(),
                );
                match &outcome {
                    HelperOutcome::NotStarted(error) if error.contains("Text file busy") => {
                        std::thread::sleep(Duration::from_millis(50));
                    }
                    _ => return outcome,
                }
            }
            HelperOutcome::NotStarted(String::from("Text file busy (retries exhausted)"))
        }

        fn script(name: &str, body: &str) -> PathBuf {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let dir = std::env::temp_dir().join(format!(
                "orcel-xp10-{}-{}-{}",
                std::process::id(),
                crate::now_ms(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&dir).expect("dir");
            let path = dir.join(name);
            std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("write");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).expect("chmod");
            path
        }

        fn run(body: &str, deadline: Duration) -> HelperOutcome {
            let path = script("helper", body);
            let outcome = run_helper(
                &path,
                ApprovalClass::Soft,
                DIALOG_HEADER,
                "body",
                1,
                deadline,
                Vec::new(),
            );
            let _ = std::fs::remove_dir_all(path.parent().expect("dir"));
            outcome
        }

        /// Echoes the nonce from the request it was sent, and hashes the
        /// exact request line (with its newline) as the real helper does.
        const ECHO: &str = r#"read -r line; nonce=$(printf '%s' "$line" | /usr/bin/sed 's/.*"nonce":"\([0-9a-f]*\)".*/\1/'); digest=$(printf '%s\n' "$line" | /usr/bin/sha256sum | /usr/bin/cut -d' ' -f1)"#;

        #[test]
        fn xp10_runner_accepts_only_this_requests_nonce() {
            let approve = format!(
                "{ECHO}; printf 'orcel-approval-helper/1 %s %s approve\\n' \"$nonce\" \"$digest\""
            );
            assert_eq!(
                run(&approve, Duration::from_secs(10)),
                HelperOutcome::Answered(true)
            );
            let deny = format!(
                "{ECHO}; printf 'orcel-approval-helper/1 %s %s deny\\n' \"$nonce\" \"$digest\""
            );
            assert_eq!(
                run(&deny, Duration::from_secs(10)),
                HelperOutcome::Answered(false)
            );
            // Spoofed, missing and replayed nonces.
            for body in [
                "read line; echo 'orcel-approval-helper/1 0123456789abcdef0123456789abcdef e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 approve'".to_owned(),
                "read line; echo 'orcel-approval-helper/1 approve'".to_owned(),
                // The right nonce, but no digest, or the digest of other text:
                // the request this helper showed is not the one orceld sent.
                format!("{ECHO}; printf 'orcel-approval-helper/1 %s approve\\n' \"$nonce\""),
                format!("{ECHO}; other=$(printf '%s\\n' \"$line\" | /usr/bin/sed 's/\"body\":\"body\"/\"body\":\"safe\"/' | /usr/bin/sha256sum | /usr/bin/cut -d' ' -f1); printf 'orcel-approval-helper/1 %s %s approve\\n' \"$nonce\" \"$other\""),
                "echo approve".to_owned(),
                format!("{ECHO}; printf 'orcel-approval-helper/1 %s %s approve\\n' \"$nonce\" \"$digest\"; printf 'orcel-approval-helper/1 %s %s approve\\n' \"$nonce\" \"$digest\""),
            ] {
                assert!(
                    matches!(run(&body, Duration::from_secs(10)), HelperOutcome::Malformed(_)),
                    "{body}"
                );
            }
            // The same helper run twice gets two different nonces: an answer
            // captured from the first run is refused by the second.
            let capture = script("capture", &format!("{ECHO}; printf '%s %s' \"$nonce\" \"$digest\" > \"$0.nonce\"; printf 'orcel-approval-helper/1 %s %s approve\\n' \"$nonce\" \"$digest\""));
            let first = run_helper(
                &capture,
                ApprovalClass::Soft,
                "t",
                "b",
                1,
                Duration::from_secs(10),
                Vec::new(),
            );
            assert_eq!(first, HelperOutcome::Answered(true));
            let old = std::fs::read_to_string(capture.with_extension("nonce")).expect("nonce");
            let replay = script(
                "replay",
                &format!("read line; printf 'orcel-approval-helper/1 %s approve\\n' '{old}'"),
            );
            assert!(matches!(
                run_helper(
                    &replay,
                    ApprovalClass::Soft,
                    "t",
                    "b",
                    1,
                    Duration::from_secs(10),
                    Vec::new()
                ),
                HelperOutcome::Malformed(_)
            ));
            let _ = std::fs::remove_dir_all(capture.parent().expect("dir"));
            let _ = std::fs::remove_dir_all(replay.parent().expect("dir"));
        }

        #[test]
        fn xp10_runner_crash_silence_and_hang_fail_closed() {
            assert!(matches!(
                run(
                    &format!(
                        "{ECHO}; printf 'orcel-approval-helper/1 %s %s approve\\n' \"$nonce\" \"$digest\"; exit 1"
                    ),
                    Duration::from_secs(10)
                ),
                HelperOutcome::Crashed(_)
            ));
            assert!(matches!(
                run("kill -SEGV $$", Duration::from_secs(10)),
                HelperOutcome::Crashed(_)
            ));
            assert!(matches!(
                run("read line; exit 0", Duration::from_secs(10)),
                HelperOutcome::Malformed(_)
            ));
            let started = Instant::now();
            assert_eq!(
                run("read line; /usr/bin/sleep 30", Duration::from_millis(500)),
                HelperOutcome::TimedOut
            );
            assert!(started.elapsed() < Duration::from_secs(10));
            assert!(matches!(
                run_helper(
                    std::path::Path::new("/nonexistent/orcel-approval-helper-linux"),
                    ApprovalClass::Soft,
                    "t",
                    "b",
                    1,
                    Duration::from_secs(1),
                    Vec::new()
                ),
                HelperOutcome::NotStarted(_)
            ));
        }

        #[test]
        fn xp10_runner_clears_the_environment() {
            // The test process has HOME (sh may invent a default PATH, so
            // PATH proves nothing); the helper sees only what it is given.
            assert!(std::env::var_os("HOME").is_some());
            let body = format!("{ECHO}; if [ -z \"$HOME$LD_PRELOAD$CARGO\" ] && [ \"$ORCEL_XP10_GIVEN\" = 1 ]; then v=approve; else v=deny; fi; printf 'orcel-approval-helper/1 %s %s %s\n' \"$nonce\" \"$digest\" \"$v\"");
            let path = script("env", &body);
            let outcome = run_helper(
                &path,
                ApprovalClass::Soft,
                DIALOG_HEADER,
                "body",
                1,
                Duration::from_secs(10),
                vec![("ORCEL_XP10_GIVEN".into(), "1".into())],
            );
            let _ = std::fs::remove_dir_all(path.parent().expect("dir"));
            assert_eq!(outcome, HelperOutcome::Answered(true));
        }

        #[test]
        fn xp10_helper_location_is_never_taken_from_path() {
            // A helper on PATH or in the working directory is not found:
            // only the sibling of the test binary and the system path count.
            match sys::helper_path() {
                Ok(path) => {
                    let exe_dir = std::env::current_exe()
                        .ok()
                        .and_then(|exe| std::fs::canonicalize(exe).ok())
                        .and_then(|exe| exe.parent().map(|dir| dir.to_path_buf()));
                    assert!(
                        path == std::path::Path::new(SYSTEM_HELPER_PATH)
                            || path.parent().map(std::path::Path::to_path_buf) == exe_dir,
                        "{path:?}"
                    );
                }
                Err(error) => assert!(
                    error.contains(HELPER_FILE_NAME) || error.contains("written"),
                    "{error}"
                ),
            }
            assert!(sys::trusted_file(std::path::Path::new("/tmp"), true).is_err());
        }
    }
}
