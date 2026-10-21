//! orcel-approval-helper-linux (XP-10): the GTK4 approval dialog orceld
//! spawns on Linux.
//!
//! First, before GTK or anything else is loaded, it checks that stdin is a
//! pipe and reads the whole request from it. It shows the text exactly as
//! orceld sent it (orceld bounds and escapes every field; the helper refuses
//! text that was not escaped), and prints one answer line to stdout with
//! orceld's channel nonce and the SHA-256 of the exact bytes it read, so
//! orceld refuses the answer when those bytes are not what it sent. Deny is
//! the default button and Approve becomes clickable only after a short
//! delay. Deny, Escape, closing the window and the timeout all answer deny.
//! When the request is refused or no dialog can be shown (no display), the
//! helper prints nothing and exits non-zero, which orceld treats as a
//! failure.
//!
//! The helper decides nothing: orceld's broker records the answer for the
//! request it asked about and the ledger binds it to that request. It is
//! never looked up on `PATH`; orceld starts it from a pinned location with a
//! cleared environment.

mod protocol;

#[cfg(target_os = "linux")]
mod dialog;

use std::io::{Read, Write};
use std::process::ExitCode;

fn main() -> ExitCode {
    if !make_non_dumpable() {
        eprintln!("orcel-approval-helper-linux: cannot make the process non-dumpable");
        return ExitCode::from(2);
    }
    if !stdin_is_pipe() {
        eprintln!("orcel-approval-helper-linux: stdin is not a pipe");
        return ExitCode::from(2);
    }
    let mut input = Vec::new();
    let limit = protocol::MAX_REQUEST_BYTES as u64 + 1;
    if std::io::stdin()
        .lock()
        .take(limit)
        .read_to_end(&mut input)
        .is_err()
    {
        return ExitCode::from(2);
    }
    let request = match protocol::parse_request(&input) {
        Ok(request) => request,
        Err(error) => {
            eprintln!("orcel-approval-helper-linux: {error}");
            return ExitCode::from(2);
        }
    };
    // The digest of the bytes parsed and shown, not of anything re-encoded.
    let digest = protocol::request_digest(&input);
    let Some(approved) = show(&request) else {
        eprintln!("orcel-approval-helper-linux: no dialog could be shown");
        return ExitCode::from(3);
    };
    let mut stdout = std::io::stdout().lock();
    let answer = protocol::answer_line(&request.nonce, &digest, approved);
    if stdout
        .write_all(answer.as_bytes())
        .and_then(|()| stdout.flush())
        .is_err()
    {
        return ExitCode::from(4);
    }
    ExitCode::SUCCESS
}

/// #373 item 1: before the request is read, the helper makes itself
/// non-dumpable. With Yama `ptrace_scope=0` another process of the same user
/// could otherwise attach (or write `/proc/<pid>/mem`) and change the text
/// after it was hashed and before it is shown. A non-dumpable process can
/// only be traced with `CAP_SYS_PTRACE`, its `/proc/<pid>` files belong to
/// root, and it writes no core dump. If the call fails the helper answers
/// nothing, which orceld treats as unavailable.
#[cfg(target_os = "linux")]
fn make_non_dumpable() -> bool {
    // SAFETY: PR_SET_DUMPABLE reads only its integer arguments and touches
    // no memory of this process; the unused arguments are 0, as prctl(2)
    // requires.
    unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) == 0 }
}

#[cfg(not(target_os = "linux"))]
fn make_non_dumpable() -> bool {
    true
}

/// orceld always starts the helper with a pipe it owns on stdin.
#[cfg(target_os = "linux")]
fn stdin_is_pipe() -> bool {
    use std::os::unix::fs::FileTypeExt;
    std::fs::metadata("/proc/self/fd/0").is_ok_and(|meta| meta.file_type().is_fifo())
}

#[cfg(not(target_os = "linux"))]
fn stdin_is_pipe() -> bool {
    true
}

#[cfg(target_os = "linux")]
fn show(request: &protocol::Request) -> Option<bool> {
    dialog::ask(request)
}

/// The helper exists for Linux only; elsewhere nothing can be shown.
#[cfg(not(target_os = "linux"))]
fn show(_request: &protocol::Request) -> Option<bool> {
    None
}
