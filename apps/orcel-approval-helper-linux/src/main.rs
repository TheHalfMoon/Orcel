//! orcel-approval-helper-linux (XP-10): the GTK4 approval dialog orceld
//! spawns on Linux.
//!
//! It reads one request from stdin, shows the text exactly as orceld sent
//! it (orceld bounds and escapes every field; the helper refuses text that
//! was not escaped), and prints one answer line with orceld's channel nonce
//! to stdout. Deny is the default button and Approve becomes clickable only
//! after a short delay. Deny, Escape, closing the window and the timeout all
//! answer deny. When the request is refused or no dialog can be shown (no
//! display), the helper prints nothing and exits non-zero, which orceld
//! treats as a failure.
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
    let Some(approved) = show(&request) else {
        eprintln!("orcel-approval-helper-linux: no dialog could be shown");
        return ExitCode::from(3);
    };
    let mut stdout = std::io::stdout().lock();
    let answer = protocol::answer_line(&request.nonce, approved);
    if stdout
        .write_all(answer.as_bytes())
        .and_then(|()| stdout.flush())
        .is_err()
    {
        return ExitCode::from(4);
    }
    ExitCode::SUCCESS
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
