//! The service-rendered confirmation (spec 4.13 step 4).
//!
//! `WTSSendMessageW` asks the system to show a message box in the user's
//! session on the service's behalf, titled "Orcel Authority", with the
//! requested scope, client, task, expiry and the C-27 disclosures, buttons
//! Yes and No, a 60 s timeout, and waits for the answer. No user-session
//! process draws it.
//!
//! Not yet proven (WP1-10): that `SendInput` or `PostMessageW` from a
//! medium-integrity user process cannot answer it. Until that verification
//! runs on the installed service, every grant records
//! `confirmation_input_protected: false` and the C-27 (f) residual carries
//! the weight. Also to be verified at install: that the virtual service
//! account may send a message to the console session (the
//! `WINSTATION_MSG` right); a failure answers [`ConfirmAnswer::Failed`]
//! and the intent is cleared, so nothing is issued.

use crate::core::{ConfirmAnswer, ConfirmationTask};
use windows_sys::Win32::System::RemoteDesktop::{WTSSendMessageW, WTS_CURRENT_SERVER_HANDLE};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    IDNO, IDTIMEOUT, IDYES, MB_DEFBUTTON2, MB_ICONWARNING, MB_SETFOREGROUND, MB_TOPMOST, MB_YESNO,
};

/// Renders `task` and waits for the answer (at most its timeout).
pub fn render(task: &ConfirmationTask) -> ConfirmAnswer {
    let title: Vec<u16> = task.title.encode_utf16().collect();
    let text: Vec<u16> = task.text.encode_utf16().collect();
    let mut response = 0i32;
    // SAFETY: both strings live through the call; lengths are in bytes as
    // the API requires; `response` receives the button id.
    let ok = unsafe {
        WTSSendMessageW(
            WTS_CURRENT_SERVER_HANDLE,
            task.ts_session_id,
            title.as_ptr(),
            (title.len() * 2) as u32,
            text.as_ptr(),
            (text.len() * 2) as u32,
            MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2 | MB_SETFOREGROUND | MB_TOPMOST,
            task.timeout_secs,
            &mut response,
            1,
        )
    };
    if ok == 0 {
        return ConfirmAnswer::Failed(format!(
            "WTSSendMessageW: {}",
            std::io::Error::last_os_error()
        ));
    }
    match response {
        IDYES => ConfirmAnswer::Yes,
        IDNO => ConfirmAnswer::No,
        IDTIMEOUT => ConfirmAnswer::Timeout,
        other => ConfirmAnswer::Failed(format!("unexpected answer {other}")),
    }
}
