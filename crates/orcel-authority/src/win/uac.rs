//! Slice 2 review F1 (a): the machine's UAC policy, read-only.
//!
//! Enrollment and reset trust the UAC prompt on the secure desktop as the
//! human gate, which holds only when UAC is on (`EnableLUA` 1), an
//! administrator is asked for consent on every elevation ("Always notify",
//! `ConsentPromptBehaviorAdmin` 2) and the prompt is on the secure desktop
//! (`PromptOnSecureDesktop` 1). The service reads the three values from
//! `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` and
//! never writes them. A value it cannot read counts as not set.

use crate::core::{UacPolicy, UacSettings};
use windows_sys::Win32::System::Registry::{RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD};

const POLICY_KEY: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";

fn read_dword(name: &str) -> Option<u32> {
    let key = super::wide(POLICY_KEY);
    let value = super::wide(name);
    let mut data = 0u32;
    let mut size = std::mem::size_of::<u32>() as u32;
    // SAFETY: both names are NUL-terminated; `data` holds `size` bytes.
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            key.as_ptr(),
            value.as_ptr(),
            RRF_RT_REG_DWORD,
            std::ptr::null_mut(),
            (&mut data as *mut u32).cast(),
            &mut size,
        )
    };
    (status == 0).then_some(data)
}

/// The local machine's UAC policy.
pub struct MachineUacPolicy;

impl UacPolicy for MachineUacPolicy {
    fn read(&self) -> UacSettings {
        UacSettings {
            enable_lua: read_dword("EnableLUA"),
            consent_prompt_behavior_admin: read_dword("ConsentPromptBehaviorAdmin"),
            prompt_on_secure_desktop: read_dword("PromptOnSecureDesktop"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Read-only: the values on this PC come back as numbers or nothing.
    #[test]
    fn the_uac_policy_is_read_without_writing() {
        let settings = MachineUacPolicy.read();
        for value in [
            settings.enable_lua,
            settings.consent_prompt_behavior_admin,
            settings.prompt_on_secure_desktop,
        ]
        .into_iter()
        .flatten()
        {
            assert!(value <= 5, "{value}");
        }
        assert_eq!(MachineUacPolicy.read(), settings, "reading changes nothing");
    }
}
