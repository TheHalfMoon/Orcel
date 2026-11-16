//! WebView2 settings, applied through the platform web view handle, then
//! read back and asserted.
//!
//! The window is created hidden; these settings are applied in this order,
//! each one read back, and any mismatch closes the window with the setting
//! named. Only then is the page reloaded and the window shown (see
//! `shell.rs`). Devtools are off three ways: the `devtools` Cargo feature is
//! not enabled, the builder calls `.devtools(false)`, and
//! `AreDevToolsEnabled` is false here.

use webview2_com::Microsoft::Web::WebView2::Win32::{
    ICoreWebView2Settings, ICoreWebView2Settings3, ICoreWebView2Settings4,
};
use windows_core::{Interface, BOOL};

/// The browser arguments, exactly. They replace Tauri's and wry's defaults
/// (which are the same string): `msSmartScreenProtection` stops URL
/// reputation lookups to Microsoft for a view that loads embedded assets
/// only, and `msWebOOUI` and `msPdfOOUI` keep Edge's out-of-process UI
/// surfaces out of the view. No other argument, never a remote-debugging or
/// logging one.
pub const BROWSER_ARGS: &str = "--disable-features=msWebOOUI,msPdfOOUI,msSmartScreenProtection";

/// Every setting the shell asserts, with the value it must hold, in the
/// order applied.
///
/// `IsWebMessageEnabled` is false because Tauri's IPC never needed a web
/// message on Windows: with it enabled, the native run counted
/// `web_messages=0` while commands went through the custom protocol (prep
/// packet, "Slice A2 as implemented"). With it false the `postMessage`
/// fallback cannot exist; the Rust-side counter stays registered anyway.
pub const SETTINGS: [(&str, bool); 9] = [
    ("AreDevToolsEnabled", false),
    ("AreDefaultContextMenusEnabled", false),
    ("AreBrowserAcceleratorKeysEnabled", false),
    ("IsStatusBarEnabled", false),
    ("IsGeneralAutofillEnabled", false),
    ("IsPasswordAutosaveEnabled", false),
    ("AreHostObjectsAllowed", false),
    ("IsBuiltInErrorPageEnabled", false),
    ("IsWebMessageEnabled", false),
];

fn later(
    settings: &ICoreWebView2Settings,
) -> Result<(ICoreWebView2Settings3, ICoreWebView2Settings4), String> {
    let three = settings
        .cast::<ICoreWebView2Settings3>()
        .map_err(|error| format!("this WebView2 has no ICoreWebView2Settings3: {error}"))?;
    let four = settings
        .cast::<ICoreWebView2Settings4>()
        .map_err(|error| format!("this WebView2 has no ICoreWebView2Settings4: {error}"))?;
    Ok((three, four))
}

/// Applies [`SETTINGS`] in order.
pub fn apply(settings: &ICoreWebView2Settings) -> Result<(), String> {
    let (three, four) = later(settings)?;
    for (name, value) in SETTINGS {
        // SAFETY: plain COM setters on live interfaces.
        let result = unsafe {
            match name {
                "AreDevToolsEnabled" => settings.SetAreDevToolsEnabled(value),
                "AreDefaultContextMenusEnabled" => settings.SetAreDefaultContextMenusEnabled(value),
                "AreBrowserAcceleratorKeysEnabled" => {
                    three.SetAreBrowserAcceleratorKeysEnabled(value)
                }
                "IsStatusBarEnabled" => settings.SetIsStatusBarEnabled(value),
                "IsGeneralAutofillEnabled" => four.SetIsGeneralAutofillEnabled(value),
                "IsPasswordAutosaveEnabled" => four.SetIsPasswordAutosaveEnabled(value),
                "AreHostObjectsAllowed" => settings.SetAreHostObjectsAllowed(value),
                "IsBuiltInErrorPageEnabled" => settings.SetIsBuiltInErrorPageEnabled(value),
                "IsWebMessageEnabled" => settings.SetIsWebMessageEnabled(value),
                other => return Err(format!("no setter for {other}")),
            }
        };
        result.map_err(|error| format!("{name} could not be set: {error}"))?;
    }
    Ok(())
}

/// Reads every setting in [`SETTINGS`] back, in order.
pub fn read_back(settings: &ICoreWebView2Settings) -> Result<Vec<(&'static str, bool)>, String> {
    let (three, four) = later(settings)?;
    let mut out = Vec::with_capacity(SETTINGS.len());
    for (name, _) in SETTINGS {
        let mut value = BOOL::default();
        // SAFETY: plain COM getters writing one BOOL each.
        let result = unsafe {
            match name {
                "AreDevToolsEnabled" => settings.AreDevToolsEnabled(&mut value),
                "AreDefaultContextMenusEnabled" => {
                    settings.AreDefaultContextMenusEnabled(&mut value)
                }
                "AreBrowserAcceleratorKeysEnabled" => {
                    three.AreBrowserAcceleratorKeysEnabled(&mut value)
                }
                "IsStatusBarEnabled" => settings.IsStatusBarEnabled(&mut value),
                "IsGeneralAutofillEnabled" => four.IsGeneralAutofillEnabled(&mut value),
                "IsPasswordAutosaveEnabled" => four.IsPasswordAutosaveEnabled(&mut value),
                "AreHostObjectsAllowed" => settings.AreHostObjectsAllowed(&mut value),
                "IsBuiltInErrorPageEnabled" => settings.IsBuiltInErrorPageEnabled(&mut value),
                "IsWebMessageEnabled" => settings.IsWebMessageEnabled(&mut value),
                other => return Err(format!("no getter for {other}")),
            }
        };
        result.map_err(|error| format!("{name} could not be read: {error}"))?;
        out.push((name, value.as_bool()));
    }
    Ok(out)
}

/// Every way `read` differs from [`SETTINGS`]: a wrong value, a missing or
/// extra setting, or another order. Empty means the readback matches.
pub fn mismatches(read: &[(&str, bool)]) -> Vec<String> {
    let mut out = Vec::new();
    for (index, (name, wanted)) in SETTINGS.iter().enumerate() {
        match read.get(index) {
            Some((got_name, got)) if got_name == name && got == wanted => {}
            Some((got_name, got)) if got_name == name => {
                out.push(format!("{name} is {got}, expected {wanted}"));
            }
            Some((got_name, _)) => out.push(format!("{got_name} was read where {name} belongs")),
            None => out.push(format!("{name} was not read back")),
        }
    }
    for (name, _) in read.iter().skip(SETTINGS.len()) {
        out.push(format!("{name} is not an asserted setting"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_browser_arguments_are_exactly_the_recorded_string() {
        assert_eq!(
            BROWSER_ARGS,
            "--disable-features=msWebOOUI,msPdfOOUI,msSmartScreenProtection"
        );
    }

    #[test]
    fn every_setting_is_off_in_the_packet_order() {
        let names: Vec<&str> = SETTINGS.iter().map(|(name, _)| *name).collect();
        assert_eq!(
            names,
            [
                "AreDevToolsEnabled",
                "AreDefaultContextMenusEnabled",
                "AreBrowserAcceleratorKeysEnabled",
                "IsStatusBarEnabled",
                "IsGeneralAutofillEnabled",
                "IsPasswordAutosaveEnabled",
                "AreHostObjectsAllowed",
                "IsBuiltInErrorPageEnabled",
                "IsWebMessageEnabled",
            ]
        );
        assert!(SETTINGS.iter().all(|(_, value)| !value));
    }

    #[test]
    fn a_matching_readback_passes_and_each_mismatch_is_named() {
        let good: Vec<(&str, bool)> = SETTINGS.to_vec();
        assert!(mismatches(&good).is_empty());

        let mut flipped = good.clone();
        flipped[0].1 = true;
        assert_eq!(
            mismatches(&flipped),
            ["AreDevToolsEnabled is true, expected false"]
        );

        assert_eq!(
            mismatches(&good[..8]),
            ["IsWebMessageEnabled was not read back"]
        );

        let mut extra = good.clone();
        extra.push(("IsScriptEnabled", true));
        assert_eq!(
            mismatches(&extra),
            ["IsScriptEnabled is not an asserted setting"]
        );

        let mut swapped = good;
        swapped.swap(1, 2);
        assert_eq!(mismatches(&swapped).len(), 2);
    }
}
