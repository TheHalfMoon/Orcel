//! The shell refuses to start when the environment could steer WebView2.
//!
//! WebView2 honours `WEBVIEW2_BROWSER_EXECUTABLE_FOLDER`,
//! `WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS`, `WEBVIEW2_USER_DATA_FOLDER`,
//! `WEBVIEW2_RELEASE_CHANNEL_PREFERENCE` and others of that prefix. Windows
//! compares environment names case-insensitively, so any name that starts
//! with `WEBVIEW2_` in any letter case stops startup, including names whose
//! letters only fold to that prefix (a dotless `ı` uppercases to `I`). The
//! same settings through policy registry keys are a recorded residual, as is
//! squatting the pipe (prep packet, "Environment overrides").

use std::ffi::{OsStr, OsString};

/// The prefix WebView2 reads its overrides under.
pub const PREFIX: &str = "WEBVIEW2_";

/// Whether `name` starts with [`PREFIX`] once each character is uppercased
/// (a character whose uppercase is more than one character is kept as is).
pub fn names_webview2(name: &OsStr) -> bool {
    let name = name.to_string_lossy();
    let mut folded = name.chars().map(|c| {
        let mut upper = c.to_uppercase();
        match (upper.next(), upper.next()) {
            (Some(single), None) => single,
            _ => c,
        }
    });
    PREFIX.chars().all(|wanted| folded.next() == Some(wanted))
}

/// The first variable in `vars` whose name [`names_webview2`].
pub fn webview2_override<I>(vars: I) -> Option<String>
where
    I: IntoIterator<Item = (OsString, OsString)>,
{
    vars.into_iter()
        .map(|(name, _)| name)
        .find(|name| names_webview2(name))
        .map(|name| name.to_string_lossy().into_owned())
}

/// This process's environment, checked: the name of an offending variable.
pub fn check() -> Result<(), String> {
    match webview2_override(std::env::vars_os()) {
        Some(name) => Err(name),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars(names: &[&str]) -> Vec<(OsString, OsString)> {
        names
            .iter()
            .map(|name| (OsString::from(name), OsString::from("x")))
            .collect()
    }

    #[test]
    fn every_letter_case_of_the_prefix_is_refused() {
        for name in [
            "WEBVIEW2_USER_DATA_FOLDER",
            "WebView2_User_Data_Folder",
            "webview2_additional_browser_arguments",
            "wEbViEw2_BROWSER_EXECUTABLE_FOLDER",
            "WEBVIEW2_RELEASE_CHANNEL_PREFERENCE",
            "WEBVIEW2_",
            "WEBVIEW2_ANYTHING_NEW",
            // U+0131 (dotless i) uppercases to I.
            "WEBV\u{131}EW2_USER_DATA_FOLDER",
        ] {
            assert_eq!(
                webview2_override(vars(&["PATH", name, "TEMP"])),
                Some(name.to_owned()),
                "{name}"
            );
        }
    }

    #[test]
    fn other_names_pass() {
        assert_eq!(
            webview2_override(vars(&[
                "PATH",
                "WEBVIEW2",
                "WEBVIEW_USER_DATA_FOLDER",
                "XWEBVIEW2_USER_DATA_FOLDER",
                "WEBVIEW3_USER_DATA_FOLDER",
                "ORCEL_WEBVIEW2_X",
            ])),
            None
        );
    }
}
