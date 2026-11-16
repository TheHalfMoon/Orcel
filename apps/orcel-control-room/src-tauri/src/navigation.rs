//! Navigation is allowed only to the exact asset origin.
//!
//! With `useHttpsScheme: true` the embedded page is served from
//! `https://tauri.localhost` on Windows. A navigation is allowed only if its
//! parsed scheme is `https`, its host is exactly `tauri.localhost`, its port
//! is the default one and it carries no user name or password. No prefix or
//! substring match is used, so `https://tauri.localhost.evil/`,
//! `http://tauri.localhost/`, `https://tauri.localhost:8443/`, userinfo
//! tricks, `https://ipc.localhost/` and every `file:`, `data:`, `blob:` and
//! `javascript:` URL are refused.

use tauri::Url;

/// The asset origin's scheme.
pub const ASSET_SCHEME: &str = "https";
/// The asset origin's host (Windows, `useHttpsScheme: true`).
pub const ASSET_HOST: &str = "tauri.localhost";
/// The page the shell loads, and reloads once its settings are asserted.
pub const ASSET_PAGE: &str = "https://tauri.localhost/index.html";

/// Whether `url` is on the exact asset origin.
pub fn allowed(url: &Url) -> bool {
    url.scheme() == ASSET_SCHEME
        && url.host_str() == Some(ASSET_HOST)
        && url.port().is_none()
        && url.username().is_empty()
        && url.password().is_none()
}

/// [`allowed`] for text: a URL that does not parse is refused.
pub fn allowed_text(text: &str) -> bool {
    Url::parse(text).is_ok_and(|url| allowed(&url))
}

/// A refused URL as one printable line: scheme, a marker for userinfo, host
/// and port, never the path, query or the userinfo itself, and only printable
/// ASCII (hosts are already punycode).
pub fn describe(url: &Url) -> String {
    let userinfo = if url.username().is_empty() && url.password().is_none() {
        ""
    } else {
        "<userinfo>@"
    };
    let host = url.host_str().unwrap_or("");
    let port = url
        .port()
        .map(|port| format!(":{port}"))
        .unwrap_or_default();
    format!("{}://{userinfo}{host}{port}", url.scheme())
        .chars()
        .map(|c| if c.is_ascii_graphic() { c } else { '?' })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_exact_asset_origin_is_allowed() {
        for url in [
            "https://tauri.localhost/",
            "https://tauri.localhost/index.html",
            "https://tauri.localhost/index.html?x=1#y",
            "https://TAURI.localhost/style.css",
            "https://tauri.localhost:443/",
            ASSET_PAGE,
        ] {
            assert!(allowed_text(url), "{url}");
        }
    }

    #[test]
    fn everything_else_is_refused() {
        for url in [
            "https://tauri.localhost.evil/",
            "https://tauri.localhost./",
            "https://evil.tauri.localhost/",
            "http://tauri.localhost/",
            "https://tauri.localhost:8443/",
            "https://tauri.localhost:80/",
            "https://user@tauri.localhost.evil/",
            "https://user@tauri.localhost/",
            "https://user:pass@tauri.localhost/",
            "https://:pass@tauri.localhost/",
            "https://tauri.localhost@evil.example/",
            "https://ipc.localhost/",
            "http://ipc.localhost/",
            "ipc://localhost/",
            "tauri://localhost/",
            "https:",
            "https://",
            "http://127.0.0.1/",
            "https://127.0.0.1/",
            "https://localhost/",
            "file:///C:/Windows/win.ini",
            "file://tauri.localhost/x",
            "data:text/html,<p>x</p>",
            "blob:https://tauri.localhost/0e7c5d2e-0000-4000-8000-000000000000",
            "javascript:alert(1)",
            "about:blank",
            "",
            "not a url",
        ] {
            assert!(!allowed_text(url), "{url}");
        }
    }

    #[test]
    fn a_refusal_is_described_without_path_or_userinfo() {
        let url = Url::parse("https://user:secret@tauri.localhost.evil:8443/a/b?c=d").unwrap();
        assert_eq!(
            describe(&url),
            "https://<userinfo>@tauri.localhost.evil:8443"
        );
        let url = Url::parse("file:///C:/Windows/win.ini").unwrap();
        assert_eq!(describe(&url), "file://");
    }
}
