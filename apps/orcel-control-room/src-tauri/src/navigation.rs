//! Navigation is allowed only to the shell's two pages on the exact asset
//! origin.
//!
//! With `useHttpsScheme: true` the embedded page is served from
//! `https://tauri.localhost` on Windows. A navigation is allowed only if its
//! parsed scheme is `https`, its host is exactly `tauri.localhost`, its port
//! is the default one, it carries no user name or password, and its path is
//! exactly `/start.html` or `/index.html` with no query and no fragment. No
//! prefix or substring match is used, so `https://tauri.localhost.evil/`,
//! `http://tauri.localhost/`, `https://tauri.localhost:8443/`, userinfo
//! tricks, `https://ipc.localhost/`, every other path on the origin (an
//! asset such as `/style.css` opened as a page, say) and every `file:`,
//! `data:`, `blob:` and `javascript:` URL are refused.
//!
//! This governs top-level navigations only (WebView2's NavigationStarting).
//! The pages' own subresources (`style.css`, `js/**`) are fetched, not
//! navigated to, and stay loadable under the CSP.

use tauri::Url;

/// The asset origin's scheme.
pub const ASSET_SCHEME: &str = "https";
/// The asset origin's host (Windows, `useHttpsScheme: true`).
pub const ASSET_HOST: &str = "tauri.localhost";
/// The view: the page the shell navigates to once its settings are asserted
/// (the window first loads `start.html`, which runs no script).
pub const ASSET_PAGE: &str = "https://tauri.localhost/index.html";

/// The only paths a navigation may open: the script-free start page the
/// window is configured with, and the view the shell reloads into.
pub const ASSET_PATHS: [&str; 2] = ["/start.html", "/index.html"];

/// Whether `url` is one of the shell's two pages on the exact asset origin.
pub fn allowed(url: &Url) -> bool {
    url.scheme() == ASSET_SCHEME
        && url.host_str() == Some(ASSET_HOST)
        && url.port().is_none()
        && url.username().is_empty()
        && url.password().is_none()
        && ASSET_PATHS.contains(&url.path())
        && url.query().is_none()
        && url.fragment().is_none()
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
            "https://tauri.localhost/index.html",
            "https://tauri.localhost/start.html",
            "https://TAURI.localhost/index.html",
            "https://tauri.localhost:443/start.html",
            "https://tauri.localhost/./index.html",
            ASSET_PAGE,
        ] {
            assert!(allowed_text(url), "{url}");
        }
    }

    #[test]
    fn everything_else_is_refused() {
        for url in [
            "https://tauri.localhost/",
            "https://tauri.localhost",
            "https://tauri.localhost/style.css",
            "https://tauri.localhost/js/view/main.js",
            "https://tauri.localhost/index.htm",
            "https://tauri.localhost/index.html/",
            "https://tauri.localhost/INDEX.html",
            "https://tauri.localhost/x/index.html",
            "https://tauri.localhost//index.html",
            "https://tauri.localhost/index.html?x=1",
            "https://tauri.localhost/index.html?",
            "https://tauri.localhost/index.html#y",
            "https://tauri.localhost/start.html#",
            "https://tauri.localhost/index.html%00",
            "https://tauri.localhost/%69ndex.html",
            "https://tauri.localhost.evil/index.html",
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
