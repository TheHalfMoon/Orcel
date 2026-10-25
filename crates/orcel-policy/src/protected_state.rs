//! SG-000041 protected Orcel state isolation.
//!
//! Orcel protected state (trust records, approval history, audit records, the
//! browser profile, and later installer configuration and secrets) lives under
//! the Orcel state root or under explicit environment overrides. A workspace
//! whose resolved root overlaps any of those locations would let workspace-scoped
//! providers reach protected state, so such workspaces are refused when the
//! policy engine is constructed.

use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};

/// Overrides that relocate protected state. They must stay identical to the
/// overrides honored by `orcel_audit::default_audit_path`,
/// `orceld` `trust::default_trust_path`,
/// `orcel_approval::default_approval_history_path`,
/// `orcel_provider_browser::default_profile_root`, and
/// `remote_session::default_lease_store_path`, and
/// `executable_registry::default_registry_path`, and
/// `orceld` `report_task::default_journal_path` and
/// `mutation_journal::default_path` (SG-000120).
pub const PROTECTED_STATE_OVERRIDES: &[&str] = &[
    "ORCEL_AUDIT_PATH",
    "ORCEL_TRUST_PATH",
    "ORCEL_APPROVAL_HISTORY_PATH",
    "ORCEL_BROWSER_STATE_DIR",
    "ORCEL_REMOTE_LEASE_PATH",
    "ORCEL_EXECUTABLE_REGISTRY_PATH",
    "ORCEL_REPORT_JOURNAL_PATH",
    "ORCEL_MUTATION_JOURNAL_PATH",
];

/// Returns the unresolved protected state roots derived from the process
/// environment.
pub fn protected_state_roots() -> Vec<PathBuf> {
    protected_state_roots_from(&|name| std::env::var_os(name))
}

/// Returns the unresolved protected state roots derived from `lookup`: the
/// XP-01 per-OS state root (`orcel_platform::paths`) and every configured
/// override.
///
/// Every default store (trust records, approval history, audit records, the
/// browser profile, the lease store, the executable registry and full-control
/// authority) resolves under the per-OS root since XP-01B, so the old
/// shared-temp `orcel` root is no longer listed: nothing defaults there, and
/// state left there by earlier builds is never read. On Windows the per-OS
/// root is `%LOCALAPPDATA%\Orcel`, the same root as before. When no per-OS
/// root can be established every default store fails closed, so only the
/// overrides remain to protect.
pub fn protected_state_roots_from(lookup: &dyn Fn(&str) -> Option<OsString>) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Ok(state_root) = orcel_platform::paths::state_root_from(lookup) {
        roots.push(state_root);
    }
    for name in PROTECTED_STATE_OVERRIDES {
        if let Some(value) = lookup(name) {
            roots.push(PathBuf::from(value));
        }
    }
    roots
}

/// Resolves a protected root to its final path: the nearest existing ancestor
/// is canonicalized and the remaining components are appended unchanged.
/// Empty paths and parent-directory components fail closed.
pub fn resolve_protected_root(path: &Path) -> Result<PathBuf, String> {
    if path.as_os_str().is_empty() {
        return Err("protected state location is empty".into());
    }
    // Verbatim (`\?\`) Windows paths parse `.` and `..` as normal components,
    // so they are rejected by name as well as by component kind.
    if path.components().any(|component| {
        matches!(component, Component::ParentDir | Component::CurDir)
            || component.as_os_str() == ".."
            || component.as_os_str() == "."
    }) {
        return Err("protected state location contains a relative-directory component".into());
    }
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| format!("resolve current directory: {error}"))?
            .join(path)
    };

    let mut existing = absolute.as_path();
    let mut suffix: Vec<OsString> = Vec::new();
    loop {
        if let Ok(resolved) = std::fs::canonicalize(existing) {
            let mut out = resolved;
            for part in suffix.iter().rev() {
                out.push(part);
            }
            return Ok(out);
        }
        let name = existing
            .file_name()
            .ok_or_else(|| "protected state location could not be resolved".to_string())?;
        suffix.push(name.to_os_string());
        existing = existing
            .parent()
            .ok_or_else(|| "protected state location could not be resolved".to_string())?;
    }
}

/// Returns true when `path` equals `base` or lies beneath it, comparing whole
/// components (case-insensitively on Windows) rather than string prefixes.
pub fn path_within(path: &Path, base: &Path) -> bool {
    let mut remaining = path.components();
    for base_component in base.components() {
        match remaining.next() {
            Some(component) if components_equal(component, base_component) => {}
            _ => return false,
        }
    }
    true
}

/// Returns true when either path equals or contains the other.
pub fn paths_overlap(first: &Path, second: &Path) -> bool {
    path_within(first, second) || path_within(second, first)
}

#[cfg(windows)]
fn components_equal(first: Component<'_>, second: Component<'_>) -> bool {
    first.as_os_str().to_string_lossy().to_lowercase()
        == second.as_os_str().to_string_lossy().to_lowercase()
}

#[cfg(not(windows))]
fn components_equal(first: Component<'_>, second: Component<'_>) -> bool {
    first == second
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static SEQUENCE: AtomicU64 = AtomicU64::new(0);

    fn temp_root(label: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "orcel-sg41-{label}-{}-{suffix}-{sequence}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).expect("create temp root");
        std::fs::canonicalize(root).expect("canonical temp root")
    }

    fn lookup(values: BTreeMap<&'static str, OsString>) -> impl Fn(&str) -> Option<OsString> {
        move |name| values.get(name).cloned()
    }

    /// A per-OS state root for the running OS's layout.
    fn state_root_values() -> BTreeMap<&'static str, OsString> {
        if cfg!(windows) {
            BTreeMap::from([("LOCALAPPDATA", OsString::from(r"C:\Users\u\AppData\Local"))])
        } else {
            BTreeMap::from([("HOME", OsString::from("/home/u"))])
        }
    }

    #[test]
    fn state_root_follows_the_per_os_root_and_every_override() {
        let mut values = state_root_values();
        let state_root =
            orcel_platform::paths::state_root_from(&lookup(values.clone())).expect("root");
        values.extend([
            ("ORCEL_AUDIT_PATH", OsString::from("/a/audit.jsonl")),
            ("ORCEL_TRUST_PATH", OsString::from("/t/trust.jsonl")),
            (
                "ORCEL_APPROVAL_HISTORY_PATH",
                OsString::from("/h/history.jsonl"),
            ),
            ("ORCEL_BROWSER_STATE_DIR", OsString::from("/b")),
            (
                "ORCEL_REPORT_JOURNAL_PATH",
                OsString::from("/j/report-tasks.jsonl"),
            ),
        ]);
        let roots = protected_state_roots_from(&lookup(values));
        assert_eq!(
            roots,
            vec![
                state_root,
                PathBuf::from("/a/audit.jsonl"),
                PathBuf::from("/t/trust.jsonl"),
                PathBuf::from("/h/history.jsonl"),
                PathBuf::from("/b"),
                PathBuf::from("/j/report-tasks.jsonl"),
            ]
        );
    }

    /// XP-01B: no default store resolves under the shared temp directory, so
    /// it is no longer a protected root, and without a per-OS root only the
    /// overrides remain.
    #[test]
    fn xp01b_temp_orcel_is_no_longer_a_protected_root() {
        let roots = protected_state_roots_from(&lookup(BTreeMap::new()));
        assert!(roots.is_empty(), "{roots:?}");
        let roots = protected_state_roots_from(&lookup(BTreeMap::from([(
            "ORCEL_TRUST_PATH",
            OsString::from("/t/trust.jsonl"),
        )])));
        assert_eq!(roots, vec![PathBuf::from("/t/trust.jsonl")]);
        let roots = protected_state_roots_from(&lookup(state_root_values()));
        let legacy = std::env::temp_dir().join("orcel");
        assert!(!roots.contains(&legacy), "{roots:?}");
    }

    #[cfg(windows)]
    #[test]
    fn xp01_windows_roots_are_unchanged() {
        let roots = protected_state_roots_from(&lookup(BTreeMap::from([
            ("LOCALAPPDATA", OsString::from(r"C:\Users\u\AppData\Local")),
            ("HOME", OsString::from(r"C:\Users\u")),
        ])));
        assert_eq!(
            roots,
            vec![PathBuf::from(r"C:\Users\u\AppData\Local").join("Orcel")]
        );
    }

    #[cfg(unix)]
    #[test]
    fn xp01_per_os_state_root_is_protected() {
        let values = BTreeMap::from([("HOME", OsString::from("/home/u"))]);
        let state_root =
            orcel_platform::paths::state_root_from(&lookup(values.clone())).expect("root");
        let roots = protected_state_roots_from(&lookup(values));
        assert_eq!(roots, vec![state_root]);
    }

    #[test]
    fn overlap_is_component_wise_not_string_prefix() {
        let base = PathBuf::from("/x/Orcel");
        assert!(paths_overlap(&base, &PathBuf::from("/x/Orcel/state")));
        assert!(paths_overlap(&base, &PathBuf::from("/x")));
        assert!(paths_overlap(&base, &PathBuf::from("/x/Orcel")));
        assert!(!paths_overlap(&base, &PathBuf::from("/x/Orcel-work")));
        assert!(!paths_overlap(&base, &PathBuf::from("/x/Cotr")));
        assert!(!paths_overlap(&base, &PathBuf::from("/y/Orcel")));
    }

    #[cfg(windows)]
    #[test]
    fn windows_overlap_is_case_insensitive() {
        assert!(paths_overlap(
            Path::new(r"C:\Users\u\AppData\Local\Orcel"),
            Path::new(r"c:\users\U\appdata\local\orcel\state")
        ));
        assert!(paths_overlap(
            Path::new(r"C:\Users\u\AppData\Local\Orcel"),
            Path::new(r"C:\USERS\U")
        ));
    }

    #[test]
    fn parent_components_and_empty_locations_fail_closed() {
        assert!(resolve_protected_root(Path::new("")).is_err());
        // Built from strings: `PathBuf::push` collapses `..` on verbatim paths.
        let sep = std::path::MAIN_SEPARATOR;
        let parent = PathBuf::from(format!(
            "{}{sep}a{sep}..{sep}b",
            std::env::temp_dir().display()
        ));
        assert!(resolve_protected_root(&parent).is_err());
        assert!(resolve_protected_root(Path::new("a/../b")).is_err());
        #[cfg(windows)]
        assert!(resolve_protected_root(Path::new(r"\\?\C:\x\..\y")).is_err());
        #[cfg(windows)]
        assert!(resolve_protected_root(Path::new(r"\\?\C:\x\.\y")).is_err());
    }

    #[test]
    fn missing_suffix_is_appended_to_canonical_existing_ancestor() {
        let root = temp_root("suffix");
        let resolved =
            resolve_protected_root(&root.join("missing").join("audit.jsonl")).expect("resolve");
        assert_eq!(resolved, root.join("missing").join("audit.jsonl"));
        let _ = std::fs::remove_dir_all(root);
    }
}
