//! Every store Orcel keeps under its per-user state root, in one place (#655).
//!
//! Resolvers build their paths from these entries, and uninstall and migration read their
//! rules from them, so a store can't be created somewhere uninstall doesn't know about.
//! `release_blocker_sweep::state_stores_*` checks that the code keeps to this.
//!
//! A top-level store also owns its siblings, by one naming rule (see [`Store::owns`]): its
//! `.lock` and `.rewrite`, an atomic write's `.<name>.tmp-*`, and the approval ledger's
//! `.quarantine-*` and `.recovering-*`.

use std::path::{Path, PathBuf};

/// What uninstall does with a store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// The person's data: kept by a plain uninstall, and reported; removed by a purge.
    UserData,
    /// Program files: removed by any uninstall, and reinstalled rather than migrated.
    Payload,
    /// Short-lived scratch or bookkeeping: reported and kept like user data, never migrated.
    Transient,
}

/// Whether migration from the earlier Windows root copies a store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Migrate {
    Copy,
    /// Left where it is. Live authority and identity: a copy would stay valid beside the
    /// original, and a revocation or rotation would reach only one.
    Leave,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    File,
    Dir,
    /// Folders named this prefix followed by a process id.
    NumberedDirs,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Store {
    /// The path under the state root, with `/` between components.
    pub relative: &'static str,
    pub kind: Kind,
    pub class: Class,
    pub migrate: Migrate,
}

const fn store(relative: &'static str, kind: Kind, class: Class, migrate: Migrate) -> Store {
    Store {
        relative,
        kind,
        class,
        migrate,
    }
}

use Class::{Payload, Transient, UserData};
use Kind::{Dir, File, NumberedDirs};

// Top level: user data.
pub const AUDIT: Store = store("audit.jsonl", File, UserData, Migrate::Copy);
pub const APPROVAL_HISTORY: Store = store("approval-history.jsonl", File, UserData, Migrate::Copy);
pub const TRUST: Store = store("trust.jsonl", File, UserData, Migrate::Copy);
pub const EXECUTABLE_REGISTRY: Store =
    store("executable_registry.json", File, UserData, Migrate::Copy);
pub const REMOTE_LEASES: Store = store("remote_leases.json", File, UserData, Migrate::Leave);
pub const REPORT_TASKS: Store = store("report-tasks.jsonl", File, UserData, Migrate::Copy);
pub const REPORT_TASKS_KEY: Store = store("report-tasks.key", File, UserData, Migrate::Copy);
pub const MUTATIONS: Store = store("mutations.jsonl", File, UserData, Migrate::Copy);
pub const BROWSER_PROFILE: Store = store("browser-profile", Dir, UserData, Migrate::Leave);
pub const STATE: Store = store("state", Dir, UserData, Migrate::Copy);
pub const SECRETS: Store = store("secrets", Dir, UserData, Migrate::Copy);
pub const LOGS: Store = store("logs", Dir, UserData, Migrate::Leave);

// Top level: program files.
pub const BIN: Store = store("bin", Dir, Payload, Migrate::Leave);
pub const VERSIONS: Store = store("versions", Dir, Payload, Migrate::Leave);
pub const CURRENT: Store = store("current.json", File, Payload, Migrate::Leave);
pub const INSTALL: Store = store("install.json", File, Payload, Migrate::Leave);
pub const RUN: Store = store("run", Dir, Payload, Migrate::Leave);

// Top level: transient.
pub const CONTAINED_RUNS: Store = store("contained-runs", Dir, Transient, Migrate::Leave);
pub const DOCUMENT_PARSE: Store = store("document-parse", Dir, Transient, Migrate::Leave);
/// Left by SG-000012's isolation test on a machine that runs it.
pub const QUALIFICATION: Store = store("sg-000012-qualification", Dir, Transient, Migrate::Leave);
/// One record per running client session, for display; each is deleted when its session ends.
pub const SESSIONS: Store = store("sessions", Dir, Transient, Migrate::Leave);
pub const MIGRATION_IN_PROGRESS: Store = store(
    "legacy-migration-in-progress",
    File,
    Transient,
    Migrate::Leave,
);
pub const MIGRATION_STAGING: Store =
    store("legacy-import-", NumberedDirs, Transient, Migrate::Leave);

// Nested, under `state` and `secrets`.
pub const CONFIG: Store = store("state/config.json", File, UserData, Migrate::Copy);
pub const TUNNEL_SECRETS: Store = store("state/secrets", Dir, UserData, Migrate::Copy);
pub const AUTHORITY: Store = store("state/authority", Dir, UserData, Migrate::Leave);
pub const SEARCH_USAGE: Store = store("state/search/usage.json", File, UserData, Migrate::Copy);
pub const DEVICE_KEY_RECORD: Store = store(
    "state/device/device_key.json",
    File,
    UserData,
    Migrate::Leave,
);
pub const DEVICE_REVOCATIONS: Store = store(
    "state/device/revocations.json",
    File,
    UserData,
    Migrate::Copy,
);
pub const UPLINK: Store = store("state/remote/uplink.json", File, UserData, Migrate::Leave);
/// Describes the installed payload, so it moves with that and not as data.
pub const UPDATE_MARKER: Store = store("state/update.json", File, Payload, Migrate::Leave);
pub const LEGACY_DECISION: Store = store(
    "state/legacy-state-decision.txt",
    File,
    UserData,
    Migrate::Leave,
);
pub const DEVICE_KEY: Store = store("secrets/device.key.dpapi", File, UserData, Migrate::Leave);

/// Every store, top level first.
pub const STORES: &[Store] = &[
    AUDIT,
    APPROVAL_HISTORY,
    TRUST,
    EXECUTABLE_REGISTRY,
    REMOTE_LEASES,
    REPORT_TASKS,
    REPORT_TASKS_KEY,
    MUTATIONS,
    BROWSER_PROFILE,
    STATE,
    SECRETS,
    LOGS,
    BIN,
    VERSIONS,
    CURRENT,
    INSTALL,
    RUN,
    CONTAINED_RUNS,
    DOCUMENT_PARSE,
    QUALIFICATION,
    SESSIONS,
    MIGRATION_IN_PROGRESS,
    MIGRATION_STAGING,
    CONFIG,
    TUNNEL_SECRETS,
    AUTHORITY,
    SEARCH_USAGE,
    DEVICE_KEY_RECORD,
    DEVICE_REVOCATIONS,
    UPLINK,
    UPDATE_MARKER,
    LEGACY_DECISION,
    DEVICE_KEY,
];

/// Suffixes a top-level file store's siblings carry.
const SIBLING_SUFFIXES: [&str; 4] = [".lock", ".rewrite", ".quarantine-", ".recovering-"];

impl Store {
    /// Its path under `root`.
    pub fn path(&self, root: &Path) -> PathBuf {
        self.relative
            .split('/')
            .fold(root.to_path_buf(), |path, part| path.join(part))
    }

    /// Folder `number` of a numbered store, such as one migration's staging folder.
    pub fn numbered(&self, root: &Path, number: u32) -> PathBuf {
        debug_assert_eq!(self.kind, Kind::NumberedDirs);
        root.join(format!("{}{number}", self.relative))
    }

    /// Whether it sits directly under the root.
    pub fn is_top_level(&self) -> bool {
        !self.relative.contains('/')
    }

    /// Whether the top-level entry `name` is this store or one of its siblings. Only Orcel's
    /// own shapes count, so a person's file with a similar name isn't taken for one.
    pub fn owns(&self, name: &str) -> bool {
        if !self.is_top_level() {
            return false;
        }
        match self.kind {
            Kind::NumberedDirs => name
                .strip_prefix(self.relative)
                .is_some_and(|id| !id.is_empty() && id.bytes().all(|byte| byte.is_ascii_digit())),
            Kind::Dir => name == self.relative,
            Kind::File => {
                name == self.relative
                    || name.strip_prefix(self.relative).is_some_and(|rest| {
                        SIBLING_SUFFIXES.iter().any(|suffix| {
                            rest == *suffix || (suffix.ends_with('-') && rest.starts_with(suffix))
                        })
                    })
                    || name
                        .strip_prefix('.')
                        .and_then(|rest| rest.strip_prefix(self.relative))
                        .is_some_and(|rest| rest.starts_with(".tmp-"))
            }
        }
    }
}

/// The top-level store that owns the entry `name` directly under the root, if any.
pub fn owner(name: &str) -> Option<&'static Store> {
    STORES.iter().find(|store| store.owns(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_store_has_one_unique_path_with_no_empty_part() {
        for (index, store) in STORES.iter().enumerate() {
            assert!(
                !store.relative.is_empty()
                    && store.relative.split('/').all(|part| !part.is_empty()),
                "{store:?}"
            );
            assert!(
                STORES[index + 1..]
                    .iter()
                    .all(|other| other.relative != store.relative),
                "{} is listed twice",
                store.relative
            );
        }
    }

    #[test]
    fn a_nested_store_lives_under_a_top_level_user_data_folder() {
        for store in STORES.iter().filter(|store| !store.is_top_level()) {
            let first = store.relative.split('/').next().unwrap();
            let parent = owner(first).expect(store.relative);
            assert_eq!(parent.kind, Kind::Dir, "{}", store.relative);
            assert_eq!(parent.class, Class::UserData, "{}", store.relative);
        }
    }

    #[test]
    fn siblings_belong_to_their_store_and_lookalikes_dont() {
        for name in [
            "approval-history.jsonl",
            "approval-history.jsonl.lock",
            "approval-history.jsonl.quarantine-1-abc",
            "approval-history.jsonl.recovering-1",
            "report-tasks.jsonl.rewrite",
            ".remote_leases.json.tmp-1-2",
            ".report-tasks.key.tmp-0f",
            "legacy-import-42",
            "state",
        ] {
            assert!(owner(name).is_some(), "{name}");
        }
        for name in [
            "approval-history.jsonl.bak",
            "approval-history.jsonl.lockfile",
            "trust.jsonl2",
            "legacy-import-",
            "legacy-import-my-notes.txt",
            "legacy-importer",
            "statefile",
            "notes.txt",
            ".trust.jsonl.tmp",
        ] {
            assert!(owner(name).is_none(), "{name}");
        }
    }

    #[test]
    fn a_path_follows_its_parts() {
        let root = Path::new("root");
        assert_eq!(AUTHORITY.path(root), root.join("state").join("authority"));
        assert_eq!(AUDIT.path(root), root.join("audit.jsonl"));
    }

    #[test]
    fn names_derived_from_another_store_match_the_registry() {
        // report_task keeps its fingerprint key beside the journal.
        assert_eq!(
            Path::new(REPORT_TASKS.relative).with_extension("key"),
            Path::new(REPORT_TASKS_KEY.relative)
        );
        let staging = MIGRATION_STAGING.numbered(Path::new("r"), 7);
        assert_eq!(staging, Path::new("r").join("legacy-import-7"));
        assert!(MIGRATION_STAGING.owns("legacy-import-7"));
    }
}
