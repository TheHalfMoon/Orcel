//! SG-000108 decision 7 (amended in slice 3b): the worker runtime pin.
//!
//! A `live-browser-dev` build compiles in the SHA-256 of `node.exe` and a
//! digest of the worker's whole runtime tree, and every launch verifies
//! both against the files about to run. The tree, not just `main.js`:
//! `main.js` imports the rest of `dist/` and `playwright-core`, so pinning
//! the entry point alone would pin nothing it loads.
//!
//! The runtime tree is `package.json`, every file under `dist/` except
//! tests, and every file under `node_modules/playwright-core/`.
//! - Each file is hashed through a handle opened without write or delete
//!   sharing, and those handles stay open for the worker's whole lifetime
//!   (Node loads modules lazily).
//! - Every directory from the drive root down to each held file (and to
//!   `node.exe`) is held too, without delete sharing, and none may be a
//!   link or other reparse point: no component of a pinned path can be
//!   renamed, removed or swapped for a junction while the worker runs.
//! - `node.exe`'s own folder must be one the current user cannot create
//!   files in (a standard Program Files install): Windows loads a DLL
//!   planted beside an executable before the system's.
//! - Files Node would find outside the tree (an optional require walking
//!   up to `C:\node_modules`, a `node_modules` created later inside
//!   `dist/`) are not pinned here: the worker's resolve guard
//!   (`resolve-guard.ts`, installed before anything else is imported)
//!   refuses every module outside the pinned runtime.
//!
//! What the pin is not: in a dev build the host and `orceld` binaries are
//! themselves files the user can write, so a same-user process that can
//! rewrite them is outside what it defends. It guarantees that local
//! configuration cannot point the worker at other code, and that the exact
//! pinned files run unmodified; SG-000106's signed payload replaces it.

use crate::error::{HostError, UnavailableReason};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// Domain separation for the tree digest.
const TREE_DOMAIN: &str = "orcel-worker-runtime-tree/2";

/// What a build pinned: `node.exe`'s SHA-256 and the runtime tree digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimePin {
    pub node_sha256: String,
    pub tree_sha256: String,
}

/// The runtime tree's files, relative to the worker root, sorted, with
/// `/` separators.
pub fn runtime_files(root: &Path) -> Result<Vec<String>, HostError> {
    let mut files = Vec::new();
    let package = root.join("package.json");
    if !plain_file(&package)? {
        return Err(unpinned());
    }
    files.push("package.json".to_owned());
    collect(root, "dist", &mut files, &|relative| {
        !relative.ends_with(".test.js")
    })?;
    collect(root, "node_modules/playwright-core", &mut files, &|_| true)?;
    files.sort();
    Ok(files)
}

fn unpinned() -> HostError {
    HostError::Unavailable(UnavailableReason::UnsupportedRuntime)
}

/// A regular file, not a link or any other reparse point.
fn plain_file(path: &Path) -> Result<bool, HostError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => Ok(metadata.is_file() && !reparse(&metadata)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(unpinned()),
    }
}

#[cfg(windows)]
fn reparse(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_type().is_symlink()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn reparse(metadata: &std::fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

/// Every regular file under `root/relative`; a link or reparse point
/// anywhere in it refuses the whole tree.
fn collect(
    root: &Path,
    relative: &str,
    files: &mut Vec<String>,
    keep: &dyn Fn(&str) -> bool,
) -> Result<(), HostError> {
    let dir = root.join(relative);
    let metadata = std::fs::symlink_metadata(&dir).map_err(|_| unpinned())?;
    if !metadata.is_dir() || reparse(&metadata) {
        return Err(unpinned());
    }
    let mut entries: Vec<_> = std::fs::read_dir(&dir)
        .map_err(|_| unpinned())?
        .collect::<Result<_, _>>()
        .map_err(|_| unpinned())?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let name = entry.file_name().into_string().map_err(|_| unpinned())?;
        // No control characters: names stay unambiguous in the digest.
        if name.chars().any(char::is_control) {
            return Err(unpinned());
        }
        let child = format!("{relative}/{name}");
        let metadata = std::fs::symlink_metadata(entry.path()).map_err(|_| unpinned())?;
        if reparse(&metadata) {
            return Err(unpinned());
        }
        if metadata.is_dir() {
            collect(root, &child, files, keep)?;
        } else if metadata.is_file() {
            if keep(&child) {
                files.push(child);
            }
        } else {
            return Err(unpinned());
        }
    }
    Ok(())
}

/// The tree digest over (relative path, file SHA-256) pairs, in order.
/// Each path is length-prefixed, so no two trees frame alike.
pub fn tree_digest(entries: &[(String, String)]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(TREE_DOMAIN.as_bytes());
    hasher.update(b"\n");
    for (path, sha256) in entries {
        hasher.update(format!("{}:{path}\n{sha256}\n", path.len()).as_bytes());
    }
    hex(&hasher.finalize())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The runtime's files, held open without write or delete sharing. Dropped
/// with the worker.
#[derive(Debug)]
pub struct HeldRuntime {
    _files: Vec<std::fs::File>,
}

impl HeldRuntime {
    /// How many files are held (node.exe and the tree).
    pub fn len(&self) -> usize {
        self._files.len()
    }

    pub fn is_empty(&self) -> bool {
        self._files.is_empty()
    }
}

/// Hold a directory: no rename or delete while it is held (children may
/// still be created; the resolve guard refuses any that would load). It
/// must not itself be a reparse point.
#[cfg(windows)]
fn hold_dir(path: &Path) -> Result<std::fs::File, HostError> {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_SHARE_READ_WRITE: u32 = 0x1 | 0x2;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    let dir = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|_| unpinned())?;
    let metadata = dir.metadata().map_err(|_| unpinned())?;
    if !metadata.is_dir() || reparse(&metadata) {
        return Err(unpinned());
    }
    Ok(dir)
}

/// Hold every directory from the drive root down to each of `paths`'
/// parents, top down, each checked through its held handle.
#[cfg(windows)]
fn hold_ancestors(paths: &[PathBuf]) -> Result<Vec<std::fs::File>, HostError> {
    let mut dirs = std::collections::BTreeSet::new();
    for path in paths {
        for ancestor in path.ancestors().skip(1) {
            if ancestor.as_os_str().is_empty() {
                continue;
            }
            dirs.insert(ancestor.to_path_buf());
        }
    }
    // Shorter paths first: a parent is held before its children are opened.
    let mut ordered: Vec<PathBuf> = dirs.into_iter().collect();
    ordered.sort_by_key(|dir| dir.components().count());
    ordered.iter().map(|dir| hold_dir(dir)).collect()
}

/// Whether the current user can create a file in `node.exe`'s folder. A
/// pinned launch refuses such a `node.exe`: a DLL planted beside it would
/// load before the system's.
#[cfg(windows)]
pub fn node_folder_writable(node: &Path) -> bool {
    let Some(folder) = node.parent() else {
        return true;
    };
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let probe = folder.join(format!(
        ".orcel-write-probe-{}-{nanos}",
        std::process::id()
    ));
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)
    {
        Ok(file) => {
            drop(file);
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(error) => error.kind() != std::io::ErrorKind::PermissionDenied,
    }
}

/// Open for reading, sharing only reads: no write, rename or delete while
/// it is held. Never follows a reparse point at the name.
#[cfg(windows)]
fn hold(path: &Path) -> Result<std::fs::File, HostError> {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_SHARE_READ: u32 = 0x1;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|_| unpinned())?;
    let metadata = file.metadata().map_err(|_| unpinned())?;
    if !metadata.is_file() || reparse(&metadata) {
        return Err(unpinned());
    }
    Ok(file)
}

#[cfg(windows)]
fn hash_held(file: &mut std::fs::File) -> Result<String, HostError> {
    use std::io::Read as _;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|_| unpinned())?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex(&hasher.finalize()))
}

/// The worker root of an entry point `<root>/dist/main.js`.
pub fn worker_root(worker_main: &Path) -> Result<PathBuf, HostError> {
    let dist = worker_main.parent().ok_or_else(unpinned)?;
    if worker_main.file_name().and_then(|name| name.to_str()) != Some("main.js")
        || dist.file_name().and_then(|name| name.to_str()) != Some("dist")
    {
        return Err(unpinned());
    }
    dist.parent().map(Path::to_path_buf).ok_or_else(unpinned)
}

/// Hold `node.exe` and the runtime tree, hash each through its held handle,
/// and measure (node SHA-256, tree digest).
#[cfg(windows)]
pub fn measure_and_hold(
    node: &Path,
    worker_main: &Path,
) -> Result<(RuntimePin, HeldRuntime), HostError> {
    let root = worker_root(worker_main)?;
    let files = runtime_files(&root)?;
    // Every directory on every pinned path, held before any file is read.
    let mut paths: Vec<PathBuf> = files.iter().map(|relative| root.join(relative)).collect();
    paths.push(node.to_path_buf());
    let mut held = hold_ancestors(&paths)?;
    let mut node_file = hold(node)?;
    let node_sha256 = hash_held(&mut node_file)?;
    held.push(node_file);
    let mut entries = Vec::new();
    for relative in files {
        let mut file = hold(&root.join(&relative))?;
        entries.push((relative, hash_held(&mut file)?));
        held.push(file);
    }
    Ok((
        RuntimePin {
            node_sha256,
            tree_sha256: tree_digest(&entries),
        },
        HeldRuntime { _files: held },
    ))
}

impl RuntimePin {
    /// Hold the runtime and require it to be exactly this pin. A changed
    /// node.exe or tree is refused, typed, until the build is redone; so is
    /// a `node.exe` in a folder the current user can write.
    #[cfg(windows)]
    pub fn verify_and_hold(
        &self,
        node: &Path,
        worker_main: &Path,
    ) -> Result<HeldRuntime, HostError> {
        if node_folder_writable(node) {
            return Err(unpinned());
        }
        self.verify_measured(node, worker_main)
    }

    /// The tree and hash check alone (unit tests use a `node.exe` stand-in
    /// in a writable temp folder).
    #[cfg(windows)]
    fn verify_measured(&self, node: &Path, worker_main: &Path) -> Result<HeldRuntime, HostError> {
        let (measured, held) = measure_and_hold(node, worker_main)?;
        if &measured != self {
            return Err(unpinned());
        }
        Ok(held)
    }
}

#[cfg(all(test, windows))]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn scratch(label: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let root = std::env::temp_dir().join(format!(
            "orcel-runtime-pin-{label}-{}-{nanos}",
            std::process::id()
        ));
        for dir in [
            "dist/extract",
            "node_modules/playwright-core/lib",
            "node_modules/typescript",
        ] {
            std::fs::create_dir_all(root.join(dir)).unwrap();
        }
        for (file, body) in [
            ("package.json", "{}"),
            ("dist/main.js", "import './worker.js';"),
            ("dist/worker.js", "export {};"),
            ("dist/worker.test.js", "test"),
            ("dist/extract/clean.js", "export {};"),
            ("node_modules/playwright-core/package.json", "{}"),
            ("node_modules/playwright-core/lib/index.js", "x"),
            ("node_modules/typescript/index.js", "not loaded"),
            ("node.exe", "MZ fake node"),
        ] {
            std::fs::write(root.join(file), body).unwrap();
        }
        root
    }

    #[test]
    fn the_tree_is_the_loadable_runtime_and_nothing_else() {
        let root = scratch("files");
        assert_eq!(
            runtime_files(&root).unwrap(),
            [
                "dist/extract/clean.js",
                "dist/main.js",
                "dist/worker.js",
                "node_modules/playwright-core/lib/index.js",
                "node_modules/playwright-core/package.json",
                "package.json",
            ]
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_matching_runtime_is_held_and_any_change_is_refused() {
        let root = scratch("verify");
        let node = root.join("node.exe");
        let main = root.join("dist/main.js");
        let (pin, held) = measure_and_hold(&node, &main).unwrap();
        // node.exe and six tree files, then every directory on their paths:
        // dist, dist/extract, node_modules, playwright-core, its lib, and the
        // root with each of its ancestors up to the drive root.
        let directories = 5 + root.ancestors().count();
        assert_eq!(held.len(), 7 + directories);
        // Held: no file of the runtime can be written, renamed or deleted.
        assert!(std::fs::write(&main, "changed").is_err());
        assert!(std::fs::remove_file(root.join("dist/worker.js")).is_err());
        assert!(std::fs::rename(&node, root.join("other.exe")).is_err());
        drop(held);
        let again = pin.verify_measured(&node, &main).unwrap();
        drop(again);
        // Any change to a pinned file, or a new loadable file, is refused.
        for (file, body) in [
            ("dist/worker.js", "export const changed = 1;"),
            ("node_modules/playwright-core/lib/added.js", "x"),
            ("node.exe", "MZ other node"),
        ] {
            let saved = std::fs::read(root.join(file)).ok();
            std::fs::write(root.join(file), body).unwrap();
            assert!(pin.verify_measured(&node, &main).is_err(), "{file}");
            match saved {
                Some(bytes) => std::fs::write(root.join(file), bytes).unwrap(),
                None => std::fs::remove_file(root.join(file)).unwrap(),
            }
        }
        // Tests and other packages are not part of the runtime.
        std::fs::write(root.join("dist/worker.test.js"), "changed").unwrap();
        std::fs::write(root.join("node_modules/typescript/index.js"), "changed").unwrap();
        assert!(pin.verify_measured(&node, &main).is_ok());
        std::fs::remove_dir_all(&root).unwrap();
    }

    // A junction inside the tree is refused: tested in worker_launch_tests.rs
    // (`runtime_pin_refuses_a_linked_tree`), the one place test processes
    // are spawned (SG-000085).

    #[test]
    fn a_node_in_a_writable_folder_is_refused() {
        let root = scratch("writable");
        let node = root.join("node.exe");
        let main = root.join("dist/main.js");
        assert!(node_folder_writable(&node));
        let (pin, held) = measure_and_hold(&node, &main).unwrap();
        drop(held);
        assert!(pin.verify_and_hold(&node, &main).is_err());
        assert!(pin.verify_measured(&node, &main).is_ok());
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn held_directories_cannot_be_renamed_or_removed() {
        let root = scratch("dirs");
        let node = root.join("node.exe");
        let main = root.join("dist/main.js");
        let (_, held) = measure_and_hold(&node, &main).unwrap();
        assert!(std::fs::rename(root.join("dist/extract"), root.join("dist/moved")).is_err());
        assert!(std::fs::rename(root.join("node_modules"), root.join("elsewhere")).is_err());
        drop(held);
        std::fs::rename(root.join("dist/extract"), root.join("dist/moved")).unwrap();
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn the_digest_frames_paths_and_hashes() {
        // The judge's collision: a name carrying a newline and a hash.
        assert_ne!(
            tree_digest(&[
                ("dist/x.js".into(), "h1".into()),
                ("dist/y.js".into(), "h2".into())
            ]),
            tree_digest(&[("dist/x.js\nh1\ndist/y.js".into(), "h2".into())])
        );
        let a = tree_digest(&[("a".into(), "1".into()), ("b".into(), "2".into())]);
        assert_ne!(
            a,
            tree_digest(&[("ab".into(), "1".into()), ("".into(), "2".into())])
        );
        assert_ne!(
            a,
            tree_digest(&[("b".into(), "2".into()), ("a".into(), "1".into())])
        );
        // Fixed vector, independently computed (Python sha256).
        assert_eq!(
            tree_digest(&[("package.json".into(), "00".into())]),
            FIXED_VECTOR
        );
    }

    const FIXED_VECTOR: &str = "6d3883c7d40e441a60db788a61be5882768e105b6b356b64960d16d7b5134535";
}
