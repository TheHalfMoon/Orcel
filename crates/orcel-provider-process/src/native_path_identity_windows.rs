//! SG-000096: Windows handle-pinned file and directory identity.
//!
//! A held handle denies share-write and share-delete, so the pinned file or
//! directory cannot be rewritten, renamed or deleted while it is held. Its
//! volume serial and file index come from the same handle, and an executable
//! is hashed through that handle. Every lexical component is checked for a
//! reparse point (symlink or junction) when the path is opened. This is
//! identity binding for a launch, not a sandbox.
use std::ffi::c_void;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};

const SHARE_READ: u32 = 1;
const OPEN_REPARSE: u32 = 0x0020_0000;
const BACKUP_SEMANTICS: u32 = 0x0200_0000;
const REPARSE_ATTRIBUTE: u32 = 0x400;
/// The largest executable SG-000096 hashes (it is read whole into memory).
pub(crate) const MAX_EXECUTABLE_BYTES: u64 = 128 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FileKey {
    pub(crate) volume: u32,
    pub(crate) index: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct NativeFileTime {
    low: u32,
    high: u32,
}

#[repr(C)]
#[derive(Default)]
struct NativeHandleInfo {
    attributes: u32,
    created: NativeFileTime,
    accessed: NativeFileTime,
    written: NativeFileTime,
    volume: u32,
    size_high: u32,
    size_low: u32,
    link_count: u32,
    index_high: u32,
    index_low: u32,
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetFileInformationByHandle(handle: *mut c_void, data: *mut NativeHandleInfo) -> i32;
}

pub(crate) fn key(file: &File) -> Result<FileKey, String> {
    let mut info = NativeHandleInfo::default();
    // SAFETY: `file` is an open handle owned by the caller and `info` is a
    // correctly sized, writable BY_HANDLE_FILE_INFORMATION.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
        return Err(format!(
            "native handle file ID query failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(FileKey {
        volume: info.volume,
        index: ((info.index_high as u64) << 32) | info.index_low as u64,
    })
}

fn checked_components(path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("target path must be absolute".into());
    }
    let mut prefix = PathBuf::new();
    for part in path.components() {
        prefix.push(part.as_os_str());
        if !prefix.is_absolute() {
            continue;
        }
        let md = fs::symlink_metadata(&prefix).map_err(|e| e.to_string())?;
        if md.file_attributes() & REPARSE_ATTRIBUTE != 0 {
            return Err("reparse or junction component is not authorized".into());
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    File,
    Directory,
}

pub(crate) struct HeldPath {
    pub(crate) path: PathBuf,
    #[cfg_attr(not(test), allow(dead_code))]
    kind: Kind,
    pub(crate) key: FileKey,
    pub(crate) sha: Option<[u8; 32]>,
    handle: File,
}

fn digest(file: &mut File) -> Result<[u8; 32], String> {
    file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
    let mut bytes = Vec::new();
    // One byte past the bound tells an oversized file from one at the bound.
    file.take(MAX_EXECUTABLE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > MAX_EXECUTABLE_BYTES {
        return Err("unbounded executable hash denied".into());
    }
    Ok(crate::contained::sha256(&bytes))
}

impl HeldPath {
    pub(crate) fn open(path: &Path, kind: Kind) -> Result<Self, String> {
        checked_components(path)?;
        let mut handle = OpenOptions::new()
            .read(true)
            .share_mode(SHARE_READ)
            .custom_flags(
                OPEN_REPARSE
                    | if kind == Kind::Directory {
                        BACKUP_SEMANTICS
                    } else {
                        0
                    },
            )
            .open(path)
            .map_err(|e| e.to_string())?;
        let md = handle.metadata().map_err(|e| e.to_string())?;
        if md.file_attributes() & REPARSE_ATTRIBUTE != 0
            || (kind == Kind::File && !md.is_file())
            || (kind == Kind::Directory && !md.is_dir())
        {
            return Err("wrong native target kind or reparse handle".into());
        }
        let native_key = key(&handle)?;
        let sha = if kind == Kind::File {
            Some(digest(&mut handle)?)
        } else {
            None
        };
        Ok(Self {
            path: path.to_path_buf(),
            kind,
            key: native_key,
            sha,
            handle,
        })
    }

    /// Whether the held handle still names the file it was opened on.
    pub(crate) fn held_key(&self) -> Result<FileKey, String> {
        key(&self.handle)
    }

    /// Test-only full recheck: held key, a fresh reopen and the digest.
    #[cfg(test)]
    pub(crate) fn verify(
        &mut self,
        path: &Path,
        expected: FileKey,
        hash: Option<[u8; 32]>,
    ) -> Result<(), String> {
        if path != self.path {
            return Err("lexical native path drift".into());
        }
        checked_components(path)?;
        let held = key(&self.handle)?;
        if held != self.key || held != expected {
            return Err("held native file ID drift".into());
        }
        let reopened = Self::open(path, self.kind)?;
        if reopened.key != self.key {
            return Err("path rebound to a different file".into());
        }
        if self.kind == Kind::File {
            let actual = digest(&mut self.handle)?;
            if Some(actual) != hash || Some(actual) != self.sha || reopened.sha != self.sha {
                return Err("executable hash mismatch".into());
            }
        } else if hash.is_some() {
            return Err("directory cannot have executable hash".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TemporaryRoot(PathBuf);
    impl Drop for TemporaryRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn temporary_root(label: &str) -> TemporaryRoot {
        let ticks = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "orcel-native-path-{label}-{}-{ticks}",
            std::process::id()
        ));
        fs::create_dir_all(&root).expect("create isolated test root");
        TemporaryRoot(root)
    }

    #[test]
    fn sg000096_windows_native_file_identity_and_digest_deny_drift() {
        let root = temporary_root("identity");
        let exe = root.0.join("disposable.bin");
        let cwd = root.0.join("cwd");
        fs::write(&exe, b"disposable fixture bytes a").expect("create synthetic binary");
        fs::create_dir(&cwd).expect("create cwd");

        let mut pinned = HeldPath::open(&exe, Kind::File).expect("open dummy file");
        let mut directory = HeldPath::open(&cwd, Kind::Directory).expect("open native directory");
        let native_key = pinned.key;
        let cwd_key = directory.key;
        let hash = pinned.sha.expect("hash is present");
        pinned
            .verify(&exe, native_key, Some(hash))
            .expect("matching file ID and bytes");
        directory
            .verify(&cwd, cwd_key, None)
            .expect("matching working directory ID");
        let mut wrong_hash = hash;
        wrong_hash[0] ^= 1;
        assert!(pinned.verify(&exe, native_key, Some(wrong_hash)).is_err());
        let wrong_key = FileKey {
            index: native_key.index ^ 1,
            ..native_key
        };
        assert!(pinned.verify(&exe, wrong_key, Some(hash)).is_err());
        assert!(pinned.verify(&cwd, native_key, Some(hash)).is_err());
        assert!(HeldPath::open(&exe, Kind::Directory).is_err());
        assert!(HeldPath::open(&cwd, Kind::File).is_err());
        assert!(HeldPath::open(Path::new("relative.bin"), Kind::File).is_err());
        assert!(directory.verify(&cwd, cwd_key, Some(hash)).is_err());
        drop(pinned);
        drop(directory);
        fs::write(&exe, b"disposable fixture bytes b").expect("mutate only after handle release");
        let mut changed = HeldPath::open(&exe, Kind::File).expect("reopen altered file");
        let changed_key = changed.key;
        assert!(changed.verify(&exe, changed_key, Some(hash)).is_err());
    }

    /// A held handle stops the pinned file and its ancestors from being
    /// rewritten, renamed or deleted, so the path cannot be rebound while
    /// a launch holds it.
    #[test]
    fn sg000096_held_paths_deny_rewrite_rename_and_ancestor_rename() {
        let root = temporary_root("hold");
        let parent = root.0.join("parent");
        let cwd = parent.join("cwd");
        fs::create_dir_all(&cwd).expect("create cwd");
        let exe = parent.join("tool.bin");
        fs::write(&exe, b"pinned bytes").expect("create file");

        let file = HeldPath::open(&exe, Kind::File).expect("pin file");
        let directory = HeldPath::open(&cwd, Kind::Directory).expect("pin directory");
        assert!(fs::write(&exe, b"replaced").is_err(), "rewrite while held");
        assert!(
            fs::rename(&exe, parent.join("moved.bin")).is_err(),
            "rename while held"
        );
        assert!(fs::remove_file(&exe).is_err(), "delete while held");
        assert!(
            fs::rename(&cwd, parent.join("cwd2")).is_err(),
            "directory rename while held"
        );
        assert!(
            fs::rename(&parent, root.0.join("parent2")).is_err(),
            "ancestor rename while a descendant is held"
        );
        drop(file);
        drop(directory);
        fs::rename(&parent, root.0.join("parent2")).expect("rename once released");
    }

    #[test]
    fn sg000096_junction_components_are_refused() {
        let root = temporary_root("junction");
        let real = root.0.join("real");
        fs::create_dir_all(&real).expect("real dir");
        fs::write(real.join("tool.bin"), b"bytes").expect("file");
        let link = root.0.join("link");
        let status = std::process::Command::new("cmd")
            .args(["/d", "/c", "mklink", "/J"])
            .arg(&link)
            .arg(&real)
            .output()
            .expect("run mklink");
        assert!(status.status.success(), "mklink /J needs no privilege");
        assert!(HeldPath::open(&link.join("tool.bin"), Kind::File).is_err());
        assert!(HeldPath::open(&link, Kind::Directory).is_err());
    }
}
