//! XP-01B owner-only state files.
//!
//! Authority keys, trust records, lease stores and the executable registry
//! are written readable by their owner only (mode 0600 on Unix). On Windows
//! the files inherit the protected owner-only DACL of their directory
//! (`paths::ensure_private_dir`).
//!
//! An atomic replace writes a sibling temp file first. Its name carries a
//! random suffix and it is created with `create_new`, so a pre-created or
//! symlinked temp name is never opened, followed or reused.

use std::collections::hash_map::RandomState;
use std::fs::{File, OpenOptions};
use std::hash::{BuildHasher, Hasher};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Attempts before giving up when random temp names keep colliding.
const TEMP_ATTEMPTS: u32 = 16;

static SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Replaces `path` with `bytes` through a fresh owner-only temp file in the
/// same directory and a rename. The parent directory must already exist.
pub fn write_private_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let (temp, mut file) = create_private_temp(path)?;
    let synced = file.write_all(bytes).and_then(|()| file.sync_all());
    drop(file);
    let written = synced.and_then(|()| std::fs::rename(&temp, path));
    if written.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    written
}

/// Writes `bytes` to `path` only when nothing is there yet (#358 item 4):
/// the bytes go to a fresh owner-only temp file, which is then hard-linked
/// to `path`. The link fails with [`io::ErrorKind::AlreadyExists`] when
/// another writer got there first, so a concurrent creator never overwrites
/// it, and a reader never sees a partly written file.
pub fn write_private_new(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let (temp, mut file) = create_private_temp(path)?;
    let synced = file.write_all(bytes).and_then(|()| file.sync_all());
    drop(file);
    let linked = synced.and_then(|()| std::fs::hard_link(&temp, path));
    let _ = std::fs::remove_file(&temp);
    linked
}

/// Moves `from` to `to` in the same directory, never replacing what is at
/// `to`: an existing file, directory or symbolic link (dangling or not) is
/// left as it is and the move fails with [`io::ErrorKind::AlreadyExists`],
/// with `from` untouched. One step in the kernel (`renameat2` with
/// `RENAME_NOREPLACE`, `renamex_np` with `RENAME_EXCL`, `MoveFileExW`
/// without replace), so a crash leaves the file at exactly one of the names.
///
/// A filesystem without that step (and any other Unix) gets a hard link at
/// `to` and then loses `from`. An error there takes the link away again where
/// the directory allows it (an append-only one does not, and the link stays);
/// that error, or a crash in between, leaves the same file at both names,
/// never at neither. A filesystem without hard links either fails closed.
pub fn rename_no_replace(from: &Path, to: &Path) -> io::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        match exclusive_rename(from, to) {
            Err(error) if exclusive_rename_unsupported(&error) => link_then_unlink(from, to),
            done => done,
        }
    }
    #[cfg(windows)]
    {
        exclusive_rename(from, to)
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        link_then_unlink(from, to)
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn exclusive_rename(from: &Path, to: &Path) -> io::Result<()> {
    use std::os::unix::ffi::OsStrExt as _;
    let c_path = |path: &Path| {
        std::ffi::CString::new(path.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path holds a NUL byte"))
    };
    let (from, to) = (c_path(from)?, c_path(to)?);
    // The system call itself: `renameat2` is in glibc only since 2.28.
    // SAFETY: both paths are NUL-terminated and outlive the call, and the
    // arguments have the types the call takes.
    #[cfg(target_os = "linux")]
    let status = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            from.as_ptr(),
            libc::AT_FDCWD,
            to.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    // SAFETY: as above.
    #[cfg(target_os = "macos")]
    let status = unsafe { libc::renamex_np(from.as_ptr(), to.as_ptr(), libc::RENAME_EXCL) };
    if status == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Whether the kernel, a system call filter (`EPERM`) or the filesystem has
/// no exclusive rename. The two-step move never replaces either, so a wrong
/// guess costs at most a spare name (see [`rename_no_replace`]).
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn exclusive_rename_unsupported(error: &io::Error) -> bool {
    [libc::ENOSYS, libc::EINVAL, libc::ENOTSUP, libc::EPERM]
        .iter()
        .any(|code| error.raw_os_error() == Some(*code))
}

/// `MoveFileExW` without `MOVEFILE_REPLACE_EXISTING` or
/// `MOVEFILE_COPY_ALLOWED`: one rename, or an error.
#[cfg(windows)]
fn exclusive_rename(from: &Path, to: &Path) -> io::Result<()> {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::WIN32_ERROR;
    use windows::Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_WRITE_THROUGH};
    let (from, to) = (verbatim(from)?, verbatim(to)?);
    // SAFETY: both paths are NUL-terminated and outlive the call.
    unsafe {
        MoveFileExW(
            PCWSTR(from.as_ptr()),
            PCWSTR(to.as_ptr()),
            MOVEFILE_WRITE_THROUGH,
        )
    }
    // The windows crate's own conversion loses the error's kind.
    .map_err(|error| match WIN32_ERROR::from_error(&error) {
        Some(code) => io::Error::from_raw_os_error(code.0 as i32),
        None => error.into(),
    })
}

/// `path` as an absolute, NUL-terminated `\\?\` path, so a long one works as
/// it does through `std::fs`.
#[cfg(windows)]
fn verbatim(path: &Path) -> io::Result<Vec<u16>> {
    std::path::absolute(path).map(|path| verbatim_of(&path))
}

#[cfg(windows)]
fn verbatim_of(path: &Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt as _;
    use std::path::{Component, Prefix};
    let (prefix, skip) = match path.components().next() {
        Some(Component::Prefix(prefix)) => match prefix.kind() {
            Prefix::Disk(_) => (r"\\?\", 0),
            Prefix::UNC(..) => (r"\\?\UNC\", 2),
            _ => ("", 0),
        },
        _ => ("", 0),
    };
    prefix
        .encode_utf16()
        .chain(path.as_os_str().encode_wide().skip(skip))
        .chain(std::iter::once(0))
        .collect()
}

/// The two-step move: `to` is created exclusively as a second name of the
/// file, made durable, and only then does `from` go.
#[cfg(any(test, not(windows)))]
fn link_then_unlink(from: &Path, to: &Path) -> io::Result<()> {
    link_then_unlink_with(from, to, sync_parent_dir, |from| std::fs::remove_file(from))
}

#[cfg(any(test, not(windows)))]
fn link_then_unlink_with(
    from: &Path,
    to: &Path,
    sync: impl FnOnce(&Path) -> io::Result<()>,
    unlink: impl FnOnce(&Path) -> io::Result<()>,
) -> io::Result<()> {
    std::fs::hard_link(from, to)?;
    sync(to)
        .and_then(|()| unlink(from))
        .inspect_err(|_| remove_spare_name(from, to))
}

/// Takes away `to`, the second name this process gave the file at `from`,
/// unless `from` is that file no longer: then `to` may be its only name. A
/// process that writes to the directory without taking the caller's lock can
/// still remove `from` in between, as it could remove the file itself.
#[cfg(any(test, not(windows)))]
fn remove_spare_name(from: &Path, to: &Path) {
    let (Ok(from), Ok(named)) = (
        std::fs::symlink_metadata(from),
        std::fs::symlink_metadata(to),
    ) else {
        return;
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if (from.dev(), from.ino()) != (named.dev(), named.ino()) {
            return;
        }
    }
    #[cfg(not(unix))]
    let _ = (from, named);
    let _ = std::fs::remove_file(to);
}

/// Makes the names in `path`'s directory durable, where the filesystem can.
#[cfg(any(test, not(windows)))]
fn sync_parent_dir(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        directory_synced(File::open(parent)?.sync_all())
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

/// A filesystem that cannot sync a directory says so with `EINVAL`,
/// `ENOTSUP` or (macOS, where the sync is `F_FULLFSYNC`) `ENOTTY`; any other
/// error is one.
#[cfg(unix)]
fn directory_synced(synced: io::Result<()>) -> io::Result<()> {
    match synced {
        Err(error)
            if matches!(
                error.raw_os_error(),
                Some(libc::EINVAL | libc::ENOTSUP | libc::ENOTTY)
            ) =>
        {
            Ok(())
        }
        synced => synced,
    }
}

/// Creates one new directory that only its owner can enter (#417): mode 0700
/// from the first instant on Unix, and a protected DACL naming only the user,
/// `SYSTEM` and Administrators on Windows (not whatever `%TEMP%` grants). It
/// fails with [`io::ErrorKind::AlreadyExists`] when `path` exists; the parent
/// must already exist.
pub fn create_private_dir_new(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        std::fs::DirBuilder::new().mode(0o700).create(path)
    }
    #[cfg(windows)]
    {
        let user = crate::acl::current_user_sid()
            .map_err(|reason| io::Error::new(io::ErrorKind::PermissionDenied, reason))?;
        crate::acl::create_private_dir(path, &user)
    }
    #[cfg(not(any(unix, windows)))]
    {
        std::fs::DirBuilder::new().create(path)
    }
}

/// Opens `path` for appending, creating it owner-only when it is missing.
///
/// An existing file is held to the same rule (#358 item 3). On Unix it must
/// be a regular file (a symbolic link is not followed) owned by the
/// effective uid, and any group or other permission is removed through the
/// open descriptor. On Windows its DACL must admit nobody but the user,
/// `SYSTEM` and Administrators. Anything else is refused with
/// [`io::ErrorKind::PermissionDenied`].
pub fn open_private_append(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    owner_only(&mut options);
    let file = options.open(path)?;
    tighten_existing(path, &file)?;
    Ok(file)
}

#[cfg(unix)]
fn tighten_existing(path: &Path, file: &File) -> io::Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(refused(path, "is not a regular file"));
    }
    if Some(metadata.uid()) != crate::session::effective_uid() {
        return Err(refused(path, "is owned by another user"));
    }
    if metadata.mode() & 0o077 != 0 {
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[cfg(windows)]
fn tighten_existing(path: &Path, _file: &File) -> io::Result<()> {
    let user = crate::acl::current_user_sid().map_err(|reason| refused(path, &reason))?;
    let (owner, dacl) = crate::acl::security_of(path).map_err(|reason| refused(path, &reason))?;
    crate::acl::judge(&owner, dacl.as_deref(), &user, crate::acl::Role::PrivateDir)
        .map_err(|reason| refused(path, &reason))
}

#[cfg(not(any(unix, windows)))]
fn tighten_existing(path: &Path, _file: &File) -> io::Result<()> {
    Err(refused(path, "cannot be checked on this platform"))
}

fn refused(path: &Path, reason: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!("state file {} {reason}", path.display()),
    )
}

fn create_private_temp(path: &Path) -> io::Result<(PathBuf, File)> {
    let name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "state file path has no file name",
        )
    })?;
    for _ in 0..TEMP_ATTEMPTS {
        let temp = path.with_file_name(format!(
            ".{}.tmp-{:016x}",
            name.to_string_lossy(),
            random_suffix()
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        owner_only(&mut options);
        match options.open(&temp) {
            Ok(file) => return Ok((temp, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not create a unique state temp file",
    ))
}

/// 128 bits in hex that tell one call's result from any other's, in this
/// process or another: for names and records that must differ even when made
/// in the same millisecond. Never a key or a secret. It cannot fail.
pub fn unique_token() -> String {
    format!("{:016x}{:016x}", random_suffix(), random_suffix())
}

/// A suffix nobody can predict: `RandomState` is seeded from the OS once per
/// process, mixed with the time, the pid and a per-process counter.
fn random_suffix() -> u64 {
    let mut hasher = RandomState::new().build_hasher();
    hasher.write_u64(SEQUENCE.fetch_add(1, Ordering::Relaxed));
    hasher.write_u32(std::process::id());
    if let Ok(elapsed) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        hasher.write_u128(elapsed.as_nanos());
    }
    hasher.finish()
}

/// Mode 0600 when created, and never through a final symbolic link.
#[cfg(unix)]
fn owner_only(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
}

#[cfg(not(unix))]
fn owner_only(_options: &mut OpenOptions) {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    /// #417: a new private directory is exclusive and owner-only: mode 0700 on
    /// Unix, a DACL the private-directory rule accepts on Windows.
    #[test]
    fn a_new_private_directory_is_exclusive_and_owner_only() {
        let parent = sandbox("private-dir");
        std::fs::create_dir_all(&parent).unwrap();
        let dir = parent.join("d");
        create_private_dir_new(&dir).unwrap();
        assert_eq!(
            create_private_dir_new(&dir).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        #[cfg(windows)]
        {
            let user = crate::acl::current_user_sid().unwrap();
            let (owner, dacl) = crate::acl::security_of(&dir).unwrap();
            crate::acl::judge(&owner, dacl.as_deref(), &user, crate::acl::Role::PrivateDir)
                .expect("the DACL admits only the user, SYSTEM and Administrators");
        }
        let _ = std::fs::remove_dir_all(&parent);
    }

    fn sandbox(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!(
            "orcel-platform-files-{label}-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("sandbox");
        dir
    }

    #[test]
    fn atomic_write_replaces_and_leaves_no_temp_file() {
        let dir = sandbox("atomic");
        let path = dir.join("state.json");
        write_private_atomic(&path, b"one").expect("first");
        write_private_atomic(&path, b"two").expect("second");
        assert_eq!(std::fs::read(&path).expect("read"), b"two");
        let names: Vec<_> = std::fs::read_dir(&dir)
            .expect("dir")
            .map(|entry| entry.expect("entry").file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from("state.json")]);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn temp_suffixes_differ_between_calls() {
        assert_ne!(random_suffix(), random_suffix());
    }

    #[test]
    fn unique_tokens_differ_between_calls() {
        let tokens: std::collections::HashSet<_> = (0..1000).map(|_| unique_token()).collect();
        assert_eq!(tokens.len(), 1000);
        assert!(tokens.iter().all(|token| token.len() == 32));
    }

    type Move = fn(&Path, &Path) -> io::Result<()>;

    /// Both ways to move a file aside: the one this platform uses, and the
    /// two-step one a filesystem without an exclusive rename gets.
    const MOVES: [Move; 2] = [rename_no_replace, link_then_unlink];

    #[test]
    fn a_move_without_replace_moves_the_file() {
        for (index, rename) in MOVES.iter().enumerate() {
            let dir = sandbox(&format!("move-{index}"));
            let (from, to) = (dir.join("from"), dir.join("to"));
            std::fs::write(&from, b"one").expect("from");
            rename(&from, &to).expect("move");
            assert!(!from.exists(), "move {index}");
            assert_eq!(std::fs::read(&to).expect("to"), b"one");
            assert_eq!(
                rename(&from, &dir.join("other")).expect_err("gone").kind(),
                io::ErrorKind::NotFound
            );
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    #[test]
    fn a_move_without_replace_never_replaces_a_file_or_a_directory() {
        for (index, rename) in MOVES.iter().enumerate() {
            let dir = sandbox(&format!("taken-{index}"));
            let (from, to) = (dir.join("from"), dir.join("to"));
            std::fs::write(&from, b"new").expect("from");
            std::fs::write(&to, b"kept").expect("to");
            std::fs::create_dir(dir.join("folder")).expect("folder");
            for target in [to.clone(), dir.join("folder")] {
                let error = rename(&from, &target).expect_err("taken");
                assert_eq!(error.kind(), io::ErrorKind::AlreadyExists, "move {index}");
            }
            assert_eq!(std::fs::read(&to).expect("to"), b"kept");
            assert_eq!(std::fs::read(&from).expect("from"), b"new");
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    /// A link at the target, whether it leads anywhere or not, is neither
    /// replaced nor followed.
    #[cfg(unix)]
    #[test]
    fn a_move_without_replace_never_replaces_or_follows_a_symlink() {
        for (index, rename) in MOVES.iter().enumerate() {
            let dir = sandbox(&format!("move-link-{index}"));
            let (from, victim) = (dir.join("from"), dir.join("victim"));
            std::fs::write(&from, b"new").expect("from");
            std::fs::write(&victim, b"keep").expect("victim");
            for leads_to in [victim.clone(), dir.join("nowhere")] {
                let to = dir.join(format!("to-{}", leads_to.exists()));
                std::os::unix::fs::symlink(&leads_to, &to).expect("link");
                let error = rename(&from, &to).expect_err("taken");
                assert_eq!(error.kind(), io::ErrorKind::AlreadyExists, "move {index}");
                assert_eq!(std::fs::read_link(&to).expect("link kept"), leads_to);
            }
            assert_eq!(std::fs::read(&victim).expect("victim"), b"keep");
            assert_eq!(std::fs::read(&from).expect("from"), b"new");
            assert!(!dir.join("nowhere").exists());
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    /// An error after the link was made takes the link away again: nothing
    /// has moved, and the same name can be tried again.
    #[test]
    fn a_failed_two_step_move_moves_nothing() {
        fn failed() -> io::Result<()> {
            Err(io::Error::other("injected"))
        }
        let moves: [Move; 2] = [
            |from, to| {
                link_then_unlink_with(
                    from,
                    to,
                    |_| failed(),
                    |_| Err(io::Error::other("unlinked before the sync")),
                )
            },
            |from, to| link_then_unlink_with(from, to, |_| Ok(()), |_| failed()),
        ];
        for (index, rename) in moves.iter().enumerate() {
            let dir = sandbox(&format!("move-failed-{index}"));
            let (from, to) = (dir.join("from"), dir.join("to"));
            std::fs::write(&from, b"one").expect("from");
            let error = rename(&from, &to).expect_err("injected");
            assert_eq!(error.to_string(), "injected", "move {index}");
            assert!(std::fs::symlink_metadata(&to).is_err(), "move {index}");
            assert_eq!(std::fs::read(&from).expect("from"), b"one");
            link_then_unlink(&from, &to).expect("the next try");
            assert_eq!(std::fs::read(&to).expect("to"), b"one");
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    /// When the old name is gone although taking it away failed, the new
    /// name is the file's only one and stays.
    #[test]
    fn a_failed_two_step_move_never_removes_the_only_name() {
        let dir = sandbox("move-only-name");
        let (from, to) = (dir.join("from"), dir.join("to"));
        std::fs::write(&from, b"one").expect("from");
        let gone = |from: &Path| {
            std::fs::remove_file(from).expect("gone");
            Err(io::Error::other("injected"))
        };
        assert!(link_then_unlink_with(&from, &to, |_| Ok(()), gone).is_err());
        assert_eq!(std::fs::read(&to).expect("to"), b"one");
        #[cfg(unix)]
        {
            // Another file at the old name does not make the new one spare.
            let to = dir.join("to-2");
            std::fs::write(&from, b"two").expect("from");
            let replaced = |from: &Path| {
                std::fs::write(dir.join("other"), b"other").expect("other");
                std::fs::rename(dir.join("other"), from).expect("replaced");
                Err(io::Error::other("injected"))
            };
            assert!(link_then_unlink_with(&from, &to, |_| Ok(()), replaced).is_err());
            assert_eq!(std::fs::read(&to).expect("to"), b"two");
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Only a directory that cannot be synced at all is let off.
    #[cfg(unix)]
    #[test]
    fn a_directory_sync_error_is_an_error_unless_syncing_is_unsupported() {
        let synced = |code| directory_synced(Err(io::Error::from_raw_os_error(code)));
        for code in [libc::EINVAL, libc::ENOTSUP, libc::ENOTTY] {
            assert!(synced(code).is_ok(), "{code}");
        }
        for code in [libc::EIO, libc::ENOSPC, libc::EACCES, libc::EPERM] {
            assert_eq!(synced(code).expect_err("error").raw_os_error(), Some(code));
        }
        assert!(directory_synced(Ok(())).is_ok());
        let dir = sandbox("sync-dir");
        sync_parent_dir(&dir.join("name")).expect("a directory is synced");
        assert!(sync_parent_dir(&dir.join("missing").join("name")).is_err());
        sync_parent_dir(Path::new("name")).expect("the current directory is synced");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// The paths the Windows move passes to the system.
    #[cfg(windows)]
    #[test]
    fn verbatim_paths_have_the_form_windows_takes() {
        for (path, wide) in [
            (r"C:\dir\file", r"\\?\C:\dir\file"),
            (r"\\server\share\dir\file", r"\\?\UNC\server\share\dir\file"),
            (r"\\?\C:\dir\file", r"\\?\C:\dir\file"),
            (r"\\?\UNC\server\share\f", r"\\?\UNC\server\share\f"),
            (r"\\.\pipe\name", r"\\.\pipe\name"),
        ] {
            let expected: Vec<u16> = wide.encode_utf16().chain(std::iter::once(0)).collect();
            assert_eq!(verbatim_of(Path::new(path)), expected, "{path}");
        }
    }

    /// Only an absent exclusive rename leads to the two-step move; a taken
    /// name or any other failure does not.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn only_an_unsupported_exclusive_rename_falls_back() {
        for code in [libc::ENOSYS, libc::EINVAL, libc::ENOTSUP, libc::EPERM] {
            assert!(exclusive_rename_unsupported(&io::Error::from_raw_os_error(
                code
            )));
        }
        for code in [libc::EEXIST, libc::ENOENT, libc::EACCES, libc::ENOSPC] {
            assert!(!exclusive_rename_unsupported(
                &io::Error::from_raw_os_error(code)
            ));
        }
    }

    /// A name longer than MAX_PATH moves, as it does through `std::fs`.
    #[cfg(windows)]
    #[test]
    fn a_move_without_replace_takes_a_long_path() {
        let dir = sandbox("move-long");
        let mut deep = dir.clone();
        while deep.as_os_str().len() < 300 {
            deep.push("d".repeat(50));
        }
        std::fs::create_dir_all(&deep).expect("deep");
        std::fs::write(deep.join("from"), b"one").expect("from");
        rename_no_replace(&deep.join("from"), &deep.join("to")).expect("move");
        assert_eq!(std::fs::read(deep.join("to")).expect("to"), b"one");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn append_creates_and_extends() {
        let dir = sandbox("append");
        let path = dir.join("trust.jsonl");
        open_private_append(&path)
            .and_then(|mut file| file.write_all(b"a\n"))
            .expect("first");
        open_private_append(&path)
            .and_then(|mut file| file.write_all(b"b\n"))
            .expect("second");
        assert_eq!(std::fs::read(&path).expect("read"), b"a\nb\n");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn files_are_owner_only_whatever_the_umask() {
        use std::os::unix::fs::PermissionsExt;
        let dir = sandbox("mode");
        let atomic = dir.join("leases.json");
        write_private_atomic(&atomic, b"{}").expect("atomic");
        let appended = dir.join("trust.jsonl");
        open_private_append(&appended).expect("append");
        for path in [atomic, appended] {
            let mode = std::fs::metadata(&path).expect("meta").permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "{}", path.display());
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn write_new_never_replaces_an_existing_file() {
        let dir = sandbox("new");
        let path = dir.join("authority.key");
        write_private_new(&path, b"first").expect("first");
        let error = write_private_new(&path, b"second").expect_err("second");
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&path).expect("read"), b"first");
        let names: Vec<_> = std::fs::read_dir(&dir)
            .expect("dir")
            .map(|entry| entry.expect("entry").file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from("authority.key")]);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// #358 item 4: of many concurrent creators exactly one wins, every
    /// other one is told the file exists, and the file holds the winner's
    /// bytes in full.
    #[test]
    fn concurrent_creators_never_overwrite_each_other() {
        let dir = sandbox("race");
        for round in 0..20 {
            let path = dir.join(format!("key-{round}"));
            let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
            let writers: Vec<_> = (0..8_u8)
                .map(|writer| {
                    let path = path.clone();
                    let barrier = barrier.clone();
                    std::thread::spawn(move || {
                        barrier.wait();
                        let bytes = [writer; 32];
                        write_private_new(&path, &bytes).map(|()| bytes)
                    })
                })
                .collect();
            let results: Vec<_> = writers
                .into_iter()
                .map(|writer| writer.join().expect("thread"))
                .collect();
            let winners: Vec<_> = results.iter().filter_map(|r| r.as_ref().ok()).collect();
            assert_eq!(winners.len(), 1, "round {round}");
            for result in &results {
                if let Err(error) = result {
                    assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
                }
            }
            assert_eq!(std::fs::read(&path).expect("read"), winners[0].to_vec());
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    /// #358 item 3: an existing trust file keeps no group or other access.
    #[cfg(unix)]
    #[test]
    fn an_existing_append_file_is_tightened_to_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = sandbox("tighten");
        let path = dir.join("trust.jsonl");
        std::fs::write(&path, b"old\n").expect("legacy");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).expect("chmod");
        open_private_append(&path)
            .and_then(|mut file| file.write_all(b"new\n"))
            .expect("append");
        let mode = std::fs::metadata(&path).expect("meta").permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        assert_eq!(std::fs::read(&path).expect("read"), b"old\nnew\n");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn an_append_target_that_is_a_symlink_is_refused() {
        let dir = sandbox("append-link");
        let victim = dir.join("victim");
        std::fs::write(&victim, b"keep").expect("victim");
        let path = dir.join("trust.jsonl");
        std::os::unix::fs::symlink(&victim, &path).expect("link");
        assert!(open_private_append(&path).is_err());
        assert_eq!(std::fs::read(&victim).expect("victim"), b"keep");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// #358 item 3 on Windows: an existing file another principal can read
    /// is refused rather than appended to.
    #[cfg(windows)]
    #[test]
    fn an_existing_append_file_others_can_read_is_refused() {
        let dir = sandbox("append-acl");
        let path = dir.join("trust.jsonl");
        open_private_append(&path).expect("create");
        let status = std::process::Command::new("icacls")
            .arg(&path)
            .args(["/grant", "*S-1-1-0:(R)"])
            .stdout(std::process::Stdio::null())
            .status()
            .expect("icacls");
        assert!(status.success());
        let error = open_private_append(&path).expect_err("shared");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn a_planted_temp_symlink_is_never_followed() {
        let dir = sandbox("planted");
        let victim = dir.join("victim");
        std::fs::write(&victim, b"keep").expect("victim");
        // Every predictable name an attacker could plant is a symlink; the
        // writer must still succeed without touching the victim.
        let path = dir.join("state.json");
        for name in [".state.json.tmp", ".state.json.tmp-0"] {
            std::os::unix::fs::symlink(&victim, dir.join(name)).expect("plant");
        }
        write_private_atomic(&path, b"new").expect("write");
        assert_eq!(std::fs::read(&victim).expect("victim"), b"keep");
        assert_eq!(std::fs::read(&path).expect("state"), b"new");
        let _ = std::fs::remove_dir_all(dir);
    }
}
