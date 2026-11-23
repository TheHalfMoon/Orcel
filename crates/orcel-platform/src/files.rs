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
use std::io::{self, Seek as _, Write};
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
/// never at neither, where the directory can be synced. A filesystem without
/// hard links either fails closed.
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
    move_file(from, to, Default::default())
}

/// `MoveFileExW`, written through.
#[cfg(windows)]
fn move_file(
    from: &Path,
    to: &Path,
    flags: windows::Win32::Storage::FileSystem::MOVE_FILE_FLAGS,
) -> io::Result<()> {
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_WRITE_THROUGH};
    let (from, to) = (verbatim(from)?, verbatim(to)?);
    // SAFETY: both paths are NUL-terminated and outlive the call.
    unsafe {
        MoveFileExW(
            PCWSTR(from.as_ptr()),
            PCWSTR(to.as_ptr()),
            flags | MOVEFILE_WRITE_THROUGH,
        )
    }
    .map_err(windows_error)
}

/// The windows crate's own conversion loses the error's kind.
#[cfg(windows)]
fn windows_error(error: windows::core::Error) -> io::Error {
    match windows::Win32::Foundation::WIN32_ERROR::from_error(&error) {
        Some(code) => io::Error::from_raw_os_error(code.0 as i32),
        None => error.into(),
    }
}

/// Moves `from` to `to` in the same directory, replacing a file there in one
/// rename, also while others have it open. On Windows the rename is written
/// through, and a read-only file is not replaced; on Unix the caller makes
/// it durable with [`sync_parent_dir`].
pub fn rename_replace(from: &Path, to: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        use windows::Win32::Foundation::ERROR_ACCESS_DENIED;
        use windows::Win32::Storage::FileSystem::MOVEFILE_REPLACE_EXISTING;
        match move_file(from, to, MOVEFILE_REPLACE_EXISTING) {
            // Perhaps only because someone has the file at `to` open.
            Err(error) if error.raw_os_error() == Some(ERROR_ACCESS_DENIED.0 as i32) => {
                posix_replace(from, to).map_err(|_| error)
            }
            done => done,
        }
    }
    #[cfg(not(windows))]
    {
        std::fs::rename(from, to)
    }
}

/// The rename that takes the name of a file others have open, as
/// `std::fs::rename` does it, through a write-through handle.
#[cfg(windows)]
fn posix_replace(from: &Path, to: &Path) -> io::Result<()> {
    use std::os::windows::fs::OpenOptionsExt as _;
    use std::os::windows::io::AsRawHandle as _;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Storage::FileSystem::{
        FileRenameInfoEx, SetFileInformationByHandle, DELETE, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_FLAG_WRITE_THROUGH, FILE_RENAME_INFO, SYNCHRONIZE,
    };
    const REPLACE_IF_EXISTS: u32 = 1;
    const POSIX_SEMANTICS: u32 = 2;
    let file = OpenOptions::new()
        .access_mode(DELETE.0 | SYNCHRONIZE.0)
        .custom_flags(FILE_FLAG_WRITE_THROUGH.0 | FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(from)?;
    let name = verbatim(to)?;
    let name_at = std::mem::offset_of!(FILE_RENAME_INFO, FileName);
    let size = (name_at + size_of_val(name.as_slice())).max(size_of::<FILE_RENAME_INFO>());
    let too_long = |_| io::Error::from(io::ErrorKind::InvalidInput);
    let name_bytes = u32::try_from((name.len() - 1) * 2).map_err(too_long)?;
    let info_bytes = u32::try_from(size).map_err(too_long)?;
    // u64 elements keep the FILE_RENAME_INFO aligned.
    let mut buffer = vec![0_u64; size.div_ceil(8)];
    let info = buffer.as_mut_ptr().cast::<FILE_RENAME_INFO>();
    // SAFETY: `buffer` is zeroed, aligned for FILE_RENAME_INFO and holds at
    // least `size` bytes: the fields and, from `name_at`, all of `name`.
    unsafe {
        (*info).Anonymous.Flags = REPLACE_IF_EXISTS | POSIX_SEMANTICS;
        (*info).FileNameLength = name_bytes;
        std::ptr::copy_nonoverlapping(
            name.as_ptr(),
            info.cast::<u8>().add(name_at).cast::<u16>(),
            name.len(),
        );
    }
    // SAFETY: the handle is open for the call, as `file` outlives it, and
    // `info` points to `info_bytes` readable bytes.
    unsafe {
        SetFileInformationByHandle(
            HANDLE(file.as_raw_handle()),
            FileRenameInfoEx,
            info.cast(),
            info_bytes,
        )
    }
    .map_err(windows_error)
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
fn remove_spare_name(from: &Path, to: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let (Ok(from), Ok(named)) = (
            std::fs::symlink_metadata(from),
            std::fs::symlink_metadata(to),
        ) else {
            return;
        };
        if (from.dev(), from.ino()) != (named.dev(), named.ino()) {
            return;
        }
    }
    #[cfg(windows)]
    {
        let mut options = OpenOptions::new();
        options.read(true);
        not_through_a_link(&mut options);
        if options
            .open(from)
            .and_then(|from| is_at(&from, to))
            .is_err()
        {
            return;
        }
    }
    let _ = std::fs::remove_file(to);
}

/// A file kept under a second name by [`keep_file_as`].
#[must_use]
#[derive(Debug)]
pub struct KeptFile {
    from: PathBuf,
    to: PathBuf,
    copied: bool,
}

impl KeptFile {
    /// Takes the kept name away again, unless it may be the file's only one:
    /// it stays when the file is no longer at the name it was kept from, and
    /// so does a copy, which cannot be told from the only one.
    pub fn remove_spare(self) {
        if !self.copied {
            remove_spare_name(&self.from, &self.to);
        }
    }
}

/// Opens the regular file at `path` so that [`keep_file_as`] can keep it. A
/// link there is refused, not followed, and so is anything else that is not
/// a regular file. Keeping the file flushes it, which on Windows needs a
/// handle that may write: a read-only file is refused there.
pub fn open_to_keep(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(cfg!(windows));
    not_through_a_link(&mut options);
    let file = options.open(path).map_err(|error| {
        if error.kind() != io::ErrorKind::PermissionDenied {
            return error;
        }
        let remedy = if cfg!(windows) {
            "clear its read-only attribute, and check that its permissions let you write to it"
        } else {
            "check that its permissions let you read it"
        };
        io::Error::new(
            error.kind(),
            format!("it cannot be opened to flush it to disk: {error}; {remedy}"),
        )
    })?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "it is a link or not a regular file",
        ));
    }
    Ok(file)
}

/// Opens what is at the path, never what a link there leads to, and never
/// waits for a pipe's other end.
fn not_through_a_link(options: &mut OpenOptions) {
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(options, libc::O_NOFOLLOW | libc::O_NONBLOCK);
    #[cfg(windows)]
    std::os::windows::fs::OpenOptionsExt::custom_flags(
        options,
        windows::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT.0,
    );
    #[cfg(not(any(unix, windows)))]
    let _ = options;
}

/// Keeps `file`, which [`open_to_keep`] opened at `from`, under the name `to`
/// as well, durably, without moving it: as a hard link, or as a copy, read
/// from `file` itself, where the filesystem has no hard links. Any other
/// failure to link is an error, and so is a `from` that is not `file` any
/// longer: what took its place is never copied, and a link to it is taken
/// away again. Whatever is at `to` is never replaced or followed
/// ([`io::ErrorKind::AlreadyExists`]). On an error nothing is kept, or at
/// most a whole copy.
///
/// A process that writes to the directory without taking the caller's lock
/// can still put another file at `from` later, as it could remove the file.
pub fn keep_file_as(file: &File, from: &Path, to: &Path) -> io::Result<KeptFile> {
    keep_file_with(
        file,
        from,
        to,
        |from, to| std::fs::hard_link(from, to),
        File::sync_all,
        sync_parent_dir,
    )
}

fn keep_file_with(
    file: &File,
    from: &Path,
    to: &Path,
    link: impl FnOnce(&Path, &Path) -> io::Result<()>,
    flush: impl FnOnce(&File) -> io::Result<()>,
    sync: impl FnOnce(&Path) -> io::Result<()>,
) -> io::Result<KeptFile> {
    let copied = match link(from, to) {
        Ok(()) => false,
        Err(error) if hard_links_unsupported(&error) => {
            copy_to_new(file, to, || {})?;
            true
        }
        Err(error) => return Err(error),
    };
    let kept = KeptFile {
        from: from.to_path_buf(),
        to: to.to_path_buf(),
        copied,
    };
    // The linked file's bytes may not be on disk yet; a copy's are.
    let flushed = if copied {
        Ok(())
    } else {
        is_at(file, to).and_then(|()| flush(file))
    };
    match flushed.and_then(|()| sync(to)) {
        Ok(()) => Ok(kept),
        Err(error) => {
            kept.remove_spare();
            Err(error)
        }
    }
}

/// Whether the error says that the filesystem has no hard links, as against
/// every other reason why one was not made. `EPERM` is what Linux answers for
/// such a filesystem (and for another user's file, or from a system call
/// filter: what is copied then is the checked file all the same).
fn hard_links_unsupported(error: &io::Error) -> bool {
    #[cfg(target_os = "linux")]
    let unsupported = [libc::EPERM, libc::ENOTSUP, libc::ENOSYS];
    #[cfg(all(unix, not(target_os = "linux")))]
    let unsupported = [libc::ENOTSUP, libc::EOPNOTSUPP, libc::ENOSYS];
    // ERROR_INVALID_FUNCTION (FAT and exFAT) and ERROR_NOT_SUPPORTED.
    #[cfg(windows)]
    let unsupported = [1, 50];
    #[cfg(not(any(unix, windows)))]
    let unsupported: [i32; 0] = [];
    error
        .raw_os_error()
        .is_some_and(|code| unsupported.contains(&code))
}

/// An error unless `file` is what has the name `path`.
fn is_at(file: &File, path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    let same = {
        use std::os::unix::fs::MetadataExt as _;
        let (file, named) = (file.metadata()?, std::fs::symlink_metadata(path)?);
        (file.dev(), file.ino()) == (named.dev(), named.ino())
    };
    #[cfg(windows)]
    let same = {
        let mut options = OpenOptions::new();
        options.read(true);
        not_through_a_link(&mut options);
        identity(file)? == identity(&options.open(path)?)?
    };
    #[cfg(not(any(unix, windows)))]
    let same = {
        let _ = (file, path);
        false
    };
    if same {
        Ok(())
    } else {
        Err(io::Error::other("another file took the file's place"))
    }
}

/// The volume and the file on it.
#[cfg(windows)]
fn identity(file: &File) -> io::Result<(u32, u32, u32)> {
    use std::os::windows::io::AsRawHandle as _;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the handle is open for the call, as `file` outlives it; `info`
    // is a valid out pointer.
    unsafe { GetFileInformationByHandle(HANDLE(file.as_raw_handle()), &mut info) }
        .map_err(windows_error)?;
    Ok((
        info.dwVolumeSerialNumber,
        info.nFileIndexHigh,
        info.nFileIndexLow,
    ))
}

/// An error unless both files were opened in one directory: a path whose
/// directory was swapped meanwhile leads to another one. Checked on Windows
/// only; no elevated command keeps a file on Unix.
fn in_one_directory(a: &File, b: &File) -> io::Result<()> {
    #[cfg(windows)]
    if directory_of(a)? != directory_of(b)? {
        return Err(io::Error::other("another directory took the file's place"));
    }
    #[cfg(not(windows))]
    let _ = (a, b);
    Ok(())
}

/// The directory the system opened `file` in.
#[cfg(windows)]
fn directory_of(file: &File) -> io::Result<Vec<u16>> {
    use std::os::windows::io::AsRawHandle as _;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Storage::FileSystem::{
        GetFinalPathNameByHandleW, FILE_NAME_OPENED, GETFINALPATHNAMEBYHANDLE_FLAGS, VOLUME_NAME_NT,
    };
    // No path is longer than this, NUL included.
    let mut path = vec![0_u16; 0x8000];
    // SAFETY: the handle is open for the call, as `file` outlives it.
    let length = unsafe {
        GetFinalPathNameByHandleW(
            HANDLE(file.as_raw_handle()),
            &mut path,
            GETFINALPATHNAMEBYHANDLE_FLAGS(FILE_NAME_OPENED.0 | VOLUME_NAME_NT.0),
        )
    } as usize;
    if length == 0 {
        return Err(io::Error::last_os_error());
    }
    path.truncate(length);
    path.iter()
        .rposition(|unit| *unit == u16::from(b'\\'))
        .map(|end| path[..end].to_vec())
        .ok_or_else(|| io::Error::other("the file's directory is not known"))
}

/// Copies all of `source` to `to`, which must not exist yet and is made in
/// the same directory, owner-only on Unix, and flushes it. A partial copy is
/// removed, and so is one of a file whose length changed (`read` runs when
/// the bytes have been read).
fn copy_to_new(source: &File, to: &Path, read: impl FnOnce()) -> io::Result<()> {
    let mut source = source;
    // A reparse point that is no link: its own bytes are not the file's.
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        use windows::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
        if source.metadata()?.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
            return Err(io::Error::other("a reparse point is not copied"));
        }
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    owner_only(&mut options);
    let mut copy = options.open(to)?;
    let fill = || {
        in_one_directory(source, &copy)?;
        source.rewind()?;
        let bytes = io::copy(&mut source, &mut copy)?;
        read();
        if bytes != source.metadata()?.len() {
            return Err(io::Error::other("the file changed while it was copied"));
        }
        copy.sync_all()
    };
    let copied = fill();
    drop(copy);
    if copied.is_err() {
        let _ = std::fs::remove_file(to);
    }
    copied
}

/// Makes the names in `path`'s directory durable, where the filesystem can
/// (on Windows the filesystem's own journal orders them).
pub fn sync_parent_dir(path: &Path) -> io::Result<()> {
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
                link_then_unlink_with(from, to, |_| failed(), |from| std::fs::remove_file(from))
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
        let _ = std::fs::remove_dir_all(dir);
    }

    /// What a filesystem without hard links answers.
    fn no_hard_links() -> io::Error {
        #[cfg(unix)]
        let code = libc::ENOTSUP;
        #[cfg(not(unix))]
        let code = 1;
        io::Error::from_raw_os_error(code)
    }

    fn copy_as(file: &File, from: &Path, to: &Path) -> io::Result<KeptFile> {
        let no_link = |_: &Path, _: &Path| Err(no_hard_links());
        keep_file_with(file, from, to, no_link, File::sync_all, sync_parent_dir)
    }

    type Keep = fn(&Path, &Path) -> io::Result<KeptFile>;

    /// Both ways to keep a file: a hard link, and the copy a filesystem
    /// without hard links gets.
    const KEEPERS: [Keep; 2] = [
        |from, to| keep_file_as(&open_to_keep(from)?, from, to),
        |from, to| copy_as(&open_to_keep(from)?, from, to),
    ];

    #[test]
    fn a_file_is_kept_whole_and_where_it_is() {
        for (index, keep) in KEEPERS.iter().enumerate() {
            let dir = sandbox(&format!("keep-{index}"));
            let (from, to) = (dir.join("from"), dir.join("to"));
            std::fs::write(&from, b"one").expect("from");
            let kept = keep(&from, &to).expect("keep");
            assert_eq!(kept.copied, index == 1);
            assert_eq!(std::fs::read(&from).expect("from"), b"one");
            assert_eq!(std::fs::read(&to).expect("to"), b"one");
            // Replacing the file leaves the kept one, and it is then not spare.
            std::fs::write(dir.join("new"), b"new").expect("new");
            std::fs::rename(dir.join("new"), &from).expect("replace");
            assert_eq!(std::fs::read(&to).expect("to"), b"one");
            kept.remove_spare();
            assert_eq!(std::fs::read(&to).expect("to"), b"one");
            #[cfg(unix)]
            if index == 1 {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(&to).expect("meta").permissions().mode();
                assert_eq!(mode & 0o777, 0o600);
            }
            // Where the file is still in place, a link can be taken away.
            let spare = keep(&from, &dir.join("spare")).expect("keep");
            spare.remove_spare();
            assert_eq!(dir.join("spare").exists(), index == 1);
            assert_eq!(std::fs::read(&from).expect("from"), b"new");
            // Where it is gone, the kept one stays.
            let only = keep(&from, &dir.join("only")).expect("keep");
            std::fs::remove_file(&from).expect("gone");
            only.remove_spare();
            assert_eq!(std::fs::read(dir.join("only")).expect("only"), b"new");
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    #[test]
    fn keeping_a_file_never_replaces_or_follows_what_is_there() {
        for (index, keep) in KEEPERS.iter().enumerate() {
            let dir = sandbox(&format!("keep-taken-{index}"));
            let (from, to) = (dir.join("from"), dir.join("to"));
            std::fs::write(&from, b"new").expect("from");
            std::fs::write(&to, b"kept").expect("to");
            std::fs::create_dir(dir.join("folder")).expect("folder");
            let mut targets = vec![to.clone()];
            // A directory refuses a copy with another error on Windows.
            if index == 0 || cfg!(unix) {
                targets.push(dir.join("folder"));
            }
            #[cfg(unix)]
            for (name, leads_to) in [("link", "to"), ("dangling", "nowhere")] {
                std::os::unix::fs::symlink(dir.join(leads_to), dir.join(name)).expect("link");
                targets.push(dir.join(name));
            }
            for target in targets {
                let error = keep(&from, &target).expect_err("taken");
                assert_eq!(error.kind(), io::ErrorKind::AlreadyExists, "keep {index}");
            }
            assert_eq!(std::fs::read(&to).expect("to"), b"kept");
            assert!(!dir.join("nowhere").exists());
            assert_eq!(std::fs::read(&from).expect("from"), b"new");
            let missing = keep(&dir.join("missing"), &dir.join("none")).expect_err("missing");
            assert_eq!(missing.kind(), io::ErrorKind::NotFound);
            assert!(!dir.join("none").exists());
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    /// Only a filesystem that has no hard links leads to a copy; any other
    /// failure to link keeps nothing.
    #[test]
    fn only_unsupported_hard_links_lead_to_a_copy() {
        let dir = sandbox("keep-link-error");
        let (from, to) = (dir.join("from"), dir.join("to"));
        std::fs::write(&from, b"one").expect("from");
        let file = open_to_keep(&from).expect("open");
        // Access denied, not found, disk full, too many links, I/O error.
        #[cfg(windows)]
        let others = [5, 2, 112, 1142, 1117];
        #[cfg(unix)]
        let others = [
            libc::EACCES,
            libc::ENOENT,
            libc::ENOSPC,
            libc::EMLINK,
            libc::EIO,
        ];
        let others = others.map(io::Error::from_raw_os_error);
        let unnumbered = [io::ErrorKind::Unsupported, io::ErrorKind::Other].map(io::Error::from);
        for error in others.into_iter().chain(unnumbered) {
            let expected = error.to_string();
            let no_link = |_: &Path, _: &Path| Err(error);
            let failed = keep_file_with(&file, &from, &to, no_link, File::sync_all, |_| Ok(()))
                .expect_err("the error");
            assert_eq!(failed.to_string(), expected);
            assert!(std::fs::symlink_metadata(&to).is_err(), "{expected}");
        }
        #[cfg(windows)]
        let unsupported = [1, 50];
        #[cfg(target_os = "linux")]
        let unsupported = [libc::EPERM, libc::ENOTSUP, libc::ENOSYS];
        #[cfg(all(unix, not(target_os = "linux")))]
        let unsupported = [libc::ENOTSUP, libc::EOPNOTSUPP, libc::ENOSYS];
        for (index, code) in unsupported.into_iter().enumerate() {
            let to = dir.join(format!("copy-{index}"));
            let no_link = |_: &Path, _: &Path| Err(io::Error::from_raw_os_error(code));
            let kept = keep_file_with(&file, &from, &to, no_link, File::sync_all, |_| Ok(()))
                .expect("a copy");
            assert!(kept.copied);
            assert_eq!(std::fs::read(&to).expect("copy"), b"one", "{code}");
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Another file that took the checked file's place is neither kept nor
    /// copied, and the checked file is copied whole wherever its reader was.
    #[test]
    fn a_file_that_took_the_place_is_never_kept_or_copied() {
        let dir = sandbox("keep-swapped");
        let (from, to) = (dir.join("from"), dir.join("to"));
        std::fs::write(&from, b"one").expect("from");
        let file = open_to_keep(&from).expect("open");
        io::copy(&mut &file, &mut io::sink()).expect("read to its end");
        std::fs::rename(&from, dir.join("moved")).expect("moved");
        std::fs::write(&from, b"secret").expect("another");
        assert!(keep_file_as(&file, &from, &to).is_err());
        assert!(std::fs::symlink_metadata(&to).is_err());
        assert_eq!(std::fs::read(&from).expect("from"), b"secret");
        assert!(copy_as(&file, &from, &to).expect("a copy").copied);
        assert_eq!(std::fs::read(&to).expect("to"), b"one");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A copy is made where the checked file is, not in a directory that
    /// took the place of that one.
    #[cfg(windows)]
    #[test]
    fn a_copy_is_never_made_in_another_directory() {
        let dir = sandbox("keep-directory");
        std::fs::create_dir(dir.join("other")).expect("other");
        let from = dir.join("from");
        std::fs::write(&from, b"one").expect("from");
        let file = open_to_keep(&from).expect("open");
        let to = dir.join("other").join("to");
        assert!(copy_as(&file, &from, &to).is_err());
        assert!(std::fs::symlink_metadata(&to).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A link is never opened to be kept, whether it leads anywhere or not,
    /// nor is a directory.
    #[test]
    fn only_a_regular_file_is_opened_to_be_kept() {
        let dir = sandbox("keep-open");
        assert!(open_to_keep(&dir).is_err(), "a directory");
        assert_eq!(
            open_to_keep(&dir.join("missing"))
                .expect_err("missing")
                .kind(),
            io::ErrorKind::NotFound
        );
        let victim = dir.join("victim");
        std::fs::write(&victim, b"secret").expect("victim");
        for target in [victim.clone(), dir.join("nowhere")] {
            let link = dir.join(format!("link-{}", target.exists()));
            #[cfg(unix)]
            std::os::unix::fs::symlink(&target, &link).expect("link");
            // Without the privilege to make one there is nothing to test.
            #[cfg(windows)]
            if std::os::windows::fs::symlink_file(&target, &link).is_err() {
                continue;
            }
            assert_ne!(
                open_to_keep(&link).expect_err("a link").kind(),
                io::ErrorKind::NotFound
            );
        }
        // Windows lets everyone make a junction. One that leads nowhere is
        // there all the same.
        #[cfg(windows)]
        for target in [dir.clone(), dir.join("nowhere")] {
            let link = dir.join(format!("junction-{}", target.exists()));
            junction(&target, &link);
            assert_ne!(
                open_to_keep(&link).expect_err("a junction").kind(),
                io::ErrorKind::NotFound
            );
        }
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt as _;
            let pipe = dir.join("pipe");
            let name = std::ffi::CString::new(pipe.as_os_str().as_bytes()).expect("name");
            // SAFETY: the path is NUL-terminated and outlives the call.
            assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
            let refused = open_to_keep(&pipe).expect_err("a pipe, without waiting for it");
            assert_eq!(refused.kind(), io::ErrorKind::InvalidInput);
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(windows)]
    fn junction(target: &Path, link: &Path) {
        let status = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .args([link, target])
            .stdout(std::process::Stdio::null())
            .status()
            .expect("mklink");
        assert!(status.success());
        assert!(std::fs::symlink_metadata(link).is_ok());
    }

    /// Why a read-only file is not kept, and what to do about it.
    #[cfg(windows)]
    #[test]
    fn a_read_only_file_is_refused_with_its_remedy() {
        let dir = sandbox("keep-read-only");
        let from = dir.join("from");
        std::fs::write(&from, b"one").expect("from");
        let writable = std::fs::metadata(&from).expect("meta").permissions();
        let mut permissions = writable.clone();
        permissions.set_readonly(true);
        std::fs::set_permissions(&from, permissions).expect("read-only");
        let error = open_to_keep(&from).expect_err("read-only");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        for part in ["flush it to disk", "read-only attribute", "permissions"] {
            assert!(error.to_string().contains(part), "{error}");
        }
        std::fs::set_permissions(&from, writable).expect("writable");
        open_to_keep(&from).expect("open");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A kept file's bytes are on disk before its new name is.
    #[test]
    fn a_kept_file_is_flushed_before_its_name() {
        let dir = sandbox("keep-order");
        let (from, to) = (dir.join("from"), dir.join("to"));
        std::fs::write(&from, b"one").expect("from");
        let file = open_to_keep(&from).expect("open");
        let steps = std::cell::RefCell::new(Vec::new());
        let keep = |flushes: bool, syncs: bool| {
            steps.take();
            let done = |step, ok: bool| {
                steps.borrow_mut().push(step);
                assert!(to.exists(), "{step} comes after the link");
                if ok {
                    Ok(())
                } else {
                    Err(io::Error::other(step))
                }
            };
            keep_file_with(
                &file,
                &from,
                &to,
                |from, to| std::fs::hard_link(from, to),
                |_| done("flush", flushes),
                |synced| {
                    assert_eq!(synced, to);
                    done("sync", syncs)
                },
            )
        };
        for (flushes, syncs, failed) in [(false, true, "flush"), (true, false, "sync")] {
            let error = keep(flushes, syncs).expect_err("injected");
            assert_eq!(error.to_string(), failed);
            assert!(std::fs::symlink_metadata(&to).is_err(), "{failed}");
        }
        keep(true, true).expect("kept").remove_spare();
        assert_eq!(steps.take(), ["flush", "sync"]);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A copy of a file that grew or shrank meanwhile is not the file.
    #[test]
    fn a_copy_of_a_file_that_changed_meanwhile_is_removed() {
        let dir = sandbox("keep-changed");
        let (from, to) = (dir.join("from"), dir.join("to"));
        for now in ["one and more", "o"] {
            std::fs::write(&from, b"one").expect("from");
            let file = open_to_keep(&from).expect("open");
            let error = copy_to_new(&file, &to, || {
                std::fs::write(&from, now).expect("changed");
            })
            .expect_err("changed");
            assert!(error.to_string().contains("changed"), "{error}");
            assert!(!to.exists(), "{now}");
            copy_to_new(&file, &to, || {}).expect("the next try");
            assert_eq!(std::fs::read(&to).expect("to"), now.as_bytes());
            std::fs::remove_file(&to).expect("to");
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    /// The replacing rename takes the name of a file that is open, and leaves
    /// everything as it was when it fails.
    #[test]
    fn a_replacing_rename_replaces_a_file_also_while_it_is_open() {
        use std::io::Read as _;
        let dir = sandbox("replace");
        let (from, to) = (dir.join("from"), dir.join("to"));
        for open in [false, true] {
            std::fs::write(&from, b"new").expect("from");
            std::fs::write(&to, b"old").expect("to");
            let reader = open.then(|| File::open(&to).expect("reader"));
            rename_replace(&from, &to).expect("replaced");
            assert!(!from.exists());
            assert_eq!(std::fs::read(&to).expect("to"), b"new");
            if let Some(mut reader) = reader {
                let mut read = Vec::new();
                reader.read_to_end(&mut read).expect("read on");
                assert_eq!(read, b"old");
            }
        }
        std::fs::write(&from, b"new").expect("from");
        std::fs::create_dir(dir.join("folder")).expect("folder");
        assert!(rename_replace(&from, &dir.join("folder")).is_err());
        assert_eq!(std::fs::read(&from).expect("from"), b"new");
        assert!(dir.join("folder").is_dir());
        #[cfg(windows)]
        {
            let writable = std::fs::metadata(&to).expect("meta").permissions();
            let mut permissions = writable.clone();
            permissions.set_readonly(true);
            std::fs::set_permissions(&to, permissions).expect("read-only");
            let error = rename_replace(&from, &to).expect_err("read-only");
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            assert_eq!(std::fs::read(&to).expect("to"), b"new");
            std::fs::set_permissions(&to, writable).expect("writable");
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Both renames on Windows take names longer than MAX_PATH.
    #[cfg(windows)]
    #[test]
    fn a_replacing_rename_takes_a_long_path() {
        let dir = sandbox("replace-long");
        let mut deep = dir.clone();
        while deep.as_os_str().len() < 300 {
            deep.push("d".repeat(50));
        }
        std::fs::create_dir_all(&deep).expect("deep");
        let (from, to) = (deep.join("from"), deep.join("to"));
        for replace in [rename_replace, posix_replace] {
            std::fs::write(&from, b"new").expect("from");
            std::fs::write(&to, b"old").expect("to");
            let _reader = File::open(&to).expect("reader");
            replace(&from, &to).expect("replaced");
            assert_eq!(std::fs::read(&to).expect("to"), b"new");
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
