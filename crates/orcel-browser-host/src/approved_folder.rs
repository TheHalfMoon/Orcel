//! #307: create-only writes into the approved folder through held handles.
//!
//! The approved folder is opened once, its real path compared with the one
//! the approval named, and the handle held without delete sharing: while it
//! is held, the folder cannot be renamed, removed or replaced by a junction.
//! Every subfolder and the file itself are then opened relative to their
//! parent's handle with `OBJ_DONT_REPARSE`, so a junction, symlink or mount
//! point anywhere below the folder refuses the write instead of redirecting
//! it, and there is no window between a check and a create. The content is
//! written to a hidden temporary file that is marked for deletion until the
//! last step: if the host dies mid-write, the system removes it. The file
//! then takes its name with a rename that never replaces.

use crate::error::HostError;
use std::fs::File;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::path::{Path, PathBuf};
use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    NtCreateFile, NtSetInformationFile, FILE_CREATE, FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE,
    FILE_OPEN, FILE_OPEN_IF, FILE_RENAME_INFORMATION, FILE_SYNCHRONOUS_IO_NONALERT,
};
use windows_sys::Win32::Foundation::{HANDLE, UNICODE_STRING};
use windows_sys::Win32::Storage::FileSystem::{
    FileBasicInfo, FileDispositionInfo, GetFinalPathNameByHandleW, SetFileInformationByHandle,
    DELETE, FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_NORMAL,
    FILE_ATTRIBUTE_TEMPORARY, FILE_BASIC_INFO, FILE_DISPOSITION_INFO, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_SHARE_READ, FILE_SHARE_WRITE,
    FILE_TRAVERSE, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, SYNCHRONIZE, VOLUME_NAME_DOS,
};
use windows_sys::Win32::Storage::FileSystem::{
    GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
};
use windows_sys::Win32::System::Kernel::OBJ_DONT_REPARSE;
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

const OBJ_CASE_INSENSITIVE: u32 = 0x40;
const STATUS_OBJECT_NAME_COLLISION: i32 = 0xC000_0035_u32 as i32;
const STATUS_REPARSE_POINT_ENCOUNTERED: i32 = 0xC000_050B_u32 as i32;
const STATUS_NOT_A_DIRECTORY: i32 = 0xC000_0103_u32 as i32;
/// A folder turned into a mount point while held (its name now leads
/// nowhere the relative open may follow).
const STATUS_REPARSE_POINT_NOT_RESOLVED: i32 = 0xC000_0280_u32 as i32;
const STATUS_FILE_IS_A_DIRECTORY: i32 = 0xC000_00BA_u32 as i32;
const STATUS_OBJECT_NAME_NOT_FOUND: i32 = 0xC000_0034_u32 as i32;
const STATUS_OBJECT_PATH_NOT_FOUND: i32 = 0xC000_003A_u32 as i32;

/// Directory rights the commit needs on a folder it holds.
const FOLDER_ACCESS: u32 = FILE_LIST_DIRECTORY
    | FILE_ADD_FILE
    | FILE_ADD_SUBDIRECTORY
    | FILE_TRAVERSE
    | FILE_READ_ATTRIBUTES
    | SYNCHRONIZE;

fn escape() -> HostError {
    HostError::Invalid("destination escapes the approved folder".into())
}

fn wide(text: &str) -> Vec<u16> {
    std::ffi::OsStr::new(text).encode_wide().collect()
}

/// The real path of an open handle, in `std::fs::canonicalize`'s form.
fn final_path(handle: RawHandle) -> Result<PathBuf, HostError> {
    let mut buffer = vec![0u16; 1024];
    loop {
        // SAFETY: `handle` is an open handle owned by the caller for the
        // duration of the call; `buffer` is writable for its full length.
        let written = unsafe {
            GetFinalPathNameByHandleW(
                handle as HANDLE,
                buffer.as_mut_ptr(),
                buffer.len() as u32,
                VOLUME_NAME_DOS,
            )
        } as usize;
        if written == 0 {
            return Err(HostError::Platform("final path of a handle".into()));
        }
        if written < buffer.len() {
            buffer.truncate(written);
            return Ok(PathBuf::from(String::from_utf16_lossy(&buffer)));
        }
        if buffer.len() >= 32 * 1024 {
            return Err(HostError::Platform("final path is too long".into()));
        }
        buffer.resize(written + 1, 0);
    }
}

/// `NtCreateFile` relative to `parent`, never following a reparse point.
fn open_relative(
    parent: RawHandle,
    name: &str,
    access: u32,
    share: u32,
    attributes: u32,
    disposition: u32,
    options: u32,
) -> Result<OwnedHandle, HostError> {
    let name = wide(name);
    let bytes = u16::try_from(name.len() * 2).map_err(|_| escape())?;
    let unicode = UNICODE_STRING {
        Length: bytes,
        MaximumLength: bytes,
        Buffer: name.as_ptr() as *mut u16,
    };
    let object = OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent as HANDLE,
        ObjectName: &unicode,
        Attributes: OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE as u32,
        SecurityDescriptor: std::ptr::null(),
        SecurityQualityOfService: std::ptr::null(),
    };
    // SAFETY: an all-zero IO_STATUS_BLOCK is a valid initial value.
    let mut status_block: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
    let mut handle: HANDLE = 0;
    // SAFETY: `object`, `unicode` and `name` live until the call returns;
    // `parent` is a directory handle the caller holds; `handle` and
    // `status_block` are writable outputs.
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            access,
            &object,
            &mut status_block,
            std::ptr::null(),
            attributes,
            share,
            disposition,
            options,
            std::ptr::null(),
            0,
        )
    };
    match status {
        // NT_SUCCESS: any non-negative status.
        0.. => {
            // SAFETY: NtCreateFile succeeded, so `handle` is a new handle
            // this function now owns.
            Ok(unsafe { OwnedHandle::from_raw_handle(handle as RawHandle) })
        }
        STATUS_OBJECT_NAME_COLLISION => Err(HostError::Invalid(
            "destination exists (create-only)".into(),
        )),
        STATUS_REPARSE_POINT_ENCOUNTERED | STATUS_REPARSE_POINT_NOT_RESOLVED => {
            Err(HostError::Invalid(
                "destination escapes the approved folder (a reparse point below it)".into(),
            ))
        }
        STATUS_OBJECT_NAME_NOT_FOUND | STATUS_OBJECT_PATH_NOT_FOUND => Err(HostError::Invalid(
            "the file does not exist in the approved folder".into(),
        )),
        STATUS_NOT_A_DIRECTORY | STATUS_FILE_IS_A_DIRECTORY => Err(HostError::Invalid(
            "destination escapes the approved folder (not a folder)".into(),
        )),
        other => Err(HostError::Platform(format!(
            "destination: NTSTATUS {:#010x}",
            other as u32
        ))),
    }
}

fn set_delete_on_close(file: RawHandle, delete: bool) -> Result<(), HostError> {
    let info = FILE_DISPOSITION_INFO {
        DeleteFile: u8::from(delete),
    };
    // SAFETY: `file` is an open handle with DELETE access; `info` is a valid
    // FILE_DISPOSITION_INFO for the size given.
    let ok = unsafe {
        SetFileInformationByHandle(
            file as HANDLE,
            FileDispositionInfo,
            (&info as *const FILE_DISPOSITION_INFO).cast(),
            std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    };
    if ok == 0 {
        return Err(HostError::Platform("staged file disposition".into()));
    }
    Ok(())
}

/// `FILE_INFORMATION_CLASS::FileRenameInformation` (documented value).
const FILE_RENAME_INFORMATION_CLASS: i32 = 10;

/// Rename the open `file` to `name` inside the held `folder`, never
/// replacing. The name is relative to the folder's handle: a bare name
/// without a root would be resolved against the process's current folder.
fn rename_no_replace(file: RawHandle, folder: RawHandle, name: &str) -> Result<(), HostError> {
    let name = wide(name);
    let header = std::mem::size_of::<FILE_RENAME_INFORMATION>();
    let size = header + name.len() * 2;
    // u64 words keep the buffer aligned for FILE_RENAME_INFORMATION.
    let mut buffer = vec![0u64; size.div_ceil(8)];
    let info = buffer.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>();
    // SAFETY: `buffer` holds at least `size` bytes, aligned for the struct;
    // the name is copied into the trailing flexible array, inside `buffer`.
    unsafe {
        (*info).Anonymous.Flags = 0;
        (*info).RootDirectory = folder as HANDLE;
        (*info).FileNameLength = (name.len() * 2) as u32;
        std::ptr::copy_nonoverlapping(
            name.as_ptr(),
            std::ptr::addr_of_mut!((*info).FileName).cast::<u16>(),
            name.len(),
        );
    }
    // SAFETY: an all-zero IO_STATUS_BLOCK is a valid initial value.
    let mut status_block: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
    // SAFETY: `file` is open with DELETE access and `folder` is a directory
    // handle the caller holds; `info` points to `size` initialized bytes.
    let status = unsafe {
        NtSetInformationFile(
            file as HANDLE,
            &mut status_block,
            info.cast(),
            size as u32,
            FILE_RENAME_INFORMATION_CLASS,
        )
    };
    match status {
        0 => Ok(()),
        STATUS_OBJECT_NAME_COLLISION => Err(HostError::Invalid(
            "destination exists (create-only)".into(),
        )),
        other => Err(HostError::Platform(format!(
            "destination rename: NTSTATUS {:#010x}",
            other as u32
        ))),
    }
}

/// Commit `content` create-only as `relative` (already validated by
/// `validate_relative_destination`) inside `root`, whose real path must
/// still be `bound_root` (the one the approval named). Returns the
/// committed file's path.
pub(crate) fn commit(
    root: &Path,
    bound_root: &str,
    relative: &str,
    content: &[u8],
) -> Result<PathBuf, HostError> {
    use std::io::Write;
    use std::os::windows::fs::OpenOptionsExt;
    let parts: Vec<&str> = relative.split(['/', '\\']).collect();
    let Some((file_name, folders)) = parts.split_last() else {
        return Err(HostError::Invalid("destination has no file name".into()));
    };
    // The approved folder, held without delete sharing for the whole commit.
    let root_handle: OwnedHandle = std::fs::OpenOptions::new()
        .access_mode(FOLDER_ACCESS)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(root)
        .map_err(|err| HostError::Invalid(format!("the approved folder cannot be held: {err}")))?
        .into();
    let real_root = final_path(root_handle.as_raw_handle())?;
    if real_root.as_os_str() != std::ffi::OsStr::new(bound_root) {
        return Err(HostError::Invalid(
            "the approved folder changed since it was approved".into(),
        ));
    }
    // Each folder below it, opened or created relative to its parent and
    // held (no delete sharing) until the file has its name.
    let mut held: Vec<OwnedHandle> = Vec::with_capacity(folders.len());
    for folder in folders {
        let parent = held
            .last()
            .map_or(root_handle.as_raw_handle(), AsRawHandle::as_raw_handle);
        let handle = open_relative(
            parent,
            folder,
            FOLDER_ACCESS,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_ATTRIBUTE_NORMAL,
            FILE_OPEN_IF,
            FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        )?;
        held.push(handle);
    }
    let folder = held
        .last()
        .map_or(root_handle.as_raw_handle(), AsRawHandle::as_raw_handle);
    // One temporary name per destination (#309): a leftover from a commit
    // the host never finished is found, and removed, by the next attempt.
    let staged_name = staged_name_for(file_name);
    let create = || {
        open_relative(
            folder,
            &staged_name,
            FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            0,
            FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_TEMPORARY,
            FILE_CREATE,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        )
    };
    let staged = match create() {
        Err(HostError::Invalid(message)) if message.contains("create-only") => {
            remove_stale(folder, &staged_name)?;
            create()?
        }
        other => other?,
    };
    crash_point("created");
    // From here on, any failure marks the file for deletion again (the
    // guard), so nothing staged or half-committed outlives the commit.
    let mut staged = Staged {
        file: File::from(staged),
        keep: false,
    };
    // Until it has its name, the file goes away with the last handle, even
    // if the host dies.
    set_delete_on_close(staged.raw(), true)?;
    staged
        .file
        .write_all(content)
        .and_then(|()| staged.file.sync_all())
        .map_err(|err| HostError::Platform(format!("destination write: {err}")))?;
    crash_point("written");
    // The committed file is an ordinary file, not a hidden temporary one:
    // its attributes are cleared while it still has its temporary name, so
    // it never stands under the approved name hidden.
    set_attributes(staged.raw(), FILE_ATTRIBUTE_NORMAL)?;
    // A file marked for deletion cannot be renamed, so the mark is cleared
    // just before the rename.
    set_delete_on_close(staged.raw(), false)?;
    crash_point("cleared");
    rename_no_replace(staged.raw(), folder, file_name)?;
    // Defense in depth: the named file is inside the held folder.
    let committed = final_path(staged.raw())?;
    let inside = committed
        .strip_prefix(&real_root)
        .is_ok_and(|rest| rest.components().count() == parts.len());
    if !inside {
        return Err(HostError::Invalid(format!(
            "destination escapes the approved folder (committed as {})",
            committed.display()
        )));
    }
    staged.keep = true;
    drop(staged);
    drop(held);
    // The path the held handle reached, not one rebuilt from the caller's
    // text.
    Ok(committed)
}

/// The temporary name for `file_name`: hidden, in Orcel's own namespace,
/// and the same for every attempt at that destination (case-insensitive,
/// as the file system is).
/// BR-03: read `relative` (already validated by
/// `validate_relative_destination`) from inside `root`, whose real path must
/// still be `bound_root`, at most `max_bytes`. Every folder and the file are
/// opened relative to their parent's handle without following a reparse
/// point, and nothing is created: a junction or symlink anywhere below the
/// folder refuses the read instead of redirecting it, and so does a file
/// with more than one hard link (another name, possibly outside the folder,
/// for the same content).
pub(crate) fn read(
    root: &Path,
    bound_root: &str,
    relative: &str,
    max_bytes: u64,
) -> Result<Vec<u8>, HostError> {
    use std::io::Read;
    use std::os::windows::fs::OpenOptionsExt;
    let parts: Vec<&str> = relative.split(['/', '\\']).collect();
    let Some((file_name, folders)) = parts.split_last() else {
        return Err(HostError::Invalid("the source has no file name".into()));
    };
    let root_handle: OwnedHandle = std::fs::OpenOptions::new()
        .access_mode(FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES | SYNCHRONIZE)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(root)
        .map_err(|err| HostError::Invalid(format!("the approved folder cannot be held: {err}")))?
        .into();
    let real_root = final_path(root_handle.as_raw_handle())?;
    if real_root.as_os_str() != std::ffi::OsStr::new(bound_root) {
        return Err(HostError::Invalid(
            "the approved folder changed since it was approved".into(),
        ));
    }
    let mut held: Vec<OwnedHandle> = Vec::with_capacity(folders.len());
    for folder in folders {
        let parent = held
            .last()
            .map_or(root_handle.as_raw_handle(), AsRawHandle::as_raw_handle);
        held.push(open_relative(
            parent,
            folder,
            FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_ATTRIBUTE_NORMAL,
            FILE_OPEN,
            FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        )?);
    }
    let folder = held
        .last()
        .map_or(root_handle.as_raw_handle(), AsRawHandle::as_raw_handle);
    let file = open_relative(
        folder,
        file_name,
        FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        FILE_SHARE_READ,
        FILE_ATTRIBUTE_NORMAL,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
    )?;
    // SAFETY: an all-zero BY_HANDLE_FILE_INFORMATION is a valid initial
    // value; `file` is an open file handle this function holds.
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: `file` is a valid handle and `info` a writable output.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle() as HANDLE, &mut info) } == 0 {
        return Err(HostError::Platform(format!(
            "upload source: {}",
            std::io::Error::last_os_error()
        )));
    }
    if info.nNumberOfLinks != 1 {
        return Err(HostError::Invalid(
            "the file has more than one hard link (another name may lie outside the approved folder)"
                .into(),
        ));
    }
    let mut content = Vec::new();
    File::from(file)
        .take(max_bytes + 1)
        .read_to_end(&mut content)
        .map_err(|err| HostError::Platform(format!("upload source: {err}")))?;
    if content.len() as u64 > max_bytes {
        return Err(HostError::Invalid(
            "the file is larger than the transfer bound".into(),
        ));
    }
    Ok(content)
}

pub(crate) fn staged_name_for(file_name: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(file_name.to_lowercase().as_bytes());
    let hex: String = digest[..8].iter().map(|b| format!("{b:02x}")).collect();
    format!(".orcel-dl-{hex}.part")
}

/// Remove a leftover temporary file of an earlier, unfinished commit. It is
/// opened exclusively, without following a reparse point: a commit still in
/// progress holds its file exclusively, so it is never removed under it.
fn remove_stale(folder: RawHandle, staged_name: &str) -> Result<(), HostError> {
    let stale = open_relative(
        folder,
        staged_name,
        DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        0,
        FILE_ATTRIBUTE_NORMAL,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
    )
    .map_err(|error| match error {
        // Held without sharing: a commit (or another reader) has it open.
        HostError::Platform(detail) if detail.contains("0xc0000043") => HostError::Invalid(
            "another commit to this destination is in progress, or its leftover is in use".into(),
        ),
        _ => HostError::Invalid(format!(
            "a leftover temporary file for this destination cannot be removed ({error})"
        )),
    })?;
    set_delete_on_close(stale.as_raw_handle(), true).map_err(|_| {
        HostError::Invalid(
            "a leftover temporary file for this destination cannot be removed (read-only?)".into(),
        )
    })?;
    drop(stale);
    Ok(())
}

/// Test-only crash points: a child test process told to stop at `stage`
/// signals it and waits there to be killed (#309; the test is in
/// worker_launch_tests.rs, where test process spawning lives). Absent from product
/// builds.
#[cfg(test)]
fn crash_point(stage: &str) {
    if std::env::var("ORCEL_309_CRASH_AT").as_deref() == Ok(stage) {
        if let Ok(marker) = std::env::var("ORCEL_309_MARKER") {
            let _ = std::fs::write(marker, stage);
        }
        // Killed by the parent; never outlives it by more than two minutes.
        std::thread::sleep(std::time::Duration::from_secs(120));
        std::process::exit(3);
    }
}

#[cfg(not(test))]
fn crash_point(_stage: &str) {}

/// The staged file; unless `keep` is set, dropping it marks the file for
/// deletion, so it goes away when its handle closes.
struct Staged {
    file: File,
    keep: bool,
}

impl Staged {
    fn raw(&self) -> RawHandle {
        self.file.as_raw_handle()
    }
}

impl Drop for Staged {
    fn drop(&mut self) {
        if !self.keep {
            let _ = set_delete_on_close(self.raw(), true);
        }
    }
}

fn set_attributes(file: RawHandle, attributes: u32) -> Result<(), HostError> {
    // Zero times leave the file's timestamps unchanged.
    let info = FILE_BASIC_INFO {
        CreationTime: 0,
        LastAccessTime: 0,
        LastWriteTime: 0,
        ChangeTime: 0,
        FileAttributes: attributes,
    };
    // SAFETY: `file` is an open handle with FILE_WRITE_ATTRIBUTES access;
    // `info` is a valid FILE_BASIC_INFO for the size given.
    let ok = unsafe {
        SetFileInformationByHandle(
            file as HANDLE,
            FileBasicInfo,
            (&info as *const FILE_BASIC_INFO).cast(),
            std::mem::size_of::<FILE_BASIC_INFO>() as u32,
        )
    };
    if ok == 0 {
        return Err(HostError::Platform("destination attributes".into()));
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_WRITE,
    };
    use windows_sys::Win32::System::IO::DeviceIoControl;

    const FSCTL_SET_REPARSE_POINT: u32 = 0x0009_00A4;
    const IO_REPARSE_TAG_MOUNT_POINT: u32 = 0xA000_0003;

    pub(crate) fn scratch(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "orcel-307-{label}-{}-{:x}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    pub(crate) fn bound(root: &Path) -> String {
        std::fs::canonicalize(root)
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned()
    }

    /// Make `link` (an empty folder) a junction to `target`, with
    /// `FSCTL_SET_REPARSE_POINT` (no shell, no `mklink`).
    pub(crate) fn junction(link: &Path, target: &Path) {
        std::fs::create_dir(link).unwrap();
        let target = std::fs::canonicalize(target).unwrap();
        let plain = target
            .to_str()
            .unwrap()
            .trim_start_matches(r"\\?\")
            .to_owned();
        let substitute = wide(&format!(r"\??\{plain}"));
        let print = wide(&plain);
        let mut path_buffer: Vec<u16> = Vec::new();
        path_buffer.extend(&substitute);
        path_buffer.push(0);
        path_buffer.extend(&print);
        path_buffer.push(0);
        let mut data: Vec<u8> = Vec::new();
        let data_length = (8 + path_buffer.len() * 2) as u16;
        data.extend(IO_REPARSE_TAG_MOUNT_POINT.to_le_bytes());
        data.extend(data_length.to_le_bytes());
        data.extend(0u16.to_le_bytes());
        data.extend(0u16.to_le_bytes());
        data.extend(((substitute.len() * 2) as u16).to_le_bytes());
        data.extend((((substitute.len() + 1) * 2) as u16).to_le_bytes());
        data.extend(((print.len() * 2) as u16).to_le_bytes());
        for unit in path_buffer {
            data.extend(unit.to_le_bytes());
        }
        let handle: OwnedHandle = std::fs::OpenOptions::new()
            .access_mode(FILE_GENERIC_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(link)
            .unwrap()
            .into();
        let mut returned = 0u32;
        // SAFETY: `handle` is an open directory handle; `data` is a
        // complete mount-point REPARSE_DATA_BUFFER of the length given.
        let ok = unsafe {
            DeviceIoControl(
                handle.as_raw_handle() as HANDLE,
                FSCTL_SET_REPARSE_POINT,
                data.as_ptr().cast(),
                data.len() as u32,
                std::ptr::null_mut(),
                0,
                &mut returned,
                std::ptr::null_mut(),
            )
        };
        assert_ne!(ok, 0, "junction: {}", std::io::Error::last_os_error());
    }

    use std::os::windows::fs::OpenOptionsExt;

    #[test]
    fn a_file_is_committed_create_only_inside_the_held_folder() {
        let root = scratch("plain");
        let path = commit(&root, &bound(&root), "reports\\2026\\r.pdf", b"%PDF-1.4").unwrap();
        assert_eq!(
            path,
            std::fs::canonicalize(root.join("reports\\2026\\r.pdf")).unwrap()
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"%PDF-1.4");
        // An ordinary file: neither hidden nor temporary.
        use std::os::windows::fs::MetadataExt;
        let attributes = std::fs::metadata(&path).unwrap().file_attributes();
        assert_eq!(
            attributes & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_TEMPORARY),
            0,
            "{attributes:#x}"
        );
        assert!(matches!(
            commit(&root, &bound(&root), "reports\\2026\\r.pdf", b"other"),
            Err(HostError::Invalid(message)) if message.contains("create-only")
        ));
        assert_eq!(std::fs::read(&path).unwrap(), b"%PDF-1.4");
        // No staged file is left behind, whatever the outcome.
        let names: Vec<String> = std::fs::read_dir(root.join("reports\\2026"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, ["r.pdf"]);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_junction_anywhere_below_the_folder_refuses_the_write() {
        let root = scratch("junction-root");
        let outside = scratch("junction-outside");
        junction(&root.join("link"), &outside);
        assert!(matches!(
            commit(&root, &bound(&root), "link\\r.pdf", b"%PDF-1.4"),
            Err(HostError::Invalid(message)) if message.contains("a reparse point below it")
        ));
        assert!(
            std::fs::read_dir(&outside).unwrap().next().is_none(),
            "nothing may be written behind the junction"
        );
        // A junction deeper down is refused the same way, and the same
        // folder accepts a write that does not pass through it.
        std::fs::create_dir_all(root.join("a\\b")).unwrap();
        junction(&root.join("a\\b\\c"), &outside);
        assert!(matches!(
            commit(&root, &bound(&root), "a\\b\\c\\r.pdf", b"x"),
            Err(HostError::Invalid(message)) if message.contains("a reparse point below it")
        ));
        commit(&root, &bound(&root), "a\\b\\ok.pdf", b"x").unwrap();
        assert!(std::fs::read_dir(&outside).unwrap().next().is_none());
        std::fs::remove_dir(root.join("link")).unwrap();
        std::fs::remove_dir(root.join("a\\b\\c")).unwrap();
        std::fs::remove_dir_all(&root).unwrap();
        std::fs::remove_dir_all(&outside).unwrap();
    }

    /// BR-03: an upload source is read from inside the approved folder only:
    /// never through a junction below it, never past the bound.
    #[test]
    fn br03_an_upload_source_is_read_without_following_a_junction() {
        let root = scratch("read-root");
        let outside = scratch("read-outside");
        std::fs::create_dir_all(root.join("docs")).unwrap();
        std::fs::write(root.join("docs\\report.txt"), b"orcel-upload-bytes").unwrap();
        assert_eq!(
            read(&root, &bound(&root), "docs\\report.txt", 1024).unwrap(),
            b"orcel-upload-bytes"
        );
        std::fs::write(outside.join("secret.txt"), b"outside").unwrap();
        junction(&root.join("link"), &outside);
        assert!(matches!(
            read(&root, &bound(&root), "link\\secret.txt", 1024),
            Err(HostError::Invalid(message)) if message.contains("reparse point")
        ));
        assert!(matches!(
            read(&root, &bound(&root), "docs\\missing.txt", 1024),
            Err(HostError::Invalid(message)) if message.contains("does not exist")
        ));
        assert!(matches!(
            read(&root, &bound(&root), "docs\\report.txt", 4),
            Err(HostError::Invalid(message)) if message.contains("larger than")
        ));
        std::fs::remove_dir(root.join("link")).unwrap();
        // A hard link to a file outside the folder is refused too.
        std::fs::hard_link(outside.join("secret.txt"), root.join("docs\\linked.txt")).unwrap();
        assert!(matches!(
            read(&root, &bound(&root), "docs\\linked.txt", 1024),
            Err(HostError::Invalid(message)) if message.contains("hard link")
        ));
        // A root retargeted after it was approved is refused.
        let parent = scratch("read-parent");
        let chosen = parent.join("chosen");
        junction(&chosen, &root);
        let approved = bound(&chosen);
        std::fs::remove_dir(&chosen).unwrap();
        junction(&chosen, &outside);
        assert!(matches!(
            read(&chosen, &approved, "secret.txt", 1024),
            Err(HostError::Invalid(message)) if message.contains("changed")
        ));
        std::fs::remove_dir(&chosen).unwrap();
        std::fs::remove_dir_all(&parent).unwrap();
        std::fs::remove_dir_all(&root).unwrap();
        std::fs::remove_dir_all(&outside).unwrap();
    }

    #[test]
    fn a_folder_retargeted_after_approval_is_refused() {
        // The approval named one real folder; at commit the path leads to
        // another (a junction retargeted in between).
        let approved = scratch("approved");
        let other = scratch("other");
        let parent = scratch("parent");
        let path = parent.join("chosen");
        junction(&path, &approved);
        let bound_root = bound(&path);
        std::fs::remove_dir(&path).unwrap();
        junction(&path, &other);
        assert!(matches!(
            commit(&path, &bound_root, "r.pdf", b"%PDF-1.4"),
            Err(HostError::Invalid(message)) if message.contains("changed")
        ));
        assert!(std::fs::read_dir(&other).unwrap().next().is_none());
        assert!(std::fs::read_dir(&approved).unwrap().next().is_none());
        std::fs::remove_dir(&path).unwrap();
        for folder in [approved, other, parent] {
            std::fs::remove_dir_all(folder).unwrap();
        }
    }

    #[test]
    fn the_held_folder_cannot_be_swapped_while_the_commit_holds_it() {
        // While the folder's handle is held without delete sharing, it can
        // be neither renamed nor removed.
        let parent = scratch("hold");
        let root = parent.join("approved");
        std::fs::create_dir(&root).unwrap();
        let held: OwnedHandle = std::fs::OpenOptions::new()
            .access_mode(FOLDER_ACCESS)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(&root)
            .unwrap()
            .into();
        assert!(std::fs::rename(&root, parent.join("moved")).is_err());
        assert!(std::fs::remove_dir(&root).is_err());
        drop(held);
        std::fs::rename(&root, parent.join("moved")).unwrap();
        std::fs::remove_dir_all(&parent).unwrap();
    }

    pub(crate) fn names(folder: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(folder)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn a_commit_in_progress_is_never_removed_as_a_leftover() {
        // A live commit holds its temporary file exclusively: a second
        // commit to the same destination is refused, not removed under it.
        let root = scratch("in-progress");
        let folder: OwnedHandle = std::fs::OpenOptions::new()
            .access_mode(FOLDER_ACCESS)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(&root)
            .unwrap()
            .into();
        let held = open_relative(
            folder.as_raw_handle(),
            &staged_name_for("r.pdf"),
            FILE_WRITE_DATA | DELETE | SYNCHRONIZE,
            0,
            FILE_ATTRIBUTE_HIDDEN,
            FILE_CREATE,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        )
        .unwrap();
        assert!(matches!(
            commit(&root, &bound(&root), "r.pdf", b"x"),
            Err(HostError::Invalid(message)) if message.contains("in progress")
        ));
        assert!(!root.join("r.pdf").exists());
        drop(held);
        drop(folder);
        // Released, it is a leftover: the next commit removes it.
        commit(&root, &bound(&root), "r.pdf", b"x").unwrap();
        assert_eq!(names(&root), ["r.pdf"]);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_file_where_a_folder_should_be_refuses_the_write() {
        let root = scratch("not-a-folder");
        std::fs::write(root.join("reports"), b"x").unwrap();
        assert!(matches!(
            commit(&root, &bound(&root), "reports\\r.pdf", b"%PDF-1.4"),
            Err(HostError::Invalid(message)) if message.contains("not a folder")
        ));
        assert_eq!(std::fs::read(root.join("reports")).unwrap(), b"x");
        std::fs::remove_dir_all(&root).unwrap();
    }
}
