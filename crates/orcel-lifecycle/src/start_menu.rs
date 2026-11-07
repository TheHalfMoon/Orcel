//! The Start Menu entry that opens the app, so a person doesn't need to know `orcel app`.
//!
//! It points at `bin\\orcel.exe app` and not at the app itself, whose path changes with each
//! version. That's a console program, so the entry starts it minimized. The entry grants nothing:
//! the app starts `orcel` from the install, and approvals are `orceld`'s.

use crate::LifecycleError;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use windows::core::{Interface, PCWSTR};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoTaskMemFree, CoUninitialize, IPersistFile,
    CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, STGM_READ,
};
use windows::Win32::UI::Shell::{
    FOLDERID_Programs, IShellLinkW, SHGetKnownFolderPath, ShellLink, KF_FLAG_DEFAULT,
};
use windows::Win32::UI::WindowsAndMessaging::SW_SHOWMINNOACTIVE;

const ARGUMENTS: &str = "app";
const DESCRIPTION: &str = "Open Orcel";

fn wide(text: &std::ffi::OsStr) -> Vec<u16> {
    text.encode_wide().chain(Some(0)).collect()
}

fn failure(action: &str, error: impl std::fmt::Display) -> LifecycleError {
    LifecycleError::platform(format!("{action}: {error}"))
}

/// COM for this thread while it's in scope. Undone only if this call started it.
struct Com(bool);

impl Com {
    fn start() -> Self {
        // SAFETY: no reserved pointer. A thread already in COM reports that, and keeps its mode.
        Self(unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) }.is_ok())
    }
}

impl Drop for Com {
    fn drop(&mut self) {
        if self.0 {
            // SAFETY: balances the successful CoInitializeEx on this thread.
            unsafe { CoUninitialize() };
        }
    }
}

/// This user's Start Menu programs folder.
pub fn programs_folder() -> Result<PathBuf, LifecycleError> {
    // SAFETY: the id is a valid constant and no token means the current user. On success the
    // result is a NUL-terminated string, copied, and freed once.
    unsafe {
        let text = SHGetKnownFolderPath(&FOLDERID_Programs, KF_FLAG_DEFAULT, None)
            .map_err(|error| failure("find the Start Menu", error))?;
        let path = PathBuf::from(std::ffi::OsString::from_wide(text.as_wide()));
        CoTaskMemFree(Some(text.0.cast()));
        Ok(path)
    }
}

/// Writes the entry at `path`, replacing one that's there.
pub fn write_entry(path: &Path, cli: &Path) -> Result<(), LifecycleError> {
    let _com = Com::start();
    let target = wide(cli.as_os_str());
    let arguments = wide(ARGUMENTS.as_ref());
    let description = wide(DESCRIPTION.as_ref());
    let file = wide(path.as_os_str());
    // SAFETY: COM is started for this thread, and every string is NUL-terminated and outlives the
    // call that takes it.
    unsafe {
        let link: IShellLinkW = CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER)
            .map_err(|error| failure("create a shortcut", error))?;
        link.SetPath(PCWSTR(target.as_ptr()))
            .map_err(|error| failure("set the shortcut's target", error))?;
        link.SetArguments(PCWSTR(arguments.as_ptr()))
            .map_err(|error| failure("set the shortcut's arguments", error))?;
        link.SetDescription(PCWSTR(description.as_ptr()))
            .map_err(|error| failure("describe the shortcut", error))?;
        link.SetShowCmd(SW_SHOWMINNOACTIVE)
            .map_err(|error| failure("set how the shortcut opens", error))?;
        link.cast::<IPersistFile>()
            .map_err(|error| failure("save the shortcut", error))?
            .Save(PCWSTR(file.as_ptr()), true)
            .map_err(|error| failure("save the shortcut", error))
    }
}

/// The target and arguments of the entry at `path`.
pub fn read_entry(path: &Path) -> Result<(PathBuf, String), LifecycleError> {
    let _com = Com::start();
    let file = wide(path.as_os_str());
    // SAFETY: as for `write_entry`. The buffers are written within their stated lengths, and the
    // null find-data pointer is allowed.
    unsafe {
        let link: IShellLinkW = CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER)
            .map_err(|error| failure("create a shortcut", error))?;
        link.cast::<IPersistFile>()
            .map_err(|error| failure("read the shortcut", error))?
            .Load(PCWSTR(file.as_ptr()), STGM_READ)
            .map_err(|error| failure("read the shortcut", error))?;
        let mut target = vec![0_u16; 32_768];
        link.GetPath(&mut target, std::ptr::null_mut(), 0)
            .map_err(|error| failure("read the shortcut's target", error))?;
        let mut arguments = vec![0_u16; 1_024];
        link.GetArguments(&mut arguments)
            .map_err(|error| failure("read the shortcut's arguments", error))?;
        let text = |buffer: &[u16]| {
            let end = buffer
                .iter()
                .position(|unit| *unit == 0)
                .unwrap_or(buffer.len());
            std::ffi::OsString::from_wide(&buffer[..end])
        };
        Ok((
            PathBuf::from(text(&target)),
            text(&arguments).to_string_lossy().into_owned(),
        ))
    }
}

/// Removes the entry at `path` if it opens the app through `cli`. A missing one is fine, and one
/// that points elsewhere, or can't be read as a shortcut, isn't Orcel's and stays.
pub fn remove_entry(path: &Path, cli: &Path) -> Result<bool, LifecycleError> {
    if !path.exists() {
        return Ok(false);
    }
    let (target, arguments) = read_entry(path)?;
    if !target.as_os_str().eq_ignore_ascii_case(cli.as_os_str()) || arguments != ARGUMENTS {
        return Ok(false);
    }
    std::fs::remove_file(path).map_err(|error| failure("remove the shortcut", error))?;
    Ok(true)
}
