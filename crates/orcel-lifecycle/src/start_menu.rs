//! The Start Menu entry that opens the app, so a person doesn't need to know `orcel app`.
//!
//! It points at `bin\\orcel.exe app` and not at the app itself, whose path changes with each
//! version. That's a console program, so the entry starts it minimized. The entry grants nothing:
//! the app starts `orcel` from the install, and approvals are `orceld`'s. A minimized console
//! closes with whatever it printed, so `orcel app` shows a failure in a dialog when the entry
//! started it (see [`show_if_no_terminal`]).

use crate::LifecycleError;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use windows::core::{Interface, PCWSTR};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoTaskMemFree, CoUninitialize, IPersistFile,
    CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, STGM_READ,
};
use windows::Win32::UI::Shell::{
    FOLDERID_Programs, IShellLinkW, SHGetKnownFolderPath, ShellLink, KF_FLAG_DEFAULT, SLGP_RAWPATH,
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

/// Writes the entry at `path`. One already there is replaced only if it's Orcel's: a shortcut or
/// file of someone else's under that name stays, and this says so.
pub fn write_entry(path: &Path, cli: &Path) -> Result<(), LifecycleError> {
    if std::fs::symlink_metadata(path).is_ok() {
        let (target, arguments) = read_entry(path)?;
        if !same_path(&target, cli) || arguments != ARGUMENTS {
            return Err(LifecycleError::platform(format!(
                "{} is already there and isn't Orcel's",
                path.display()
            )));
        }
    }
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
        let persist = link
            .cast::<IPersistFile>()
            .map_err(|error| failure("save the shortcut", error))?;
        persist
            .Save(PCWSTR(file.as_ptr()), true)
            .map_err(|error| failure("save the shortcut", error))?;
        // Released here, while COM is still up: a tail expression's temporary would outlive `_com`.
        drop(persist);
        drop(link);
        Ok(())
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
        let persist = link
            .cast::<IPersistFile>()
            .map_err(|error| failure("read the shortcut", error))?;
        persist
            .Load(PCWSTR(file.as_ptr()), STGM_READ)
            .map_err(|error| failure("read the shortcut", error))?;
        drop(persist);
        let mut target = vec![0_u16; 32_768];
        // As stored, not resolved to the form on disk, which could differ from what was written.
        link.GetPath(&mut target, std::ptr::null_mut(), SLGP_RAWPATH.0 as u32)
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
        let read = (
            PathBuf::from(text(&target)),
            text(&arguments).to_string_lossy().into_owned(),
        );
        drop(link);
        Ok(read)
    }
}

/// Shows `message` in a dialog when no terminal will show it: when this process is the only one
/// attached to its console and its standard error is that console, as when the Start Menu entry
/// started it. From a terminal, the shell shares the console, so nothing is shown and the message
/// goes to standard error as usual. A caller that redirects standard error, or asked for JSON,
/// reads the error itself, so a dialog that nobody may be there to close never blocks it. Nor
/// does a session without a visible desktop: a task set to run whether or not the user is logged
/// on, or a service, gets a hidden window station, where a dialog would wait for nobody.
pub fn show_if_no_terminal(message: &str, json: bool) {
    use windows_sys::Win32::System::Console::{
        GetConsoleMode, GetConsoleProcessList, GetStdHandle, STD_ERROR_HANDLE,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        MessageBoxW, MB_ICONERROR, MB_OK, MB_SETFOREGROUND,
    };
    if json || !desktop_is_visible() {
        return;
    }
    let mut mode = 0_u32;
    // SAFETY: GetStdHandle has no preconditions, and GetConsoleMode only writes `mode`; it fails
    // for a handle that isn't a console, such as a pipe, a file or none.
    if unsafe { GetConsoleMode(GetStdHandle(STD_ERROR_HANDLE), &mut mode) } == 0 {
        return;
    }
    let mut processes = [0_u32; 2];
    // SAFETY: the buffer holds two ids and its length says so; the call writes at most that many.
    let attached = unsafe { GetConsoleProcessList(processes.as_mut_ptr(), 2) };
    if attached != 1 {
        return;
    }
    let text = wide(std::ffi::OsStr::new(message));
    let caption = wide(std::ffi::OsStr::new("Orcel"));
    // SAFETY: both strings are NUL-terminated and outlive the call; no owner window is passed.
    unsafe {
        MessageBoxW(
            0,
            text.as_ptr(),
            caption.as_ptr(),
            MB_OK | MB_ICONERROR | MB_SETFOREGROUND,
        );
    }
}

/// Whether this process's window station is the interactive, visible one (`WSF_VISIBLE`). When it
/// can't be told, it's taken as hidden: the message still reaches standard error.
fn desktop_is_visible() -> bool {
    use windows_sys::Win32::System::StationsAndDesktops::{
        GetProcessWindowStation, GetUserObjectInformationW, UOI_FLAGS, USEROBJECTFLAGS,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::WSF_VISIBLE;
    let mut flags = USEROBJECTFLAGS {
        fInherit: 0,
        fReserved: 0,
        dwFlags: 0,
    };
    let mut needed = 0_u32;
    // SAFETY: the station handle belongs to this process and isn't closed here. The call writes at
    // most the stated size of `flags`, which is a `USEROBJECTFLAGS`, and `needed`.
    let read = unsafe {
        let station = GetProcessWindowStation();
        station != 0
            && GetUserObjectInformationW(
                station,
                UOI_FLAGS,
                (&mut flags as *mut USEROBJECTFLAGS).cast(),
                std::mem::size_of::<USEROBJECTFLAGS>() as u32,
                &mut needed,
            ) != 0
    };
    read && flags.dwFlags & WSF_VISIBLE as u32 != 0
}

/// Whether two Windows paths name the same place as written: case and separators aside.
fn same_path(left: &Path, right: &Path) -> bool {
    let normal = |path: &Path| path.to_string_lossy().replace('/', "\\").to_lowercase();
    normal(left) == normal(right)
}

/// Whether the entry at `path` is there and opens the app through `cli`: Orcel's own.
pub fn is_ours(path: &Path, cli: &Path) -> Result<bool, LifecycleError> {
    if std::fs::symlink_metadata(path).is_err() {
        return Ok(false);
    }
    let (target, arguments) = read_entry(path)?;
    Ok(same_path(&target, cli) && arguments == ARGUMENTS)
}

/// Removes the entry at `path` if it opens the app through `cli`. A missing one is fine, and one
/// that points elsewhere, or can't be read as a shortcut, isn't Orcel's and stays.
pub fn remove_entry(path: &Path, cli: &Path) -> Result<bool, LifecycleError> {
    if !path.exists() {
        return Ok(false);
    }
    let (target, arguments) = read_entry(path)?;
    if !same_path(&target, cli) || arguments != ARGUMENTS {
        return Ok(false);
    }
    std::fs::remove_file(path).map_err(|error| failure("remove the shortcut", error))?;
    Ok(true)
}
