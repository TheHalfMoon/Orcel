// SPDX-License-Identifier: MIT
// Portions copyright (c) 2025 Cua AI, Inc.; modifications copyright Orcel.

//! Windows containment.
//!
//! The child runs as an AppContainer (LowBox) identity with no capabilities,
//! inside a private Job Object, on a private desktop, holding exactly three
//! inherited handles.
//!
//! Each piece closes a specific hole:
//!
//! - An AppContainer with an empty capability set is the documented Windows
//!   primitive that denies network access: without `internetClient` or
//!   `privateNetworkClientServer` the token cannot reach the transport stack at
//!   all, and loopback is blocked for AppContainers by default. It also denies
//!   the user profile, the Credential Manager and DPAPI user secrets, because
//!   none of those objects grant the container's SID. The child's executable,
//!   working directory and spec roots are granted to that exact SID and
//!   nothing else is.
//! - `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` replaces `bInheritHandles = TRUE`'s
//!   "every inheritable handle in the helper" with exactly the three stdio
//!   pipes. They are private named pipes so the helper side can stay
//!   asynchronous while the child receives ordinary synchronous stdio handles.
//! - The Job Object carries kill-on-close, an active-process ceiling of one, a
//!   job memory ceiling, a per-process CPU-time ceiling and the full set of UI
//!   restrictions, so the child cannot create a process, read or write the
//!   clipboard, use a USER handle it did not create, switch desktops, or
//!   change system parameters. `JOB_OBJECT_LIMIT_BREAKAWAY_OK` is
//!   deliberately not set.
//! - A private desktop means a screen capture or synthetic input attempt
//!   reaches an empty desktop rather than the user's session.
//!
//! The child is created suspended and is resumed only after the job, the
//! limits, the UI restrictions and every handle boundary are installed, so no
//! child instruction runs before its containment exists. Any failure
//! terminates the suspended process and returns a fail-closed error.
//!
//! Residual risk after a hard kill: if the helper itself is killed (for
//! example `TerminateProcess`) between granting and revoking, the child still
//! dies (closing the job handle kills the job), but the temporary ACEs on the
//! working directory, the spec roots and the executable, and the
//! AppContainer profile, stay behind. Nothing cleans them up on the next
//! launch: the donor's recovery journal was removed with its state
//! directory. The ACEs name a unique AppContainer SID derived from a random,
//! never-disclosed 128-bit profile name, so no later process can hold a
//! token that matches them, and the working directory's protected DACL still
//! admits only the user. Recovery (a journal under the state root, replayed
//! before the next launch) is tracked as follow-up XP-13b.
//!
//! Hard links: every file the grant walk reaches must have exactly one link.
//! A hard link shares its file's security descriptor, so stamping an ACE on
//! `root\x` would also grant whatever outside file `x` is a second name for
//! (say `%USERPROFILE%\.ssh\id_rsa`). A file with more than one link aborts
//! the launch, and the count is read again after the ACE is applied, so a
//! link created between the check and the grant also aborts it and the grant
//! is rolled back. Directories cannot be hard linked.
//!
//! Order matters because `SetSecurityInfo` propagates an inheritable ACE to
//! the existing children at once. A tree is therefore granted in three
//! phases: the walk validates every object (and grants a merged root
//! non-inheritably); then the directories' ACEs become inheritable, parents
//! first, and the private working directory gets its protected DACL; then a
//! last walk refuses the grant if anything in the tree is unledgered or has
//! gained a link. So an unvalidated child never receives a grant, not even
//! for the moment before a rollback that a hard kill could interrupt.
//!
//! Denial of service, by design: a junction, symbolic link or other reparse
//! point anywhere inside a root, or a hard-linked file, makes every later
//! grant of that root refuse to launch until it is removed. Only someone with
//! write access to the root can plant one (a contained child with a writable
//! root included), and the effect is a refusal, never a wider grant. Failing
//! closed is the intended outcome.
//!
//! Provenance (T-CUA-22, COPY_ADAPT): adapted from
//! cua@a802eaf26ca97616a6bf0de6a29729a9346fbb1f
//! `libs/cua-driver/rust/crates/cua-driver-core/src/perception_client/containment/windows.rs`
//! (blob ac9b94724a3a9b0e5f042145446ed021102a6986), MIT; notice in
//! `docs/orcel/notices/cua-MIT.txt`. Orcel's changes:
//! - stderr is a third private pipe in the handle list (the donor gave the
//!   worker the null device), so the helper can relay it, bounded;
//! - the cross-process ACL lease (fs2), the AppContainer recovery journal and
//!   the background ACL reaper are removed: the helper is one-shot and always
//!   finishes teardown synchronously before it exits, aborting if teardown
//!   cannot be proven;
//! - profile, pipe and desktop names use 128 bits from `BCryptGenRandom`
//!   instead of `uuid` v4, under the `ai.orcel.contain` prefix;
//! - the executable is granted as one exact file instead of through its
//!   directory;
//! - `tracing` diagnostics are dropped (the helper has no log sink);
//! - `spawn_named` takes the profile name so a profile that cannot be
//!   created is a testable refusal; the unit tests moved to
//!   `windows_tests.rs`.

use std::ffi::{c_void, OsStr};
use std::os::windows::ffi::{OsStrExt as _, OsStringExt as _};
use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::net::windows::named_pipe::{NamedPipeServer, PipeMode, ServerOptions};

use crate::containment::{
    containment_error, os_detail, spawn_error, ContainError, ContainedChild, ContainmentLimits,
    FilesystemBoundary, RawExit, MAX_PROCESSES,
};

pub(crate) type ChildStdin = NamedPipeServer;
pub(crate) type ChildStdout = NamedPipeServer;
pub(crate) type ChildStderr = NamedPipeServer;

/// `BCRYPT_USE_SYSTEM_PREFERRED_RNG`.
const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x0000_0002;

type Handle = *mut c_void;
type Bool = i32;

const FALSE: Bool = 0;
const TRUE: Bool = 1;
const INFINITE: u32 = 0xFFFF_FFFF;
const WAIT_OBJECT_0: u32 = 0;
#[cfg(test)]
const WAIT_TIMEOUT: u32 = 258;
const WAIT_FAILED: u32 = 0xFFFF_FFFF;
const DUPLICATE_SAME_ACCESS: u32 = 0x0000_0002;
const PROCESS_REAP_GRACE_MILLIS: u32 = 5_000;
const CLEANUP_RETRY_INTERVAL: Duration = Duration::from_millis(100);
const CLEANUP_MAX_RETRY_INTERVAL: Duration = Duration::from_secs(5);
const CLEANUP_WAIT_FAILURE_ATTEMPTS: usize = 3;
const CLEANUP_AUTHORITY_FAILURE_ATTEMPTS: usize = 3;

const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const GENERIC_EXECUTE: u32 = 0x2000_0000;
const GENERIC_ALL: u32 = 0x1000_0000;
const FILE_READ_DATA: u32 = 0x0000_0001;
const READ_CONTROL: u32 = 0x0002_0000;
const WRITE_DAC: u32 = 0x0004_0000;
const OPEN_EXISTING: u32 = 3;
const FILE_SHARE_READ: u32 = 0x0000_0001;
const FILE_SHARE_WRITE: u32 = 0x0000_0002;
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
const FILE_ATTRIBUTE_TAG_INFO_CLASS: u32 = 9;
const FILE_NAME_NORMALIZED: u32 = 0;

const CREATE_SUSPENDED: u32 = 0x0000_0004;
const CREATE_UNICODE_ENVIRONMENT: u32 = 0x0000_0400;
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const EXTENDED_STARTUPINFO_PRESENT: u32 = 0x0008_0000;
const STARTF_USESTDHANDLES: u32 = 0x0000_0100;
const STARTF_USESHOWWINDOW: u32 = 0x0000_0001;
const SW_HIDE: u16 = 0;

const PROC_THREAD_ATTRIBUTE_HANDLE_LIST: usize = 0x0002_0002;
const PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES: usize = 0x0002_0009;

const JOB_OBJECT_LIMIT_PROCESS_TIME: u32 = 0x0000_0002;
const JOB_OBJECT_LIMIT_ACTIVE_PROCESS: u32 = 0x0000_0008;
const JOB_OBJECT_LIMIT_JOB_MEMORY: u32 = 0x0000_0200;
const JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION: u32 = 0x0000_0400;
const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: u32 = 0x0000_2000;

const JOB_OBJECT_BASIC_UI_RESTRICTIONS: u32 = 4;
const JOB_OBJECT_EXTENDED_LIMIT_INFORMATION: u32 = 9;

const JOB_OBJECT_UILIMIT_HANDLES: u32 = 0x0000_0001;
const JOB_OBJECT_UILIMIT_READCLIPBOARD: u32 = 0x0000_0002;
const JOB_OBJECT_UILIMIT_WRITECLIPBOARD: u32 = 0x0000_0004;
const JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS: u32 = 0x0000_0008;
const JOB_OBJECT_UILIMIT_DISPLAYSETTINGS: u32 = 0x0000_0010;
const JOB_OBJECT_UILIMIT_GLOBALATOMS: u32 = 0x0000_0020;
const JOB_OBJECT_UILIMIT_DESKTOP: u32 = 0x0000_0040;
const JOB_OBJECT_UILIMIT_EXITWINDOWS: u32 = 0x0000_0080;

/// Every UI restriction a Job Object can impose.
const JOB_OBJECT_UILIMIT_ALL: u32 = JOB_OBJECT_UILIMIT_HANDLES
    | JOB_OBJECT_UILIMIT_READCLIPBOARD
    | JOB_OBJECT_UILIMIT_WRITECLIPBOARD
    | JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS
    | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS
    | JOB_OBJECT_UILIMIT_GLOBALATOMS
    | JOB_OBJECT_UILIMIT_DESKTOP
    | JOB_OBJECT_UILIMIT_EXITWINDOWS;

const SECURITY_DESCRIPTOR_REVISION: u32 = 1;
const DACL_SECURITY_INFORMATION: u32 = 0x0000_0004;
const UNPROTECTED_DACL_SECURITY_INFORMATION: u32 = 0x2000_0000;
const PROTECTED_DACL_SECURITY_INFORMATION: u32 = 0x8000_0000;
const SE_FILE_OBJECT: u32 = 1;
const TOKEN_QUERY: u32 = 0x0008;
const TOKEN_USER_CLASS: u32 = 1;

const TRUSTEE_IS_SID: u32 = 0;
const TRUSTEE_IS_UNKNOWN: u32 = 0;
const NO_MULTIPLE_TRUSTEE: u32 = 0;
const GRANT_ACCESS: u32 = 1;
const NO_INHERITANCE: u32 = 0x0;
const SUB_CONTAINERS_AND_OBJECTS_INHERIT: u32 = 0x3;

const ERROR_SUCCESS: u32 = 0;
const ERROR_INSUFFICIENT_BUFFER: i32 = 122;
/// The rights a child needs on its private desktop: it may create its own
/// windows and read its own desktop, but never record or play back journal
/// input, hook another thread, or switch the session to another desktop.
const DESKTOP_CHILD_ACCESS: u32 = 0x0001 | 0x0002 | 0x0004 | 0x0080;

/// Exit statuses that mean a containment ceiling ended the child rather than a
/// fault in its own code.
const RESOURCE_LIMIT_EXITS: &[u32] = &[
    0xC000_0017, // STATUS_NO_MEMORY
    0xC000_0044, // STATUS_QUOTA_EXCEEDED
    0xC000_009A, // STATUS_INSUFFICIENT_RESOURCES
    0xC000_012D, // STATUS_COMMITMENT_LIMIT
];

/// `ai.orcel.contain.` plus 32 hex digits is 49 UTF-16 units, inside the
/// 64-unit Windows limit.
const APP_CONTAINER_NAME_PREFIX: &str = "ai.orcel.contain";
const APP_CONTAINER_DISPLAY_NAME: &str = "Orcel contained process";
const APP_CONTAINER_DESCRIPTION: &str =
    "Capability-less identity for one run of Orcel's contained execution tier.";

// Every type below mirrors a Win32 layout. Fields the operating system fills in
// are declared for correct size and offset even where this module never reads
// them, so the layouts are allowed to carry unread members.
#[allow(dead_code)]
#[repr(C)]
struct SecurityAttributes {
    length: u32,
    security_descriptor: *mut c_void,
    inherit_handle: Bool,
}

/// A `SECURITY_DESCRIPTOR` in absolute form. The Win32 minimum is 40 bytes on a
/// 64-bit target; 64 pointer-aligned bytes is comfortably above it.
#[repr(C, align(8))]
struct SecurityDescriptorStorage([u8; 64]);

#[allow(dead_code)]
#[repr(C)]
struct StartupInfoW {
    cb: u32,
    reserved: *mut u16,
    desktop: *mut u16,
    title: *mut u16,
    x: u32,
    y: u32,
    x_size: u32,
    y_size: u32,
    x_count_chars: u32,
    y_count_chars: u32,
    fill_attribute: u32,
    flags: u32,
    show_window: u16,
    reserved2_size: u16,
    reserved2: *mut u8,
    std_input: Handle,
    std_output: Handle,
    std_error: Handle,
}

#[allow(dead_code)]
#[repr(C)]
struct StartupInfoExW {
    startup_info: StartupInfoW,
    attribute_list: *mut c_void,
}

#[allow(dead_code)]
#[repr(C)]
struct ProcessInformation {
    process: Handle,
    thread: Handle,
    process_id: u32,
    thread_id: u32,
}

#[allow(dead_code)]
#[repr(C)]
struct IoCounters {
    read_operation_count: u64,
    write_operation_count: u64,
    other_operation_count: u64,
    read_transfer_count: u64,
    write_transfer_count: u64,
    other_transfer_count: u64,
}

#[allow(dead_code)]
#[repr(C)]
struct JobBasicLimitInformation {
    per_process_user_time_limit: i64,
    per_job_user_time_limit: i64,
    limit_flags: u32,
    minimum_working_set_size: usize,
    maximum_working_set_size: usize,
    active_process_limit: u32,
    affinity: usize,
    priority_class: u32,
    scheduling_class: u32,
}

#[allow(dead_code)]
#[repr(C)]
struct JobExtendedLimitInformation {
    basic_limit_information: JobBasicLimitInformation,
    io_info: IoCounters,
    process_memory_limit: usize,
    job_memory_limit: usize,
    peak_process_memory_used: usize,
    peak_job_memory_used: usize,
}

#[allow(dead_code)]
#[repr(C)]
struct JobBasicUiRestrictions {
    ui_restrictions_class: u32,
}

#[allow(dead_code)]
#[repr(C)]
struct SecurityCapabilities {
    app_container_sid: *mut c_void,
    capabilities: *mut c_void,
    capability_count: u32,
    reserved: u32,
}

#[allow(dead_code)]
#[repr(C)]
struct SidAndAttributes {
    sid: *mut c_void,
    attributes: u32,
}

#[allow(dead_code)]
#[repr(C)]
struct TokenUserInformation {
    user: SidAndAttributes,
}

#[allow(dead_code)]
#[repr(C)]
struct TrusteeW {
    multiple_trustee: *mut c_void,
    multiple_trustee_operation: u32,
    trustee_form: u32,
    trustee_type: u32,
    name: *mut u16,
}

#[allow(dead_code)]
#[repr(C)]
struct ExplicitAccessW {
    access_permissions: u32,
    access_mode: u32,
    inheritance: u32,
    trustee: TrusteeW,
}

#[repr(C)]
struct FileAttributeTagInfo {
    file_attributes: u32,
    reparse_tag: u32,
}

#[allow(dead_code)]
#[repr(C)]
struct FileTime {
    low_date_time: u32,
    high_date_time: u32,
}

#[allow(dead_code)]
#[repr(C)]
struct ByHandleFileInformation {
    file_attributes: u32,
    creation_time: FileTime,
    last_access_time: FileTime,
    last_write_time: FileTime,
    volume_serial_number: u32,
    file_size_high: u32,
    file_size_low: u32,
    number_of_links: u32,
    file_index_high: u32,
    file_index_low: u32,
}

#[link(name = "kernel32")]
extern "system" {
    fn CloseHandle(object: Handle) -> Bool;
    fn CreateFileW(
        file_name: *const u16,
        desired_access: u32,
        share_mode: u32,
        security_attributes: *const SecurityAttributes,
        creation_disposition: u32,
        flags_and_attributes: u32,
        template_file: Handle,
    ) -> Handle;
    fn CreateProcessW(
        application_name: *const u16,
        command_line: *mut u16,
        process_attributes: *const SecurityAttributes,
        thread_attributes: *const SecurityAttributes,
        inherit_handles: Bool,
        creation_flags: u32,
        environment: *const c_void,
        current_directory: *const u16,
        startup_info: *const StartupInfoW,
        process_information: *mut ProcessInformation,
    ) -> Bool;
    fn ResumeThread(thread: Handle) -> u32;
    fn TerminateProcess(process: Handle, exit_code: u32) -> Bool;
    fn WaitForSingleObject(object: Handle, milliseconds: u32) -> u32;
    fn GetExitCodeProcess(process: Handle, exit_code: *mut u32) -> Bool;
    fn GetCurrentProcess() -> Handle;
    fn DuplicateHandle(
        source_process: Handle,
        source: Handle,
        target_process: Handle,
        target: *mut Handle,
        desired_access: u32,
        inherit_handle: Bool,
        options: u32,
    ) -> Bool;
    fn GetSystemWindowsDirectoryW(buffer: *mut u16, size: u32) -> u32;
    fn GetFinalPathNameByHandleW(file: Handle, path: *mut u16, path_size: u32, flags: u32) -> u32;
    fn GetFileInformationByHandleEx(
        file: Handle,
        information_class: u32,
        information: *mut c_void,
        size: u32,
    ) -> Bool;
    fn GetFileInformationByHandle(file: Handle, information: *mut ByHandleFileInformation) -> Bool;
    fn CreateJobObjectW(attributes: *const SecurityAttributes, name: *const u16) -> Handle;
    fn SetInformationJobObject(
        job: Handle,
        class: u32,
        information: *const c_void,
        length: u32,
    ) -> Bool;
    fn AssignProcessToJobObject(job: Handle, process: Handle) -> Bool;
    fn TerminateJobObject(job: Handle, exit_code: u32) -> Bool;
    fn InitializeProcThreadAttributeList(
        list: *mut c_void,
        attribute_count: u32,
        flags: u32,
        size: *mut usize,
    ) -> Bool;
    fn UpdateProcThreadAttribute(
        list: *mut c_void,
        flags: u32,
        attribute: usize,
        value: *mut c_void,
        size: usize,
        previous_value: *mut c_void,
        return_size: *mut usize,
    ) -> Bool;
    fn DeleteProcThreadAttributeList(list: *mut c_void);
    fn LocalFree(memory: *mut c_void) -> *mut c_void;
}

#[link(name = "advapi32")]
extern "system" {
    fn OpenProcessToken(process: Handle, desired_access: u32, token: *mut Handle) -> Bool;
    fn GetTokenInformation(
        token: Handle,
        class: u32,
        information: *mut c_void,
        length: u32,
        return_length: *mut u32,
    ) -> Bool;
    fn InitializeSecurityDescriptor(descriptor: *mut c_void, revision: u32) -> Bool;
    fn SetSecurityDescriptorDacl(
        descriptor: *mut c_void,
        dacl_present: Bool,
        dacl: *mut c_void,
        dacl_defaulted: Bool,
    ) -> Bool;
    fn GetSecurityDescriptorControl(
        descriptor: *mut c_void,
        control: *mut u16,
        revision: *mut u32,
    ) -> Bool;
    fn SetEntriesInAclW(
        count: u32,
        entries: *mut ExplicitAccessW,
        old_acl: *mut c_void,
        new_acl: *mut *mut c_void,
    ) -> u32;
    fn GetSecurityInfo(
        object: Handle,
        object_type: u32,
        security_information: u32,
        owner: *mut *mut c_void,
        group: *mut *mut c_void,
        dacl: *mut *mut c_void,
        sacl: *mut *mut c_void,
        security_descriptor: *mut *mut c_void,
    ) -> u32;
    fn SetSecurityInfo(
        object: Handle,
        object_type: u32,
        security_information: u32,
        owner: *mut c_void,
        group: *mut c_void,
        dacl: *mut c_void,
        sacl: *mut c_void,
    ) -> u32;
    fn FreeSid(sid: *mut c_void) -> *mut c_void;
}

#[link(name = "user32")]
extern "system" {
    fn CreateDesktopW(
        desktop: *const u16,
        device: *const u16,
        devmode: *mut c_void,
        flags: u32,
        desired_access: u32,
        attributes: *const SecurityAttributes,
    ) -> Handle;
    fn CloseDesktop(desktop: Handle) -> Bool;
}

#[link(name = "bcrypt")]
extern "system" {
    fn BCryptGenRandom(algorithm: Handle, buffer: *mut u8, length: u32, flags: u32) -> i32;
}

#[link(name = "userenv")]
extern "system" {
    fn CreateAppContainerProfile(
        name: *const u16,
        display_name: *const u16,
        description: *const u16,
        capabilities: *mut c_void,
        capability_count: u32,
        sid: *mut *mut c_void,
    ) -> i32;
    fn DeleteAppContainerProfile(name: *const u16) -> i32;
}

/// Owns the job, primary-process duplicate, private desktop and temporary
/// filesystem grants. Drop terminates the job, waits for the process within a
/// bounded grace period, then revokes every grant and deletes the
/// AppContainer profile before the helper exits. The helper is one-shot, so
/// cleanup is always synchronous: there is no background reaper to outlive.
/// Kernel handles are stored as `isize` so the guard stays `Send`.
pub(crate) struct Guard {
    job: isize,
    desktop: isize,
    cleanup: Option<PendingCleanup>,
}

impl Guard {
    pub(crate) fn note_reaped(&mut self) -> std::io::Result<()> {
        // The one allowed job process has exited, so its temporary filesystem
        // authority can be removed now.
        let Some(cleanup) = &mut self.cleanup else {
            return Ok(());
        };
        cleanup.mark_process_reaped();
        cleanup.cleanup_reaped_once()?;
        if cleanup.is_clean() {
            self.cleanup.take();
        }
        Ok(())
    }

    /// Terminate every process in the job now.
    pub(crate) fn kill_tree(&mut self) {
        // SAFETY: the job handle stays open until Drop.
        unsafe {
            TerminateJobObject(self.job as Handle, 1);
        }
    }

    /// The Job Object's memory ceiling is enforced by the kernel and surfaces
    /// as an exit status, so no supervisor state is folded in here.
    pub(crate) fn memory_ceiling_exceeded(&self) -> bool {
        false
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        // SAFETY: the job, desktop and process handles are owned by this
        // guard and closed exactly once here.
        let wait = unsafe {
            TerminateJobObject(self.job as Handle, 1);
            let wait = self.cleanup.as_ref().and_then(|cleanup| {
                (!cleanup.process_reaped).then(|| {
                    WaitForSingleObject(cleanup.process as Handle, PROCESS_REAP_GRACE_MILLIS)
                })
            });
            CloseHandle(self.job as Handle);
            CloseDesktop(self.desktop as Handle);
            wait
        };
        let Some(mut cleanup) = self.cleanup.take() else {
            return;
        };
        if let Some(wait) = wait {
            if classify_wait_status(wait, std::io::Error::last_os_error).is_ok() {
                cleanup.mark_process_reaped();
            }
        }
        if cleanup.process_reaped && cleanup.cleanup_reaped_once().is_ok() && cleanup.is_clean() {
            return;
        }
        if !cleanup.run_until_clean() {
            fatal_unproven_exit();
        }
    }
}

struct PendingCleanup {
    process: isize,
    process_reaped: bool,
    grants: Option<AclGrantLedger>,
    container: Option<AppContainerSid>,
}

impl PendingCleanup {
    fn mark_process_reaped(&mut self) {
        self.process_reaped = true;
        if self.process != 0 {
            // SAFETY: `process` is a handle this cleanup owns.
            unsafe {
                CloseHandle(self.process as Handle);
            }
            self.process = 0;
        }
    }

    fn cleanup_reaped_once(&mut self) -> std::io::Result<()> {
        debug_assert!(self.process_reaped);
        if let Some(grants) = &mut self.grants {
            grants.revoke().map_err(contain_error_to_io)?;
            self.grants.take();
        }
        if let Some(container) = &mut self.container {
            container.delete_profile().map_err(contain_error_to_io)?;
            self.container.take();
        }
        Ok(())
    }

    fn is_clean(&self) -> bool {
        self.process == 0 && self.grants.is_none() && self.container.is_none()
    }

    fn run_until_clean(&mut self) -> bool {
        let mut retry_interval = CLEANUP_RETRY_INTERVAL;
        let mut wait_failures = 0;
        while !self.process_reaped {
            // SAFETY: `process` is a handle this cleanup owns.
            let status = unsafe { WaitForSingleObject(self.process as Handle, INFINITE) };
            match classify_wait_status(status, std::io::Error::last_os_error) {
                Ok(()) => self.mark_process_reaped(),
                Err(_) => {
                    wait_failures += 1;
                    if cleanup_wait_is_fatal(wait_failures) {
                        return false;
                    }
                    std::thread::sleep(retry_interval);
                    retry_interval = (retry_interval * 2).min(CLEANUP_MAX_RETRY_INTERVAL);
                }
            }
        }
        retry_interval = CLEANUP_RETRY_INTERVAL;
        let mut cleanup_failures = 0;
        while !self.is_clean() {
            if self.cleanup_reaped_once().is_err() {
                cleanup_failures += 1;
                if cleanup_authority_failure_is_fatal(cleanup_failures) {
                    return false;
                }
                std::thread::sleep(retry_interval);
                retry_interval = (retry_interval * 2).min(CLEANUP_MAX_RETRY_INTERVAL);
            }
        }
        true
    }
}

fn cleanup_wait_is_fatal(failures: usize) -> bool {
    failures >= CLEANUP_WAIT_FAILURE_ATTEMPTS
}

fn cleanup_authority_failure_is_fatal(failures: usize) -> bool {
    failures >= CLEANUP_AUTHORITY_FAILURE_ATTEMPTS
}

/// Teardown could not be proven. The helper aborts rather than report a clean
/// run: orceld sees no result and fails the call. Any ACE left behind names a
/// unique, random AppContainer SID whose profile name was never disclosed, so
/// no later process can hold a token for it.
fn fatal_unproven_exit() -> ! {
    std::process::abort()
}

fn classify_wait_status(
    status: u32,
    last_error: impl FnOnce() -> std::io::Error,
) -> std::io::Result<()> {
    match status {
        WAIT_OBJECT_0 => Ok(()),
        WAIT_FAILED => Err(last_error()),
        other => Err(std::io::Error::other(format!(
            "unexpected WaitForSingleObject status {other:#010x}"
        ))),
    }
}

fn contain_error_to_io(error: ContainError) -> std::io::Error {
    let detail = error.detail.map_or_else(
        || error.message.clone(),
        |detail| format!("{}: {detail}", error.message),
    );
    std::io::Error::other(detail)
}

pub(crate) struct Process {
    process: isize,
}

impl Process {
    pub(crate) async fn wait(&mut self) -> std::io::Result<RawExit> {
        // The blocking waiter owns a duplicate so cancellation may drop and
        // close `Process` without closing a handle under WaitForSingleObject.
        let process = OwnedHandle::duplicate_io(self.process as Handle)?;
        // SAFETY: `process` is a valid duplicate owned by the closure.
        let code = tokio::task::spawn_blocking(move || unsafe {
            let status = WaitForSingleObject(process.get(), INFINITE);
            classify_wait_status(status, std::io::Error::last_os_error)?;
            let mut code = 0_u32;
            if GetExitCodeProcess(process.get(), &mut code) == FALSE {
                return Err(std::io::Error::last_os_error());
            }
            Ok(code)
        })
        .await
        .map_err(std::io::Error::other)??;
        Ok(RawExit {
            success: code == 0,
            resource_limited: RESOURCE_LIMIT_EXITS.contains(&code),
            code: i64::from(code),
            signaled: false,
        })
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        // SAFETY: `process` is owned by this value.
        unsafe {
            CloseHandle(self.process as Handle);
        }
    }
}

pub(crate) async fn spawn(
    executable: &Path,
    args: &[String],
    working_directory: &Path,
    boundary: &FilesystemBoundary,
    limits: &ContainmentLimits,
) -> Result<ContainedChild, ContainError> {
    spawn_named(
        &format!("{APP_CONTAINER_NAME_PREFIX}.{}", random_token()?),
        executable,
        args,
        working_directory,
        boundary,
        limits,
    )
    .await
}

/// [`spawn`] with the AppContainer profile name as a parameter, so a profile
/// that cannot be created is a testable refusal. Shipped code passes only a
/// fresh random name.
pub(crate) async fn spawn_named(
    profile_name: &str,
    executable: &Path,
    args: &[String],
    working_directory: &Path,
    boundary: &FilesystemBoundary,
    limits: &ContainmentLimits,
) -> Result<ContainedChild, ContainError> {
    if !executable.is_file() {
        return Err(spawn_error(std::io::Error::from_raw_os_error(2)));
    }
    let user = current_user_sid()?;
    let container = AppContainerSid::create(profile_name)?;
    let acl_grants = grant_child_paths(working_directory, boundary, user.sid(), container.sid())?;

    let token = random_token()?;
    let stdio_security =
        PrivateSecurity::new(&[(user.sid(), GENERIC_ALL), (container.sid(), GENERIC_ALL)])?;
    let job_security = PrivateSecurity::new(&[(user.sid(), GENERIC_ALL)])?;
    let desktop_security = PrivateSecurity::new(&[
        (user.sid(), GENERIC_ALL),
        (container.sid(), DESKTOP_CHILD_ACCESS),
    ])?;

    let mut stdin = StdioPipe::create(&token, "in", Direction::ToChild, &stdio_security)?;
    let mut stdout = StdioPipe::create(&token, "out", Direction::FromChild, &stdio_security)?;
    let mut stderr = StdioPipe::create(&token, "err", Direction::FromChild, &stdio_security)?;
    // Every end already exists, so the connections complete before any child
    // code is created, let alone resumed.
    stdin.connect().await?;
    stdout.connect().await?;
    stderr.connect().await?;
    let job = OwnedHandle::create_job(limits, &job_security)?;
    let mut desktop = PrivateDesktop::create(&token, &desktop_security)?;

    let information = create_suspended(
        executable,
        args,
        working_directory,
        &desktop,
        [stdin.client(), stdout.client(), stderr.client()],
        container.sid(),
        &stdio_security,
    )?;

    // The suspended process has not executed one instruction, so any failure
    // from here on can still be resolved by terminating it.
    // SAFETY: both handles are valid for the duration of the call.
    if unsafe { AssignProcessToJobObject(job.get(), information.process) } == FALSE {
        let failure = last_error("failed to assign the contained process to its job object");
        information.terminate();
        return Err(failure);
    }
    // The child now owns its copies of the client ends; the helper keeps only
    // the server ends, so the child observes end of file when the helper goes
    // away.
    let stdin = stdin.into_server();
    let stdout = stdout.into_server();
    let stderr = stderr.into_server();

    let guard_process = OwnedHandle::duplicate(information.process)?;
    // SAFETY: the thread handle is valid until `into_process` closes it.
    if unsafe { ResumeThread(information.thread) } == u32::MAX {
        let failure = last_error("failed to resume the contained process");
        information.terminate();
        return Err(failure);
    }
    let guard = Guard {
        job: job.release() as isize,
        desktop: desktop.release() as isize,
        cleanup: Some(PendingCleanup {
            process: guard_process.release() as isize,
            process_reaped: false,
            grants: Some(acl_grants),
            container: Some(container),
        }),
    };
    let process = Process {
        process: information.into_process() as isize,
    };
    Ok(ContainedChild {
        guard,
        process,
        stdin: Some(stdin),
        stdout: Some(stdout),
        stderr: Some(stderr),
    })
}

/// 128 random bits from the system RNG as 32 hex digits, for the profile,
/// pipe and desktop names. Unpredictable names keep another local process
/// from guessing or pre-creating them.
fn random_token() -> Result<String, ContainError> {
    let mut bytes = [0_u8; 16];
    // SAFETY: `bytes` is a writable buffer of the stated length.
    let status = unsafe {
        BCryptGenRandom(
            std::ptr::null_mut(),
            bytes.as_mut_ptr(),
            bytes.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status != 0 {
        return Err(containment_error(
            "failed to generate a contained process name",
            Some(format!("ntstatus {status:#010x}")),
        ));
    }
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// A handle that is closed when it is dropped unless ownership is released to a
/// longer-lived guard.
struct OwnedHandle(Handle);

// SAFETY: a Win32 kernel handle is a process-wide value with no thread affinity, and this
// wrapper is its only owner, so moving it to another thread keeps it valid and closes it
// exactly once.
unsafe impl Send for OwnedHandle {}

impl OwnedHandle {
    fn get(&self) -> Handle {
        self.0
    }

    fn release(mut self) -> Handle {
        let handle = self.0;
        self.0 = std::ptr::null_mut();
        std::mem::forget(self);
        handle
    }

    fn duplicate(handle: Handle) -> Result<Self, ContainError> {
        Self::duplicate_io(handle).map_err(|cause| {
            containment_error(
                "failed to retain the contained process process for ACL cleanup",
                os_detail(&cause),
            )
        })
    }

    fn duplicate_io(handle: Handle) -> std::io::Result<Self> {
        // SAFETY: GetCurrentProcess takes no arguments and returns a pseudo-handle that never
        // needs closing.
        let process = unsafe { GetCurrentProcess() };
        let mut duplicate = std::ptr::null_mut();
        // SAFETY: `handle` is an open handle the caller owns, the source and target are this
        // process's pseudo-handle, and `duplicate` is a live out-pointer; on success the new
        // handle is owned by the returned value.
        if unsafe {
            DuplicateHandle(
                process,
                handle,
                process,
                &mut duplicate,
                0,
                FALSE,
                DUPLICATE_SAME_ACCESS,
            )
        } == FALSE
        {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self(duplicate))
    }

    fn create_job(
        limits: &ContainmentLimits,
        security: &PrivateSecurity,
    ) -> Result<Self, ContainError> {
        // An unnamed job object with a private, protected security descriptor
        // cannot be opened by name or by an unrelated process.
        let attributes = security.attributes();
        // SAFETY: `attributes` points at a private security descriptor kept alive by `security`
        // for the call, and a null name creates an unnamed job.
        let job = unsafe { CreateJobObjectW(&attributes, std::ptr::null()) };
        if job.is_null() {
            return Err(last_error(
                "failed to create the contained process containment job object",
            ));
        }
        let job = Self(job);

        // SAFETY: JOBOBJECT_EXTENDED_LIMIT_INFORMATION is plain integers and counters, for
        // which all-zero is a valid value.
        let mut information: JobExtendedLimitInformation = unsafe { std::mem::zeroed() };
        information.basic_limit_information.limit_flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
            | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
            | JOB_OBJECT_LIMIT_JOB_MEMORY
            | JOB_OBJECT_LIMIT_PROCESS_TIME;
        information.basic_limit_information.active_process_limit = MAX_PROCESSES;
        // `PerProcessUserTimeLimit` counts in 100-nanosecond units.
        information
            .basic_limit_information
            .per_process_user_time_limit =
            i64::try_from(limits.max_cpu_seconds().saturating_mul(10_000_000)).unwrap_or(i64::MAX);
        information.job_memory_limit =
            usize::try_from(limits.max_memory_bytes).unwrap_or(usize::MAX);
        // SAFETY: `job` is an open job handle, and the pointer and length describe the live
        // `information` struct of exactly that class.
        if unsafe {
            SetInformationJobObject(
                job.get(),
                JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                std::ptr::addr_of!(information).cast(),
                std::mem::size_of::<JobExtendedLimitInformation>() as u32,
            )
        } == FALSE
        {
            return Err(last_error(
                "failed to apply the contained process containment job object limits",
            ));
        }

        let restrictions = JobBasicUiRestrictions {
            ui_restrictions_class: JOB_OBJECT_UILIMIT_ALL,
        };
        // SAFETY: `job` is an open job handle, and the pointer and length describe the live
        // `restrictions` struct of exactly that class.
        if unsafe {
            SetInformationJobObject(
                job.get(),
                JOB_OBJECT_BASIC_UI_RESTRICTIONS,
                std::ptr::addr_of!(restrictions).cast(),
                std::mem::size_of::<JobBasicUiRestrictions>() as u32,
            )
        } == FALSE
        {
            return Err(last_error(
                "failed to apply the contained process containment job object UI restrictions",
            ));
        }
        Ok(job)
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the handle is non-null and owned by this wrapper; `release` nulls it when
            // ownership moves, so it is closed once.
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

/// The child's own desktop. Nothing else runs on it, so a capture or input
/// attempt from inside the child reaches an empty desktop rather than the
/// user's session.
struct PrivateDesktop {
    handle: Handle,
    name: Vec<u16>,
    released: bool,
}

impl PrivateDesktop {
    fn create(token: &str, security: &PrivateSecurity) -> Result<Self, ContainError> {
        let name = wide(format!("orcel-contain-{token}"));
        let attributes = security.attributes();
        // SAFETY: `name` is a NUL-terminated UTF-16 buffer and `attributes` points at a
        // descriptor kept alive by `security`, both for the duration of the call; null device
        // and devmode are allowed.
        let handle = unsafe {
            CreateDesktopW(
                name.as_ptr(),
                std::ptr::null(),
                std::ptr::null_mut(),
                0,
                GENERIC_ALL,
                &attributes,
            )
        };
        if handle.is_null() {
            return Err(last_error(
                "failed to create the private desktop for the contained process",
            ));
        }
        Ok(Self {
            handle,
            name,
            released: false,
        })
    }

    fn name(&self) -> *mut u16 {
        self.name.as_ptr().cast_mut()
    }

    /// Hand the desktop handle to the guard that outlives this value. The
    /// desktop exists only while a handle to it is open, so the guard must hold
    /// it for as long as the child runs.
    fn release(&mut self) -> Handle {
        self.released = true;
        self.handle
    }
}

impl Drop for PrivateDesktop {
    fn drop(&mut self) {
        if !self.released && !self.handle.is_null() {
            // SAFETY: the desktop handle is owned by this value and was not released to a
            // guard, so it is closed exactly once.
            unsafe {
                CloseDesktop(self.handle);
            }
        }
    }
}

#[derive(Clone, Copy)]
enum Direction {
    ToChild,
    FromChild,
}

/// One half of the framed protocol: an asynchronous private named pipe on the
/// helper side and a plain inheritable stdio handle on the child side.
struct StdioPipe {
    server: NamedPipeServer,
    client: OwnedHandle,
}

impl StdioPipe {
    fn create(
        token: &str,
        suffix: &str,
        direction: Direction,
        security: &PrivateSecurity,
    ) -> Result<Self, ContainError> {
        let name = format!(r"\\.\pipe\orcel-contain-{token}-{suffix}");
        let mut options = ServerOptions::new();
        options
            .pipe_mode(PipeMode::Byte)
            // One instance, claimed first, so no other process can pre-create
            // or later attach to this name.
            .first_pipe_instance(true)
            .max_instances(1)
            .reject_remote_clients(true);
        match direction {
            Direction::ToChild => options.access_inbound(false).access_outbound(true),
            Direction::FromChild => options.access_inbound(true).access_outbound(false),
        };
        let mut attributes = security.attributes();
        // SAFETY: `attributes` is a live SECURITY_ATTRIBUTES whose descriptor `security` keeps
        // alive until after the call; tokio copies nothing from it after creation.
        let server = unsafe {
            options.create_with_security_attributes_raw(
                &name,
                std::ptr::addr_of_mut!(attributes).cast(),
            )
        }
        .map_err(|cause| {
            containment_error(
                "failed to create a private contained process stdio pipe",
                os_detail(&cause),
            )
        })?;

        let wide_name = wide(&name);
        let client_attributes = inheritable_attributes();
        let access = match direction {
            Direction::ToChild => GENERIC_READ,
            Direction::FromChild => GENERIC_WRITE,
        };
        // SAFETY: `wide_name` is NUL-terminated and `client_attributes` is a live
        // SECURITY_ATTRIBUTES for the call; the returned handle is checked against
        // INVALID_HANDLE_VALUE before use.
        let client = unsafe {
            CreateFileW(
                wide_name.as_ptr(),
                access,
                0,
                &client_attributes,
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            )
        };
        if client as isize == -1 {
            return Err(last_error("failed to open the child end of a stdio pipe"));
        }
        Ok(Self {
            server,
            client: OwnedHandle(client),
        })
    }

    fn client(&self) -> Handle {
        self.client.get()
    }

    async fn connect(&mut self) -> Result<(), ContainError> {
        self.server.connect().await.map_err(|cause| {
            containment_error(
                "failed to connect a private contained process stdio pipe",
                os_detail(&cause),
            )
        })
    }

    /// Release the child's end, which the child now owns, and keep the
    /// helper's asynchronous end.
    fn into_server(self) -> NamedPipeServer {
        self.server
    }
}

/// The suspended child process and its primary thread.
struct SuspendedProcess {
    process: Handle,
    thread: Handle,
}

impl SuspendedProcess {
    fn terminate(self) {
        // SAFETY: both handles came from CreateProcessW and are owned by this value; `forget`
        // below stops Drop from closing them a second time.
        unsafe {
            TerminateProcess(self.process, 1);
            WaitForSingleObject(self.process, INFINITE);
            CloseHandle(self.thread);
            CloseHandle(self.process);
        }
        std::mem::forget(self);
    }

    fn into_process(self) -> Handle {
        let process = self.process;
        // SAFETY: the thread handle is owned by this value and closed once; `forget` below
        // stops Drop from touching it again, and the process handle moves to the caller.
        unsafe {
            CloseHandle(self.thread);
        }
        std::mem::forget(self);
        process
    }
}

impl Drop for SuspendedProcess {
    fn drop(&mut self) {
        // SAFETY: both handles came from CreateProcessW and are still owned here because
        // neither `terminate` nor `into_process` ran.
        unsafe {
            TerminateProcess(self.process, 1);
            WaitForSingleObject(self.process, INFINITE);
            CloseHandle(self.thread);
            CloseHandle(self.process);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn create_suspended(
    executable: &Path,
    args: &[String],
    working_directory: &Path,
    desktop: &PrivateDesktop,
    inherited: [Handle; 3],
    container: *mut c_void,
    security: &PrivateSecurity,
) -> Result<SuspendedProcess, ContainError> {
    let application = wide(executable.as_os_str());
    let mut command_line = command_line(executable, args);
    let current_directory = wide(working_directory.as_os_str());
    let environment = environment_block(working_directory)?;

    let mut attributes = AttributeList::new(2)?;
    let mut handles = inherited;
    attributes.set(
        PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
        handles.as_mut_ptr().cast(),
        std::mem::size_of_val(&handles),
        "failed to restrict the contained process's inherited handles",
    )?;
    let mut capabilities = SecurityCapabilities {
        app_container_sid: container,
        capabilities: std::ptr::null_mut(),
        capability_count: 0,
        reserved: 0,
    };
    attributes.set(
        PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
        std::ptr::addr_of_mut!(capabilities).cast(),
        std::mem::size_of::<SecurityCapabilities>(),
        "failed to place the contained process in its AppContainer",
    )?;

    // SAFETY: STARTUPINFOEXW is integers and pointers, for which all-zero (null pointers) is
    // the documented initial state.
    let mut startup: StartupInfoExW = unsafe { std::mem::zeroed() };
    startup.startup_info.cb = std::mem::size_of::<StartupInfoExW>() as u32;
    startup.startup_info.desktop = desktop.name();
    startup.startup_info.flags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    startup.startup_info.show_window = SW_HIDE;
    startup.startup_info.std_input = inherited[0];
    startup.startup_info.std_output = inherited[1];
    startup.startup_info.std_error = inherited[2];
    startup.attribute_list = attributes.pointer();

    let process_attributes = security.attributes();
    // SAFETY: PROCESS_INFORMATION is two handles and two ids; all-zero is a valid placeholder
    // that CreateProcessW overwrites.
    let mut information: ProcessInformation = unsafe { std::mem::zeroed() };
    // SAFETY: every pointer argument points at a live, NUL-terminated or correctly sized buffer
    // owned by this function (application, mutable command line, environment block, directory,
    // startup info with its attribute list) or at the descriptors `security` keeps alive, all
    // outliving the call.
    let created = unsafe {
        CreateProcessW(
            application.as_ptr(),
            command_line.as_mut_ptr(),
            &process_attributes,
            &process_attributes,
            // Required by the handle list, which is exactly what narrows this
            // from "every inheritable handle" to the three above.
            TRUE,
            CREATE_SUSPENDED
                | CREATE_NO_WINDOW
                | CREATE_UNICODE_ENVIRONMENT
                | EXTENDED_STARTUPINFO_PRESENT,
            environment.as_ptr().cast(),
            current_directory.as_ptr(),
            std::ptr::addr_of!(startup.startup_info),
            &mut information,
        )
    };
    if created == FALSE {
        return Err(last_error(
            "failed to launch the contained contained process",
        ));
    }
    Ok(SuspendedProcess {
        process: information.process,
        thread: information.thread,
    })
}

/// A `PROC_THREAD_ATTRIBUTE_LIST` in a pointer-aligned allocation.
struct AttributeList {
    storage: Vec<usize>,
}

impl AttributeList {
    fn new(count: u32) -> Result<Self, ContainError> {
        let mut size: usize = 0;
        // SAFETY: the documented sizing call: a null list with a live `size` out-pointer only
        // reports the required size.
        unsafe {
            InitializeProcThreadAttributeList(std::ptr::null_mut(), count, 0, &mut size);
        }
        if size == 0 {
            return Err(last_error(
                "failed to size the contained process process attribute list",
            ));
        }
        // `Vec<usize>` guarantees the pointer alignment the attribute list
        // requires; a byte vector does not. The list is only wrapped in the
        // guard once it initializes, so `Drop` never deletes an unformed list.
        let mut storage = vec![0_usize; size.div_ceil(std::mem::size_of::<usize>())];
        // SAFETY: `storage` is a pointer-aligned allocation of at least `size` bytes, as the
        // sizing call required.
        if unsafe {
            InitializeProcThreadAttributeList(storage.as_mut_ptr().cast(), count, 0, &mut size)
        } == FALSE
        {
            return Err(last_error(
                "failed to create the contained process process attribute list",
            ));
        }
        Ok(Self { storage })
    }

    fn pointer(&mut self) -> *mut c_void {
        self.storage.as_mut_ptr().cast()
    }

    fn set(
        &mut self,
        attribute: usize,
        value: *mut c_void,
        size: usize,
        message: &'static str,
    ) -> Result<(), ContainError> {
        let list = self.pointer();
        // SAFETY: `list` is an initialised attribute list, and `value`/`size` describe a buffer
        // the caller keeps alive until CreateProcessW returns, as UpdateProcThreadAttribute
        // requires.
        if unsafe {
            UpdateProcThreadAttribute(
                list,
                0,
                attribute,
                value,
                size,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        } == FALSE
        {
            return Err(last_error(message));
        }
        Ok(())
    }
}

impl Drop for AttributeList {
    fn drop(&mut self) {
        // SAFETY: the list was initialised in `new` (a value only exists after a successful
        // initialisation) and is deleted once.
        unsafe {
            DeleteProcThreadAttributeList(self.storage.as_mut_ptr().cast());
        }
    }
}

/// The child's AppContainer identity.
struct AppContainerSid {
    sid: *mut c_void,
    name: Vec<u16>,
    profile_deleted: bool,
}

fn validate_profile_name(name: &str) -> Result<(), ContainError> {
    if name.encode_utf16().count() > 64 {
        return Err(containment_error(
            "the contained process AppContainer profile name exceeds the Windows limit",
            None,
        ));
    }
    if !profile_name_has_shape(name, APP_CONTAINER_NAME_PREFIX) {
        return Err(containment_error(
            "the contained process AppContainer profile name is malformed",
            None,
        ));
    }
    Ok(())
}

fn profile_name_has_shape(name: &str, prefix: &str) -> bool {
    name.strip_prefix(prefix)
        .and_then(|suffix| suffix.strip_prefix('.'))
        .is_some_and(|token| {
            token.len() == 32 && token.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
}

// SAFETY: the SID is a heap allocation owned by this value and released by FreeSid in Drop;
// nothing ties it to the creating thread.
unsafe impl Send for AppContainerSid {}

impl AppContainerSid {
    fn create(profile_name: &str) -> Result<Self, ContainError> {
        validate_profile_name(profile_name)?;
        let name = wide(profile_name);
        let display = wide(APP_CONTAINER_DISPLAY_NAME);
        let description = wide(APP_CONTAINER_DESCRIPTION);
        let mut sid: *mut c_void = std::ptr::null_mut();
        // SAFETY: the three name strings are NUL-terminated buffers that outlive the call,
        // there are no capabilities (null, 0), and `sid` is a live out-pointer.
        let created = unsafe {
            CreateAppContainerProfile(
                name.as_ptr(),
                display.as_ptr(),
                description.as_ptr(),
                std::ptr::null_mut(),
                0,
                &mut sid,
            )
        };
        if created < 0 {
            return Err(containment_error(
                "failed to create the contained process AppContainer identity",
                Some(format!("hresult {created:#010x}")),
            ));
        }
        if sid.is_null() {
            // SAFETY: `name` is the NUL-terminated profile name just passed to
            // CreateAppContainerProfile.
            unsafe {
                DeleteAppContainerProfile(name.as_ptr());
            }
            return Err(containment_error(
                "the contained process AppContainer identity was empty",
                None,
            ));
        }
        Ok(Self {
            sid,
            name,
            profile_deleted: false,
        })
    }

    fn sid(&self) -> *mut c_void {
        self.sid
    }

    #[cfg(test)]
    fn create_unique() -> Result<Self, ContainError> {
        Self::create(&format!("{APP_CONTAINER_NAME_PREFIX}.{}", random_token()?))
    }

    fn delete_profile(&mut self) -> Result<(), ContainError> {
        if self.profile_deleted {
            return Ok(());
        }
        // SAFETY: `self.name` is the NUL-terminated name of the profile this value created.
        let status = unsafe { DeleteAppContainerProfile(self.name.as_ptr()) };
        classify_app_container_delete(status).map_err(|status| {
            containment_error(
                "failed to delete the contained process AppContainer profile",
                Some(format!("hresult {status:#010x}")),
            )
        })?;
        self.profile_deleted = true;
        Ok(())
    }
}

impl Drop for AppContainerSid {
    fn drop(&mut self) {
        let mut failure = None;
        for _ in 0..3 {
            match self.delete_profile() {
                Ok(()) => break,
                Err(cause) => {
                    failure = Some(cause);
                    std::thread::sleep(CLEANUP_RETRY_INTERVAL);
                }
            }
        }
        if let Some(cause) = failure.filter(|_| !self.profile_deleted) {
            // The run already finished; a profile that survives names a
            // unique random SID and grants nothing.
            let _ = cause;
        }
        // SAFETY: `self.sid` came from CreateAppContainerProfile, is owned by this value and is
        // freed exactly once here.
        unsafe {
            FreeSid(self.sid);
        }
    }
}

fn classify_app_container_delete(status: i32) -> Result<(), i32> {
    const HRESULT_FILE_NOT_FOUND: i32 = -2_147_024_894;
    const HRESULT_NOT_FOUND: i32 = -2_147_023_728;

    if status >= 0 || matches!(status, HRESULT_FILE_NOT_FOUND | HRESULT_NOT_FOUND) {
        Ok(())
    } else {
        Err(status)
    }
}

/// The helper's own user identity, read from its process token.
struct UserSid {
    buffer: Vec<u8>,
}

impl UserSid {
    fn sid(&self) -> *mut c_void {
        // `TOKEN_USER` starts with the `SID_AND_ATTRIBUTES` whose first field
        // points into this same buffer.
        let information = self.buffer.as_ptr().cast::<TokenUserInformation>();
        // SAFETY: `buffer` holds a TOKEN_USER written by GetTokenInformation; its first field
        // is a SID_AND_ATTRIBUTES whose pointer refers into the same buffer, which outlives the
        // returned pointer's uses.
        unsafe { (*information).user.sid }
    }
}

fn current_user_sid() -> Result<UserSid, ContainError> {
    let mut token: Handle = std::ptr::null_mut();
    // SAFETY: GetCurrentProcess is a pseudo-handle, and `token` is a live out-pointer whose
    // result is owned by the OwnedHandle below.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == FALSE {
        return Err(last_error(
            "failed to read the helper identity for the contained process sandbox",
        ));
    }
    let token = OwnedHandle(token);
    let mut required = 0_u32;
    // SAFETY: the documented sizing call: a null buffer of length 0 with a live `required`
    // out-pointer only reports the size.
    unsafe {
        GetTokenInformation(
            token.get(),
            TOKEN_USER_CLASS,
            std::ptr::null_mut(),
            0,
            &mut required,
        );
    }
    if required == 0
        || std::io::Error::last_os_error().raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER)
    {
        return Err(last_error(
            "failed to size the helper identity for the contained process sandbox",
        ));
    }
    let mut buffer = vec![0_u8; required as usize];
    // SAFETY: `buffer` is a writable allocation of exactly `required` bytes, the size the
    // sizing call reported.
    if unsafe {
        GetTokenInformation(
            token.get(),
            TOKEN_USER_CLASS,
            buffer.as_mut_ptr().cast(),
            required,
            &mut required,
        )
    } == FALSE
    {
        return Err(last_error(
            "failed to read the helper identity for the contained process sandbox",
        ));
    }
    Ok(UserSid { buffer })
}

/// A private, protected discretionary access control list plus the security
/// descriptor that carries it.
struct PrivateSecurity {
    descriptor: Box<SecurityDescriptorStorage>,
    _acl: LocalAcl,
}

impl PrivateSecurity {
    fn new(grants: &[(*mut c_void, u32)]) -> Result<Self, ContainError> {
        let acl = build_acl(grants, NO_INHERITANCE, std::ptr::null_mut())?;
        let mut descriptor = Box::new(SecurityDescriptorStorage([0_u8; 64]));
        let pointer: *mut c_void = std::ptr::addr_of_mut!(descriptor.0).cast();
        // SAFETY: `pointer` addresses a boxed, 8-byte-aligned 64-byte buffer, above the size of
        // an absolute SECURITY_DESCRIPTOR, that lives as long as the descriptor.
        if unsafe { InitializeSecurityDescriptor(pointer, SECURITY_DESCRIPTOR_REVISION) } == FALSE {
            return Err(last_error(
                "failed to create the private security descriptor for the contained process",
            ));
        }
        // SAFETY: `pointer` is the descriptor initialised just above, and `acl.0` is a valid
        // ACL owned by `_acl`, which lives as long as the descriptor.
        if unsafe { SetSecurityDescriptorDacl(pointer, TRUE, acl.0, FALSE) } == FALSE {
            return Err(last_error(
                "failed to apply the private access control list for the contained process",
            ));
        }
        Ok(Self {
            descriptor,
            _acl: acl,
        })
    }

    fn attributes(&self) -> SecurityAttributes {
        SecurityAttributes {
            length: std::mem::size_of::<SecurityAttributes>() as u32,
            security_descriptor: std::ptr::addr_of!(self.descriptor.0).cast_mut().cast(),
            inherit_handle: FALSE,
        }
    }
}

/// An access control list allocated by `SetEntriesInAclW`.
struct LocalAcl(*mut c_void);

// SAFETY: the ACL is a LocalAlloc allocation owned by this value and freed once by LocalFree;
// nothing ties it to the allocating thread.
unsafe impl Send for LocalAcl {}

impl Drop for LocalAcl {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the pointer is non-null, came from SetEntriesInAclW or GetSecurityInfo
            // (both LocalAlloc), and is owned and freed once here.
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}

fn build_acl(
    grants: &[(*mut c_void, u32)],
    inheritance: u32,
    existing: *mut c_void,
) -> Result<LocalAcl, ContainError> {
    let mut entries: Vec<ExplicitAccessW> = grants
        .iter()
        .map(|(sid, access)| ExplicitAccessW {
            access_permissions: *access,
            access_mode: GRANT_ACCESS,
            inheritance,
            trustee: TrusteeW {
                multiple_trustee: std::ptr::null_mut(),
                multiple_trustee_operation: NO_MULTIPLE_TRUSTEE,
                trustee_form: TRUSTEE_IS_SID,
                trustee_type: TRUSTEE_IS_UNKNOWN,
                name: (*sid).cast(),
            },
        })
        .collect();
    let mut acl: *mut c_void = std::ptr::null_mut();
    // SAFETY: `entries` is a live slice of EXPLICIT_ACCESS_W whose trustee SIDs outlive the
    // call, `existing` is null or a valid ACL, and `acl` is a live out-pointer whose LocalAlloc
    // result is owned by LocalAcl.
    let status = unsafe {
        SetEntriesInAclW(
            entries.len() as u32,
            entries.as_mut_ptr(),
            existing,
            &mut acl,
        )
    };
    if status != ERROR_SUCCESS || acl.is_null() {
        return Err(containment_error(
            "failed to build the access control list for the contained process",
            Some(format!("os error {status}")),
        ));
    }
    Ok(LocalAcl(acl))
}

/// Temporarily give the child's AppContainer identity exactly the access its
/// executable, working directory and spec roots require, and nothing else.
/// Every prior DACL is restored after the process exits.
///
/// The working directory receives a protected list naming only the helper's
/// user and the child, so no other account on the machine can read what the
/// child is working on. The remaining roots are merged rather than replaced,
/// because they are shared paths whose existing permissions belong to their
/// owner. The executable is granted as one exact file.
fn grant_child_paths(
    working_directory: &Path,
    boundary: &FilesystemBoundary,
    user: *mut c_void,
    container: *mut c_void,
) -> Result<AclGrantLedger, ContainError> {
    let working = std::fs::canonicalize(working_directory).map_err(|cause| {
        containment_error(
            "failed to resolve the private contained process directory",
            os_detail(&cause),
        )
    })?;
    let mut ledger = AclGrantLedger::default();
    let result = (|| {
        ledger
            .set_protected_dacl_tree(&working, &[(user, GENERIC_ALL), (container, GENERIC_ALL)])?;
        for root in &boundary.writable {
            if *root == working {
                continue;
            }
            ledger.merge_grant_tree(root, container, GENERIC_ALL, true)?;
        }
        for root in &boundary.readable {
            if *root == working
                || boundary
                    .writable
                    .iter()
                    .any(|writable| root.starts_with(writable))
            {
                continue;
            }
            ledger.merge_grant_tree(root, container, GENERIC_READ | GENERIC_EXECUTE, false)?;
        }
        for executable in &boundary.executables {
            ledger.merge_grant_tree(
                executable,
                container,
                GENERIC_READ | GENERIC_EXECUTE,
                false,
            )?;
        }
        Ok(())
    })();
    match result {
        Ok(()) => Ok(ledger),
        Err(cause) => match ledger.revoke() {
            Ok(()) => Err(cause),
            Err(rollback) => Err(rollback),
        },
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    volume_serial_number: u32,
    file_index_high: u32,
    file_index_low: u32,
}

struct SavedDacl {
    target: AclTarget,
    descriptor: LocalAcl,
    dacl_offset: Option<usize>,
    protected: bool,
}

impl SavedDacl {
    /// The DACL as it was before any grant (null when there was none).
    fn original_dacl(&self) -> *mut c_void {
        self.dacl_offset.map_or(std::ptr::null_mut(), |offset| {
            (self.descriptor.0 as usize + offset) as *mut c_void
        })
    }

    fn capture(target: AclTarget) -> Result<Self, ContainError> {
        let mut dacl: *mut c_void = std::ptr::null_mut();
        let mut descriptor: *mut c_void = std::ptr::null_mut();
        // SAFETY: the target handle is open with READ_CONTROL, and `dacl` and `descriptor` are
        // live out-pointers; the descriptor is LocalAlloc'd and owned by LocalAcl below.
        let status = unsafe {
            GetSecurityInfo(
                target.handle.get(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut dacl,
                std::ptr::null_mut(),
                &mut descriptor,
            )
        };
        if status != ERROR_SUCCESS || descriptor.is_null() {
            return Err(containment_error(
                "failed to save the existing permissions of a contained process path",
                Some(format!("os error {status}")),
            ));
        }
        let descriptor = LocalAcl(descriptor);
        let mut control = 0_u16;
        let mut revision = 0_u32;
        // SAFETY: `descriptor.0` is the security descriptor GetSecurityInfo just returned, and
        // both out-pointers are live locals.
        if unsafe { GetSecurityDescriptorControl(descriptor.0, &mut control, &mut revision) }
            == FALSE
        {
            return Err(last_error(
                "failed to save contained process ACL control flags",
            ));
        }
        let dacl_offset = (!dacl.is_null()).then(|| dacl as usize - descriptor.0 as usize);
        Ok(Self {
            target,
            descriptor,
            dacl_offset,
            protected: control & 0x1000 != 0,
        })
    }

    fn restore(&self) -> Result<(), ContainError> {
        let dacl = self.dacl_offset.map_or(std::ptr::null_mut(), |offset| {
            (self.descriptor.0 as usize + offset) as *mut c_void
        });
        let protection = if self.protected {
            PROTECTED_DACL_SECURITY_INFORMATION
        } else {
            UNPROTECTED_DACL_SECURITY_INFORMATION
        };
        apply_dacl(
            self.target.handle.get(),
            dacl,
            DACL_SECURITY_INFORMATION | protection,
            "failed to revoke temporary contained process filesystem access",
        )
    }
}

#[derive(Default)]
struct AclGrantLedger {
    entries: Vec<SavedDacl>,
}

impl AclGrantLedger {
    fn contains(&self, identity: FileIdentity) -> bool {
        self.entries
            .iter()
            .any(|entry| entry.target.identity == identity)
    }

    fn set_protected_dacl_tree(
        &mut self,
        path: &Path,
        grants: &[(*mut c_void, u32)],
    ) -> Result<(), ContainError> {
        let start = self.entries.len();
        walk_acl_tree(path, &mut |target| {
            if self.contains(target.identity) {
                return Ok(());
            }
            // Phase one only captures and validates: replacing a directory's
            // DACL here would strip what its unvisited children inherit, and
            // the walk could no longer open them.
            self.entries.push(SavedDacl::capture(target)?);
            Ok(())
        })?;
        self.finish_inheritance(path, start, true, |saved| {
            Ok((
                build_acl(grants, saved.target.inheritance(true), std::ptr::null_mut())?,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            ))
        })
    }

    fn merge_grant_tree(
        &mut self,
        path: &Path,
        sid: *mut c_void,
        access: u32,
        inherit_children: bool,
    ) -> Result<(), ContainError> {
        let start = self.entries.len();
        walk_acl_tree(path, &mut |target| {
            // Writable trees are processed first. Skipping an already-seen
            // identity prevents a later overlapping read root from adding a
            // duplicate ACE or replacing its stronger grant.
            if self.contains(target.identity) {
                return Ok(());
            }
            let saved = SavedDacl::capture(target)?;
            // Phase one: nothing inheritable yet (see `finish_inheritance`).
            let acl = build_acl(&[(sid, access)], NO_INHERITANCE, saved.original_dacl())?;
            self.entries.push(saved);
            let saved = &self.entries[self.entries.len() - 1];
            apply_dacl(
                saved.target.handle.get(),
                acl.0,
                DACL_SECURITY_INFORMATION,
                "failed to grant the contained process access to a spec root",
            )?;
            saved.target.ensure_single_link()
        })?;
        if !inherit_children {
            return Ok(());
        }
        self.finish_inheritance(path, start, false, |saved| {
            Ok((
                build_acl(
                    &[(sid, access)],
                    saved.target.inheritance(true),
                    saved.original_dacl(),
                )?,
                DACL_SECURITY_INFORMATION,
            ))
        })
    }

    /// Phase two and three of a tree grant (judge round on #378, L2).
    /// `SetSecurityInfo` propagates an inheritable ACE to the existing
    /// children at once, so applying it during the walk could stamp a child
    /// the walk has not validated yet, such as a hard link to an outside
    /// file, and a hard kill before rollback would leave that behind. So the
    /// walk (phase one) validates every object first (and, for a merged grant,
    /// grants it non-inheritably); only then are the entries this walk
    /// ledgered (from `start`, parents first) given their final, inheritable
    /// ACL: every entry when `every_entry` (the private working directory),
    /// otherwise its directories. A last walk (phase three) refuses the grant
    /// if any object in the tree is not ledgered (something appeared
    /// meanwhile) or has gained a second link; either refusal rolls back.
    fn finish_inheritance(
        &mut self,
        path: &Path,
        start: usize,
        every_entry: bool,
        build: impl Fn(&SavedDacl) -> Result<(LocalAcl, u32), ContainError>,
    ) -> Result<(), ContainError> {
        for saved in &self.entries[start..] {
            if !every_entry && !saved.target.is_directory() {
                continue;
            }
            let (acl, information) = build(saved)?;
            apply_dacl(
                saved.target.handle.get(),
                acl.0,
                information,
                "failed to make a contained process grant inheritable",
            )?;
            saved.target.ensure_single_link()?;
        }
        walk_acl_tree(path, &mut |target| {
            if self.contains(target.identity) {
                Ok(())
            } else {
                Err(containment_error(
                    "a contained process ACL root changed while it was granted",
                    None,
                ))
            }
        })
    }

    fn revoke(&mut self) -> Result<(), ContainError> {
        let mut first_failure = None;
        let mut failed = Vec::new();
        for entry in std::mem::take(&mut self.entries).into_iter().rev() {
            if let Err(cause) = entry.restore() {
                first_failure.get_or_insert(cause);
                failed.push(entry);
            }
        }
        // Preserve grant order so a later retry still restores descendants
        // before their parents. Guard teardown retries failures after the
        // normal-reap path, and Drop retries a failed pre-launch rollback.
        failed.reverse();
        self.entries = failed;
        first_failure.map_or(Ok(()), Err)
    }
}

impl Drop for AclGrantLedger {
    fn drop(&mut self) {
        let _ = self.revoke();
    }
}

/// Visit an ACL root and every existing descendant. After each verified
/// no-follow handle is acquired without delete sharing, the retained handle
/// blocks new delete or rename opens through DACL restoration. Protected child
/// DACLs do not inherit a root grant, so each object receives its own ACE. Any
/// failed open, validation, enumeration, or ACL update aborts the launch.
fn walk_acl_tree(
    path: &Path,
    apply: &mut impl FnMut(AclTarget) -> Result<(), ContainError>,
) -> Result<(), ContainError> {
    let target = AclTarget::open(path)?;
    check_single_link(&target, target.links)?;
    let is_directory = target.is_directory();
    let resolved = target.path.clone();
    apply(target)?;
    if !is_directory {
        return Ok(());
    }

    let entries = std::fs::read_dir(&resolved).map_err(|cause| {
        containment_error(
            "failed to enumerate a contained process ACL directory",
            os_detail(&cause),
        )
    })?;
    for entry in entries {
        let entry = entry.map_err(|cause| {
            containment_error(
                "failed to enumerate a contained process ACL directory",
                os_detail(&cause),
            )
        })?;
        walk_acl_tree(&resolved.join(entry.file_name()), apply)?;
    }
    Ok(())
}

fn apply_dacl(
    target: Handle,
    acl: *mut c_void,
    information: u32,
    message: &'static str,
) -> Result<(), ContainError> {
    // SAFETY: `target` is an open handle with WRITE_DAC, and `acl` is null or an ACL kept alive
    // by the caller for the call.
    let status = unsafe {
        SetSecurityInfo(
            target,
            SE_FILE_OBJECT,
            information,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            acl,
            std::ptr::null_mut(),
        )
    };
    if status != ERROR_SUCCESS {
        return Err(containment_error(
            message,
            Some(format!("os error {status}")),
        ));
    }
    Ok(())
}

/// An ACL target opened without following a final reparse point. The final
/// kernel-resolved name is compared with the already canonical policy path
/// before any grant is applied. A concurrent ancestor swap that redirects the
/// open resolves to a different name and is refused. Once acquired, the handle
/// is retained without delete sharing, blocking new delete or rename opens
/// through DACL restoration.
struct AclTarget {
    handle: OwnedHandle,
    path: PathBuf,
    identity: FileIdentity,
    file_attributes: u32,
    /// The link count when the handle was opened; the walk refuses more than
    /// one before granting.
    links: u32,
}

impl AclTarget {
    fn open(path: &Path) -> Result<Self, ContainError> {
        let name = wide(path.as_os_str());
        // SAFETY: `name` is a NUL-terminated UTF-16 path that outlives the call; the handle is
        // checked against INVALID_HANDLE_VALUE and then owned by OwnedHandle.
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                FILE_READ_DATA | READ_CONTROL | WRITE_DAC,
                // Allow ordinary readers and writers to keep using shared
                // installation roots. FILE_READ_DATA engages file share
                // accounting; descriptor-only rights such as READ_CONTROL and
                // WRITE_DAC do not. Once acquired, withholding delete sharing
                // blocks new delete or rename opens until the handle is released.
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                std::ptr::null_mut(),
            )
        };
        if handle as isize == -1 {
            return Err(last_error(
                "failed to open a contained process path for an ACL update",
            ));
        }
        let handle = OwnedHandle(handle);

        let mut tag = FileAttributeTagInfo {
            file_attributes: 0,
            reparse_tag: 0,
        };
        // SAFETY: `handle` is open, and the pointer and size describe the live `tag` struct of
        // exactly the FileAttributeTagInfo class.
        if unsafe {
            GetFileInformationByHandleEx(
                handle.get(),
                FILE_ATTRIBUTE_TAG_INFO_CLASS,
                std::ptr::addr_of_mut!(tag).cast(),
                std::mem::size_of::<FileAttributeTagInfo>() as u32,
            )
        } == FALSE
        {
            return Err(last_error(
                "failed to validate a contained process ACL target",
            ));
        }
        if tag.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(containment_error(
                "a contained process ACL target is a reparse point",
                None,
            ));
        }

        let resolved = final_path(&handle)?;
        if normalize_windows_path(&resolved) != normalize_windows_path(path) {
            return Err(containment_error(
                "a contained process ACL target changed while it was opened",
                None,
            ));
        }
        let information = file_information(&handle)?;
        let target = Self {
            handle,
            path: resolved,
            identity: FileIdentity {
                volume_serial_number: information.volume_serial_number,
                file_index_high: information.file_index_high,
                file_index_low: information.file_index_low,
            },
            file_attributes: tag.file_attributes,
            links: information.number_of_links,
        };
        Ok(target)
    }

    /// Read the link count again through the retained handle (see the
    /// module header: a link made after `open` must not survive the grant).
    fn ensure_single_link(&self) -> Result<(), ContainError> {
        check_single_link(self, file_information(&self.handle)?.number_of_links)
    }

    fn is_directory(&self) -> bool {
        self.file_attributes & FILE_ATTRIBUTE_DIRECTORY != 0
    }

    fn inheritance(&self, inherit_children: bool) -> u32 {
        if inherit_children && self.is_directory() {
            SUB_CONTAINERS_AND_OBJECTS_INHERIT
        } else {
            NO_INHERITANCE
        }
    }
}

fn file_information(handle: &OwnedHandle) -> Result<ByHandleFileInformation, ContainError> {
    let mut information = std::mem::MaybeUninit::<ByHandleFileInformation>::uninit();
    // SAFETY: `handle` is open and the out-pointer addresses a MaybeUninit of exactly
    // BY_HANDLE_FILE_INFORMATION.
    if unsafe { GetFileInformationByHandle(handle.get(), information.as_mut_ptr()) } == FALSE {
        return Err(last_error(
            "failed to identify a contained process ACL target",
        ));
    }
    // SAFETY: GetFileInformationByHandle returned success, which means it filled every field.
    Ok(unsafe { information.assume_init() })
}

/// A file reachable under a second name outside the root would receive the
/// root's grant through their shared security descriptor.
fn check_single_link(target: &AclTarget, links: u32) -> Result<(), ContainError> {
    if !target.is_directory() && links != 1 {
        return Err(containment_error(
            "a contained process ACL target has more than one hard link",
            Some(format!("{links} links")),
        ));
    }
    Ok(())
}

fn final_path(handle: &OwnedHandle) -> Result<std::path::PathBuf, ContainError> {
    // SAFETY: the documented sizing call: a null buffer of length 0 returns the required
    // length.
    let required = unsafe {
        GetFinalPathNameByHandleW(handle.get(), std::ptr::null_mut(), 0, FILE_NAME_NORMALIZED)
    };
    if required == 0 {
        return Err(last_error(
            "failed to size a contained process ACL target path",
        ));
    }
    let mut path = vec![0_u16; required as usize];
    // SAFETY: `path` is a writable buffer of exactly the length passed, and `handle` is open.
    let written = unsafe {
        GetFinalPathNameByHandleW(
            handle.get(),
            path.as_mut_ptr(),
            path.len() as u32,
            FILE_NAME_NORMALIZED,
        )
    };
    if written == 0 || written as usize >= path.len() {
        return Err(last_error(
            "failed to read a contained process ACL target path",
        ));
    }
    path.truncate(written as usize);
    Ok(std::path::PathBuf::from(std::ffi::OsString::from_wide(
        &path,
    )))
}

fn normalize_windows_path(path: &Path) -> String {
    let mut text = path.as_os_str().to_string_lossy().replace('/', "\\");
    if let Some(stripped) = text.strip_prefix(r"\\?\UNC\") {
        text = format!(r"\\{stripped}");
    } else if let Some(stripped) = text.strip_prefix(r"\\?\") {
        text = stripped.to_owned();
    }
    text.trim_end_matches('\\').to_ascii_lowercase()
}

/// A minimal environment block. The child inherits nothing from the helper, so
/// no proxy setting, token, or caller path reaches it; only the loader's
/// `SystemRoot` and private temporary and profile directories inside the
/// working directory are provided.
fn environment_block(working_directory: &Path) -> Result<Vec<u16>, ContainError> {
    let profile = working_directory.join("profile");
    let roaming_app_data = profile.join("AppData").join("Roaming");
    let local_app_data = profile.join("AppData").join("Local");
    std::fs::create_dir_all(&profile).map_err(|cause| {
        containment_error(
            "failed to create the contained process's private profile directory",
            os_detail(&cause),
        )
    })?;
    std::fs::create_dir_all(&roaming_app_data).map_err(|cause| {
        containment_error(
            "failed to create the contained process's private roaming application data directory",
            os_detail(&cause),
        )
    })?;
    std::fs::create_dir_all(&local_app_data).map_err(|cause| {
        containment_error(
            "failed to create the contained process's private local application data directory",
            os_detail(&cause),
        )
    })?;

    let mut system_root = vec![0_u16; 260];
    let written =
        // SAFETY: `system_root` is a writable buffer of exactly the length passed.
        unsafe { GetSystemWindowsDirectoryW(system_root.as_mut_ptr(), system_root.len() as u32) };
    if written == 0 || written as usize >= system_root.len() {
        return Err(last_error(
            "failed to read the system directory for the contained process environment",
        ));
    }
    system_root.truncate(written as usize);
    let system_root = String::from_utf16_lossy(&system_root);
    let temporary = working_directory.display().to_string();
    let profile = profile.display().to_string();
    let roaming_app_data = roaming_app_data.display().to_string();
    let local_app_data = local_app_data.display().to_string();

    let mut block = Vec::new();
    let mut entries = [
        format!("APPDATA={roaming_app_data}"),
        format!("LOCALAPPDATA={local_app_data}"),
        format!("SystemRoot={system_root}"),
        format!("PATH={system_root}\\System32"),
        format!("TEMP={temporary}"),
        format!("TMP={temporary}"),
        format!("USERPROFILE={profile}"),
        format!("windir={system_root}"),
    ];
    entries.sort_by_key(|entry| entry.to_ascii_lowercase());
    for entry in entries {
        block.extend(entry.encode_utf16());
        block.push(0);
    }
    block.push(0);
    Ok(block)
}

fn command_line(executable: &Path, args: &[String]) -> Vec<u16> {
    let mut command_line = Vec::new();
    for argument in
        std::iter::once(executable.as_os_str()).chain(args.iter().map(std::ffi::OsStr::new))
    {
        if !command_line.is_empty() {
            command_line.push(u16::from(b' '));
        }
        append_argument(&mut command_line, argument.encode_wide());
    }
    command_line.push(0);
    command_line
}

/// Quote one argument the way `CommandLineToArgvW` parses it, so an argument
/// containing a space, tab or quote cannot be split or escape into another.
fn append_argument(command_line: &mut Vec<u16>, argument: impl IntoIterator<Item = u16>) {
    let argument = argument.into_iter().collect::<Vec<_>>();
    let quote = argument.is_empty()
        || argument
            .iter()
            .any(|value| matches!(*value, 0x20 | 0x09 | 0x22));
    if !quote {
        command_line.extend(argument);
        return;
    }
    command_line.push(u16::from(b'"'));
    let mut backslashes = 0;
    for value in argument {
        if value == u16::from(b'\\') {
            backslashes += 1;
        } else if value == u16::from(b'"') {
            command_line.extend(std::iter::repeat_n(u16::from(b'\\'), backslashes * 2 + 1));
            command_line.push(value);
            backslashes = 0;
        } else {
            command_line.extend(std::iter::repeat_n(u16::from(b'\\'), backslashes));
            command_line.push(value);
            backslashes = 0;
        }
    }
    command_line.extend(std::iter::repeat_n(u16::from(b'\\'), backslashes * 2));
    command_line.push(u16::from(b'"'));
}

fn inheritable_attributes() -> SecurityAttributes {
    SecurityAttributes {
        length: std::mem::size_of::<SecurityAttributes>() as u32,
        security_descriptor: std::ptr::null_mut(),
        inherit_handle: TRUE,
    }
}

fn wide(value: impl AsRef<OsStr>) -> Vec<u16> {
    value
        .as_ref()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn last_error(message: &'static str) -> ContainError {
    containment_error(message, os_detail(&std::io::Error::last_os_error()))
}

#[cfg(test)]
#[path = "windows_tests.rs"]
mod tests;
