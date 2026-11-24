//! The lifecycle lock on Linux and macOS: an exclusive `flock` on
//! `lifecycle.lock` in the state root, with the meaning of the Windows named
//! mutex ([`crate::lifecycle::lock`]).
//!
//! - **Scope.** One lock per state root, which is per user.
//! - **Waiting.** A second command tries again for the caller's time and is
//!   then refused, with the Windows text. The thread that holds the lock can
//!   take it again; another thread of the same process waits.
//! - **A holder that dies.** The kernel releases the lock. The file stays and
//!   means nothing by itself.
//! - **Child processes.** The descriptor is close-on-exec (as every file std
//!   opens), so no program that a command starts keeps the lock. A normal
//!   release unlocks the open file itself, so a process that forked and has
//!   not called `exec` yet does not keep it either.
//! - **The file.** It is opened without following a link and without waiting
//!   for a FIFO, and used only if it is this user's plain file with no other
//!   hard link; anything else is refused and left as it is. One that others
//!   can open is made 0600 through the open descriptor. It is never read or
//!   written.
//! - **The state root.** A root that is a link or not a folder is refused, and
//!   so is one of another user, before anything is created or opened. For a
//!   root that is missing, the nearest folder above it that is there must be
//!   this user's. So `sudo orcel`, with the person's `HOME`, leaves nothing
//!   owned by root there (and a first run whose nearest folder is a shared one,
//!   such as `/tmp`, is refused). The rest of the root's permissions are the
//!   commands' own checks, because an install repairs a root that is too open.
//!   A root this user cannot write (0500) and that has no lock file yet is not
//!   repaired: the command fails with the error of opening the file, where an
//!   install without this lock would have made it 0700 first.
//! - **Never deleted.** Nothing of Orcel's removes or replaces the file, and
//!   `uninstall --purge-data` leaves it: were it removed while held, a waiting
//!   command and a new one could hold two different files at once. The name
//!   is looked up again after locking, so a command that got the lock of a file
//!   that is no longer there starts over. A person who deletes the file while a
//!   command runs lets a second one start.
//!
//! It is taken before every other lock of a command and no command takes it
//! while it holds another, so there is no order to get wrong. It is advisory:
//! it orders Orcel's own commands, and on a network file system it is as good
//! as that file system's `flock`; one that has none makes the commands fail.

use crate::layout::Layout;
use crate::LifecycleError;
use orcel_platform::paths::try_lock_exclusive;
use std::cell::RefCell;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::ErrorKind;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::rc::{Rc, Weak};
use std::time::{Duration, Instant};

/// How long a waiting command sleeps between two tries.
const POLL: Duration = Duration::from_millis(50);

/// Where a try is; tests change the files there.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Step {
    /// The root is there, the file is not opened yet.
    BeforeOpen,
    /// The file is locked, its name is not looked up again yet.
    Locked,
}

/// What came of one try.
enum Try {
    Got(File),
    /// Another command holds it.
    Busy,
    /// What went away or changed in between.
    Changed(&'static str),
}

/// The held lock, released when the last guard of the thread is dropped. Not
/// `Send`: it belongs to the thread that took it, as the Windows mutex does.
pub struct LifecycleLock {
    _held: Rc<Held>,
}

struct Held {
    file: File,
}

impl Drop for Held {
    fn drop(&mut self) {
        let _ = fs4::FileExt::unlock(&self.file);
    }
}

thread_local! {
    /// The locks this thread holds, by path: it can take one again.
    static HELD: RefCell<Vec<(PathBuf, Weak<Held>)>> = const { RefCell::new(Vec::new()) };
}

impl LifecycleLock {
    pub fn acquire(layout: &Layout, timeout: Duration) -> Result<Self, LifecycleError> {
        let uid = orcel_platform::session::effective_uid()
            .ok_or_else(|| LifecycleError::platform("the effective user id is unavailable"))?;
        Self::acquire_as(layout, timeout, uid, &mut |_| {})
    }

    fn acquire_as(
        layout: &Layout,
        timeout: Duration,
        uid: u32,
        between: &mut dyn FnMut(Step),
    ) -> Result<Self, LifecycleError> {
        let path = layout.lifecycle_lock();
        let mine = HELD.with_borrow(|held| {
            held.iter()
                .find(|(held_path, _)| *held_path == path)
                .and_then(|(_, held)| held.upgrade())
        });
        if let Some(held) = mine {
            return Ok(Self { _held: held });
        }
        let deadline = Instant::now() + timeout;
        loop {
            let outcome = try_acquire(&layout.root, &path, uid, between)?;
            if let Try::Got(file) = outcome {
                let held = Rc::new(Held { file });
                HELD.with_borrow_mut(|all| {
                    all.retain(|(_, other)| other.strong_count() > 0);
                    all.push((path, Rc::downgrade(&held)));
                });
                return Ok(Self { _held: held });
            }
            if Instant::now() >= deadline {
                return Err(match outcome {
                    Try::Changed(what) => LifecycleError::state(format!(
                        "the lifecycle lock {} could not be taken, so nothing was changed: {what}",
                        path.display()
                    )),
                    _ => LifecycleError::conflict(crate::lifecycle::LOCK_BUSY),
                });
            }
            std::thread::sleep(POLL);
        }
    }
}

fn try_acquire(
    root: &Path,
    path: &Path,
    uid: u32,
    between: &mut dyn FnMut(Step),
) -> Result<Try, LifecycleError> {
    ensure_root(root, uid)?;
    between(Step::BeforeOpen);
    let opened = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path);
    let file = match opened {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::NotFound => {
            return Ok(Try::Changed("its folder went away"))
        }
        Err(error) if error.raw_os_error() == Some(libc::ELOOP) => {
            return Err(refuse(path, "is a link"))
        }
        Err(error) => {
            return Err(LifecycleError::io(
                format!("open the lifecycle lock {}", path.display()),
                error,
            ))
        }
    };
    let lock_error = |error: std::io::Error| {
        LifecycleError::io(format!("take the lifecycle lock {}", path.display()), error)
    };
    let metadata = file.metadata().map_err(lock_error)?;
    check(&metadata, uid).map_err(|why| refuse(path, why))?;
    // Before the lock: while others can open it, they can also hold it.
    if metadata.mode() & 0o077 != 0 {
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(lock_error)?;
    }
    if !try_lock_exclusive(&file).map_err(lock_error)? {
        return Ok(Try::Busy);
    }
    between(Step::Locked);
    if !is_named(&metadata, path).map_err(lock_error)? {
        return Ok(Try::Changed("the file was removed or replaced"));
    }
    Ok(Try::Got(file))
}

/// The state root, made owner-only when it is missing. A link is not followed,
/// and nothing is created under a folder of another user.
fn ensure_root(root: &Path, uid: u32) -> Result<(), LifecycleError> {
    match fs::symlink_metadata(root) {
        Ok(metadata) if metadata.is_dir() => check_owner(root, metadata.uid(), uid),
        Ok(_) => Err(LifecycleError::state(format!(
            "the Orcel state folder {} is a link or not a folder, so nothing was changed",
            root.display()
        ))),
        Err(error) if error.kind() == ErrorKind::NotFound => {
            check_owner_above(root, uid)?;
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(root)
                .map_err(|error| LifecycleError::io(format!("create {}", root.display()), error))
        }
        Err(error) => Err(LifecycleError::io(
            format!("inspect {}", root.display()),
            error,
        )),
    }
}

/// The nearest folder above a missing root that is there must be this user's.
/// A link there is followed, as creating the root would.
fn check_owner_above(root: &Path, uid: u32) -> Result<(), LifecycleError> {
    for ancestor in root.ancestors().skip(1) {
        match fs::metadata(ancestor) {
            Ok(metadata) => return check_owner(ancestor, metadata.uid(), uid),
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => {
                return Err(LifecycleError::io(
                    format!("inspect {}", ancestor.display()),
                    error,
                ))
            }
        }
    }
    Err(LifecycleError::state(format!(
        "no folder above the Orcel state folder {} exists, so nothing was changed",
        root.display()
    )))
}

/// Whether a command that runs as `uid` may work in a folder of `owner`. Root
/// is no exception: what it made there would lock the owner out.
fn check_owner(folder: &Path, owner: u32, uid: u32) -> Result<(), LifecycleError> {
    if owner == uid {
        return Ok(());
    }
    Err(LifecycleError::state(format!(
        "{} belongs to another user (uid {owner}, and this command runs as uid {uid}), so nothing was changed{}",
        folder.display(),
        if uid == 0 { "; run it without sudo" } else { "" }
    )))
}

/// Whether the open file can be the lock: this user's, plain, of one name.
fn check(metadata: &Metadata, uid: u32) -> Result<(), &'static str> {
    if !metadata.is_file() {
        Err("is not a plain file")
    } else if metadata.uid() != uid {
        Err("is owned by another user")
    } else if metadata.nlink() > 1 {
        Err("has another hard link")
    } else {
        Ok(())
    }
}

/// Whether `path` still names the open file.
fn is_named(opened: &Metadata, path: &Path) -> std::io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(now) => Ok(now.dev() == opened.dev() && now.ino() == opened.ino()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn refuse(path: &Path, why: &str) -> LifecycleError {
    LifecycleError::state(format!(
        "the lifecycle lock {} {why}, so nothing was changed; move it away while no Orcel command runs",
        path.display()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{release_dir, temp_dir, FakePlatform};
    use crate::ErrorKind as Kind;
    use std::os::unix::fs::symlink;
    use std::process::{Child, Command, Stdio};

    const SHORT: Duration = Duration::from_millis(200);
    const LONG: Duration = Duration::from_secs(20);
    /// Set for a child that holds the lock of this root.
    const HOLD: &str = "ORCEL_TEST_HOLD_LIFECYCLE_LOCK";

    fn layout(label: &str) -> Layout {
        let base = temp_dir(label);
        fs::set_permissions(&base, fs::Permissions::from_mode(0o755)).unwrap();
        Layout::new(base.join("Orcel"))
    }

    /// From another thread, as from another process: a thread that holds the
    /// lock can take it again.
    fn elsewhere(layout: &Layout, timeout: Duration) -> Result<(), LifecycleError> {
        let layout = layout.clone();
        std::thread::spawn(move || LifecycleLock::acquire(&layout, timeout).map(|_| ()))
            .join()
            .unwrap()
    }

    fn assert_busy(result: Result<(), LifecycleError>) {
        let error = result.unwrap_err();
        assert_eq!(error.kind, Kind::Conflict, "{}", error.message);
        assert_eq!(error.message, crate::lifecycle::LOCK_BUSY);
    }

    fn ready_file(layout: &Layout) -> PathBuf {
        layout.root.with_file_name("ready")
    }

    /// Not a test by itself: the process the other tests start. It takes the
    /// lock, starts a program as a command would, names it, and waits for it.
    #[test]
    fn hold_the_lock_for_another_test() {
        let Some(root) = std::env::var_os(HOLD) else {
            return;
        };
        let layout = Layout::new(PathBuf::from(root));
        let _lock = LifecycleLock::acquire(&layout, LONG).unwrap();
        let mut program = Command::new("sleep")
            .arg("120")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let ready = ready_file(&layout);
        let written = ready.with_extension("new");
        fs::write(&written, program.id().to_string()).unwrap();
        fs::rename(&written, &ready).unwrap();
        let _ = program.wait();
    }

    /// Another process that holds the lock, and the program it started.
    struct Holder {
        process: Child,
        program: libc::pid_t,
    }

    impl Holder {
        fn start(layout: &Layout) -> Self {
            let mut process = Command::new(std::env::current_exe().unwrap())
                .args([
                    "unix_lock::tests::hold_the_lock_for_another_test",
                    "--exact",
                    "--nocapture",
                ])
                .env(HOLD, &layout.root)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let deadline = Instant::now() + LONG;
            let program = loop {
                if let Ok(text) = fs::read_to_string(ready_file(layout)) {
                    break text.parse().unwrap();
                }
                assert!(process.try_wait().unwrap().is_none(), "the holder ended");
                let late = Instant::now() > deadline;
                if late {
                    let _ = process.kill();
                    let _ = process.wait();
                }
                assert!(!late, "the holder never took the lock");
                std::thread::sleep(Duration::from_millis(20));
            };
            Self { process, program }
        }

        /// SIGKILL, as a crash: nothing in the holder runs any more.
        fn kill(&mut self) {
            self.process.kill().unwrap();
            self.process.wait().unwrap();
        }

        fn program_runs(&self) -> bool {
            // SAFETY: signal 0 only asks whether the process exists.
            unsafe { libc::kill(self.program, 0) == 0 }
        }
    }

    impl Drop for Holder {
        fn drop(&mut self) {
            let _ = self.process.kill();
            let _ = self.process.wait();
            // SAFETY: ends the `sleep` this test's holder started.
            unsafe { libc::kill(self.program, libc::SIGKILL) };
        }
    }

    #[test]
    fn a_second_process_waits_and_is_then_refused() {
        let layout = layout("lock-contend");
        let _holder = Holder::start(&layout);
        let started = Instant::now();
        assert_busy(LifecycleLock::acquire(&layout, SHORT).map(|_| ()));
        assert!(started.elapsed() >= SHORT, "it waits first");
        // Another root has its own lock.
        let other = self::layout("lock-other");
        LifecycleLock::acquire(&other, SHORT).unwrap();
    }

    #[test]
    fn a_waiting_thread_gets_the_lock_when_it_is_released() {
        let layout = layout("lock-wait");
        let lock = LifecycleLock::acquire(&layout, SHORT).unwrap();
        let waiting = {
            let layout = layout.clone();
            std::thread::spawn(move || elsewhere(&layout, LONG))
        };
        std::thread::sleep(SHORT);
        assert!(!waiting.is_finished());
        drop(lock);
        waiting.join().unwrap().unwrap();
    }

    /// Also the close-on-exec proof: the program the holder started still runs
    /// and would keep the lock if it had inherited the descriptor.
    #[test]
    fn a_killed_holder_releases_the_lock_and_its_child_does_not_keep_it() {
        let layout = layout("lock-killed");
        let mut holder = Holder::start(&layout);
        assert_busy(LifecycleLock::acquire(&layout, SHORT).map(|_| ()));
        holder.kill();
        assert!(holder.program_runs(), "the program outlives the holder");
        // Less than the program's time.
        LifecycleLock::acquire(&layout, Duration::from_secs(5)).unwrap();
        assert!(holder.program_runs());
    }

    #[test]
    fn the_descriptor_is_close_on_exec() {
        use std::os::fd::AsRawFd;
        let layout = layout("lock-cloexec");
        let lock = LifecycleLock::acquire(&layout, SHORT).unwrap();
        // SAFETY: the descriptor is open while the lock is held.
        let flags = unsafe { libc::fcntl(lock._held.file.as_raw_fd(), libc::F_GETFD) };
        assert!(flags >= 0 && flags & libc::FD_CLOEXEC != 0, "{flags}");
    }

    #[test]
    fn only_the_thread_that_holds_it_can_take_it_again() {
        let layout = layout("lock-again");
        let first = LifecycleLock::acquire(&layout, SHORT).unwrap();
        let second = LifecycleLock::acquire(&layout, SHORT).unwrap();
        assert_busy(elsewhere(&layout, SHORT));
        drop(first);
        assert_busy(elsewhere(&layout, SHORT));
        drop(second);
        elsewhere(&layout, SHORT).unwrap();
        // Held again after all of it, for real.
        let _third = LifecycleLock::acquire(&layout, SHORT).unwrap();
        assert_busy(elsewhere(&layout, SHORT));
    }

    #[test]
    fn a_missing_root_and_the_file_are_made_owner_only() {
        let layout = Layout::new(layout("lock-new").root.join("deeper").join("orcel"));
        let _lock = LifecycleLock::acquire(&layout, SHORT).unwrap();
        let mode = |path: &Path| fs::symlink_metadata(path).unwrap().mode() & 0o777;
        assert_eq!(mode(&layout.root), 0o700);
        assert_eq!(mode(&layout.lifecycle_lock()), 0o600);
    }

    #[test]
    fn a_lock_file_that_is_not_one_plain_file_is_refused_and_left_alone() {
        for case in ["link", "dangling link", "fifo", "folder", "hard link"] {
            let layout = layout("lock-refuse");
            let path = layout.lifecycle_lock();
            let outside = layout.root.with_file_name("outside");
            fs::create_dir_all(&layout.root).unwrap();
            match case {
                "link" => {
                    fs::write(&outside, b"kept").unwrap();
                    symlink(&outside, &path).unwrap();
                }
                "dangling link" => symlink(&outside, &path).unwrap(),
                "fifo" => {
                    let made = Command::new("mkfifo").arg(&path).status().unwrap();
                    assert!(made.success());
                }
                "folder" => fs::create_dir(&path).unwrap(),
                _ => {
                    fs::write(&outside, b"kept").unwrap();
                    fs::hard_link(&outside, &path).unwrap();
                }
            }
            let before = fs::symlink_metadata(&path).unwrap();
            // Returns at once, for the FIFO too.
            let started = Instant::now();
            let error = LifecycleLock::acquire(&layout, LONG)
                .map(|_| ())
                .expect_err(case);
            assert!(started.elapsed() < LONG / 2, "{case}");
            assert_ne!(error.kind, Kind::Conflict, "{case}: {}", error.message);
            let after = fs::symlink_metadata(&path).unwrap();
            assert_eq!(before.ino(), after.ino(), "{case}");
            assert_eq!(before.mode(), after.mode(), "{case}");
            match case {
                "dangling link" => assert!(!outside.exists(), "never followed"),
                "link" | "hard link" => assert_eq!(fs::read(&outside).unwrap(), b"kept"),
                _ => {}
            }
        }
    }

    #[test]
    fn a_lock_file_others_can_open_is_made_private() {
        for mode in [0o620, 0o604, 0o666] {
            let layout = layout("lock-wide");
            let path = layout.lifecycle_lock();
            fs::create_dir(&layout.root).unwrap();
            fs::write(&path, b"kept").unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            let before = fs::symlink_metadata(&path).unwrap().ino();
            let _lock = LifecycleLock::acquire(&layout, SHORT).unwrap();
            let after = fs::symlink_metadata(&path).unwrap();
            assert_eq!(after.mode() & 0o7777, 0o600, "{mode:o}");
            assert_eq!(after.ino(), before);
            assert_eq!(fs::read(&path).unwrap(), b"kept");
        }
    }

    /// As `sudo orcel` with the person's `HOME`, with the users swapped: the
    /// folders are this test's and the command claims to run as another user.
    #[test]
    fn another_users_root_is_refused_and_nothing_is_created() {
        let uid = orcel_platform::session::effective_uid().unwrap();
        let refused = |layout: &Layout| {
            let error = LifecycleLock::acquire_as(layout, LONG, uid + 1, &mut |_| {})
                .err()
                .unwrap();
            assert_eq!(error.kind, Kind::State, "{}", error.message);
            assert!(error.message.contains("another user"), "{}", error.message);
        };
        // Missing, with more than one folder missing above it.
        let here = layout("lock-sudo");
        let missing = Layout::new(here.root.join("state").join("orcel"));
        refused(&missing);
        assert!(!here.root.exists(), "nothing was created");
        // There, without and with a lock file.
        fs::create_dir(&here.root).unwrap();
        refused(&here);
        assert_eq!(fs::read_dir(&here.root).unwrap().count(), 0);
        drop(LifecycleLock::acquire(&here, SHORT).unwrap());
        let before = fs::symlink_metadata(here.lifecycle_lock()).unwrap();
        refused(&here);
        let after = fs::symlink_metadata(here.lifecycle_lock()).unwrap();
        assert_eq!((before.ino(), before.uid()), (after.ino(), after.uid()));
    }

    #[test]
    fn only_the_owner_of_a_folder_works_in_it() {
        let folder = Path::new("/somewhere");
        for (owner, uid, allowed) in [
            (501, 501, true),
            (0, 0, true),
            // sudo in a person's folder, a person in root's, and two people.
            (501, 0, false),
            (0, 501, false),
            (501, 502, false),
        ] {
            let result = check_owner(folder, owner, uid);
            assert_eq!(result.is_ok(), allowed, "{owner} {uid}");
            if let Err(error) = result {
                assert_eq!(error.message.contains("without sudo"), uid == 0);
            }
        }
    }

    /// A root that cannot be written, and has no lock file, is not repaired.
    #[test]
    fn a_root_that_cannot_be_written_fails_and_is_left_alone() {
        // Root writes anywhere, so this says nothing for it.
        if orcel_platform::session::effective_uid().unwrap() == 0 {
            return;
        }
        let layout = layout("lock-0500");
        fs::create_dir(&layout.root).unwrap();
        let set = |mode| {
            fs::set_permissions(&layout.root, fs::Permissions::from_mode(mode)).unwrap();
        };
        set(0o500);
        let error = LifecycleLock::acquire(&layout, LONG).err().unwrap();
        assert_eq!(error.kind, Kind::Io, "{}", error.message);
        let mode = fs::symlink_metadata(&layout.root).unwrap().mode() & 0o777;
        assert_eq!(mode, 0o500);
        set(0o700);
        LifecycleLock::acquire(&layout, SHORT).unwrap();
    }

    #[test]
    fn another_users_lock_file_is_refused() {
        let layout = layout("lock-foreign");
        let _lock = LifecycleLock::acquire(&layout, SHORT).unwrap();
        let metadata = fs::symlink_metadata(layout.lifecycle_lock()).unwrap();
        check(&metadata, metadata.uid()).unwrap();
        assert!(check(&metadata, metadata.uid() + 1).is_err());
    }

    #[test]
    fn a_linked_root_is_refused_and_never_followed() {
        let layout = layout("lock-root");
        let target = layout.root.with_file_name("target");
        fs::create_dir(&target).unwrap();
        symlink(&target, &layout.root).unwrap();
        let error = LifecycleLock::acquire(&layout, SHORT).err().unwrap();
        assert_eq!(error.kind, Kind::State, "{}", error.message);
        assert_eq!(fs::read_dir(&target).unwrap().count(), 0);
    }

    fn uid() -> u32 {
        orcel_platform::session::effective_uid().unwrap()
    }

    /// A command that locked a file which is no longer the one under the name
    /// starts over, and holds the one that is.
    #[test]
    fn a_file_that_was_replaced_is_tried_again() {
        for remove_only in [true, false] {
            let layout = layout("lock-replaced");
            let path = layout.lifecycle_lock();
            let mut locked = 0;
            let lock = LifecycleLock::acquire_as(&layout, LONG, uid(), &mut |step| {
                if step != Step::Locked {
                    return;
                }
                locked += 1;
                if locked == 1 {
                    // The try still has it open, so its number stays in use.
                    fs::remove_file(&path).unwrap();
                    if !remove_only {
                        fs::write(&path, b"").unwrap();
                        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
                    }
                }
            })
            .unwrap();
            assert_eq!(locked, 2);
            let held = lock._held.file.metadata().unwrap().ino();
            assert_eq!(held, fs::symlink_metadata(&path).unwrap().ino());
            assert_busy(elsewhere(&layout, SHORT));
            drop(lock);
            elsewhere(&layout, SHORT).unwrap();
        }
    }

    /// Something that keeps changing is not another command that runs.
    #[test]
    fn what_keeps_changing_is_named_and_is_not_called_busy() {
        let layout = layout("lock-changing");
        let path = layout.lifecycle_lock();
        let result = LifecycleLock::acquire_as(&layout, SHORT, uid(), &mut |step| {
            if step == Step::Locked {
                fs::remove_file(&path).unwrap();
            }
        });
        let error = result.err().unwrap();
        assert_eq!(error.kind, Kind::State, "{}", error.message);
        assert!(
            error.message.contains("removed or replaced"),
            "{}",
            error.message
        );

        let result = LifecycleLock::acquire_as(&layout, SHORT, uid(), &mut |step| {
            if step == Step::BeforeOpen {
                fs::remove_dir_all(&layout.root).unwrap();
            }
        });
        let error = result.err().unwrap();
        assert_eq!(error.kind, Kind::State, "{}", error.message);
        assert!(error.message.contains("went away"), "{}", error.message);

        // The last reason counts: after a change, a command that holds it.
        let mut other = None;
        let result = LifecycleLock::acquire_as(&layout, SHORT, uid(), &mut |step| {
            if step == Step::Locked && other.is_none() {
                fs::remove_file(&path).unwrap();
                let taken = try_acquire(&layout.root, &path, uid(), &mut |_| {}).unwrap();
                assert!(matches!(taken, Try::Got(_)));
                other = Some(taken);
            }
        });
        assert_busy(result.map(|_| ()));
        drop(other);
    }

    /// A process that forked and has not called `exec` yet has a copy of the
    /// descriptor; a normal release does not wait for it.
    #[test]
    fn a_release_counts_while_a_copy_of_the_descriptor_is_open() {
        let layout = layout("lock-copy");
        let lock = LifecycleLock::acquire(&layout, SHORT).unwrap();
        let copy = lock._held.file.try_clone().unwrap();
        assert_busy(elsewhere(&layout, SHORT));
        drop(lock);
        elsewhere(&layout, SHORT).unwrap();
        drop(copy);
    }

    /// Uninstall, with and without the data, while a command holds the lock
    /// (it is the uninstall itself): the file stays, and stays the lock.
    #[test]
    fn uninstall_and_purge_never_remove_the_held_lock() {
        use crate::install::{InstallOptions, Installer, UninstallOptions};
        for purge_data in [false, true] {
            let layout = layout("lock-purge");
            let platform = FakePlatform::default();
            let installer = Installer::new(layout.clone(), &platform);
            let path = layout.lifecycle_lock();
            let lock = LifecycleLock::acquire(&layout, SHORT).unwrap();
            installer
                .install(
                    &release_dir("0.2.0"),
                    &InstallOptions {
                        node: Some(PathBuf::from("/fake/node")),
                        add_to_path: false,
                    },
                )
                .unwrap();
            let before = fs::symlink_metadata(&path).unwrap().ino();
            let report = installer
                .uninstall(&UninstallOptions { purge_data })
                .unwrap();
            assert_eq!(fs::symlink_metadata(&path).unwrap().ino(), before);
            assert!(report.residual.is_empty(), "{:?}", report.residual);
            assert!(report.retained.contains(&path), "{:?}", report.retained);
            assert!(!report.purged.contains(&path), "{:?}", report.purged);
            assert_busy(elsewhere(&layout, SHORT));
            if purge_data {
                let left: Vec<PathBuf> = fs::read_dir(&layout.root)
                    .unwrap()
                    .map(|entry| entry.unwrap().path())
                    .collect();
                assert_eq!(left, std::slice::from_ref(&path), "only the lock is left");
                // What isn't Orcel's is still reported.
                let other = layout.root.join("somebody-elses.txt");
                fs::write(&other, b"keep").unwrap();
                let report = installer
                    .uninstall(&UninstallOptions { purge_data })
                    .unwrap();
                assert!(report.residual.contains(&other), "{:?}", report.residual);
                assert!(report.residual.contains(&layout.root));
                assert!(!report.residual.contains(&path));
            }
            drop(lock);
            elsewhere(&layout, SHORT).unwrap();
        }
    }
}
