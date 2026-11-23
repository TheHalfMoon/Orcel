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
//!   hard link and no permission for anyone else; anything else is refused and
//!   left as it is. It is never read or written. A state root that is a link
//!   or not a folder is refused; the rest of the root's permissions are the
//!   commands' own checks, because an install repairs a root that is too open.
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
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::rc::{Rc, Weak};
use std::time::{Duration, Instant};

/// How long a waiting command sleeps between two tries.
const POLL: Duration = Duration::from_millis(50);

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
            if let Some(file) = try_acquire(&layout.root, &path)? {
                let held = Rc::new(Held { file });
                HELD.with_borrow_mut(|all| {
                    all.retain(|(_, other)| other.strong_count() > 0);
                    all.push((path, Rc::downgrade(&held)));
                });
                return Ok(Self { _held: held });
            }
            if Instant::now() >= deadline {
                return Err(LifecycleError::conflict(crate::lifecycle::LOCK_BUSY));
            }
            std::thread::sleep(POLL);
        }
    }
}

/// One try. `None`: another command holds it, or the file or the root went
/// away in between.
fn try_acquire(root: &Path, path: &Path) -> Result<Option<File>, LifecycleError> {
    ensure_root(root)?;
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
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
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
    let uid = orcel_platform::session::effective_uid()
        .ok_or_else(|| LifecycleError::platform("the effective user id is unavailable"))?;
    let lock_error = |error: std::io::Error| {
        LifecycleError::io(format!("take the lifecycle lock {}", path.display()), error)
    };
    let metadata = file.metadata().map_err(lock_error)?;
    check(&metadata, uid).map_err(|why| refuse(path, why))?;
    if !try_lock_exclusive(&file).map_err(lock_error)? {
        return Ok(None);
    }
    if !is_named(&metadata, path).map_err(lock_error)? {
        return Ok(None);
    }
    Ok(Some(file))
}

/// The state root, made owner-only when it is missing; a link is not followed.
fn ensure_root(root: &Path) -> Result<(), LifecycleError> {
    match fs::symlink_metadata(root) {
        Ok(metadata) if metadata.is_dir() => Ok(()),
        Ok(_) => Err(LifecycleError::state(format!(
            "the Orcel state folder {} is a link or not a folder, so nothing was changed",
            root.display()
        ))),
        Err(error) if error.kind() == ErrorKind::NotFound => fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(root)
            .map_err(|error| LifecycleError::io(format!("create {}", root.display()), error)),
        Err(error) => Err(LifecycleError::io(
            format!("inspect {}", root.display()),
            error,
        )),
    }
}

/// Whether the open file can be the lock: this user's, plain, private.
fn check(metadata: &Metadata, uid: u32) -> Result<(), &'static str> {
    if !metadata.is_file() {
        Err("is not a plain file")
    } else if metadata.uid() != uid {
        Err("is owned by another user")
    } else if metadata.nlink() > 1 {
        Err("has another hard link")
    } else if metadata.mode() & 0o077 != 0 {
        Err("can be opened by other users")
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
    use std::os::unix::fs::{symlink, PermissionsExt};
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
    fn a_lock_file_that_is_not_this_users_private_file_is_refused_and_left_alone() {
        for case in [
            "link",
            "dangling link",
            "fifo",
            "folder",
            "hard link",
            "group",
            "others",
        ] {
            let layout = layout("lock-refuse");
            let path = layout.lifecycle_lock();
            let outside = layout.root.with_file_name("outside");
            fs::create_dir_all(&layout.root).unwrap();
            let write = |target: &Path, mode: u32| {
                fs::write(target, b"kept").unwrap();
                fs::set_permissions(target, fs::Permissions::from_mode(mode)).unwrap();
            };
            match case {
                "link" => {
                    write(&outside, 0o600);
                    symlink(&outside, &path).unwrap();
                }
                "dangling link" => symlink(&outside, &path).unwrap(),
                "fifo" => {
                    let made = Command::new("mkfifo").arg(&path).status().unwrap();
                    assert!(made.success());
                }
                "folder" => fs::create_dir(&path).unwrap(),
                "hard link" => {
                    write(&outside, 0o600);
                    fs::hard_link(&outside, &path).unwrap();
                }
                "group" => write(&path, 0o620),
                _ => write(&path, 0o604),
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

    /// What a command that opened the file before it went away is told.
    #[test]
    fn a_file_that_is_no_longer_there_is_not_the_lock() {
        let layout = layout("lock-named");
        let path = layout.lifecycle_lock();
        let file = try_acquire(&layout.root, &path).unwrap().unwrap();
        let opened = file.metadata().unwrap();
        assert!(is_named(&opened, &path).unwrap());
        fs::remove_file(&path).unwrap();
        assert!(!is_named(&opened, &path).unwrap(), "gone");
        // Another file: `file` keeps the first one's number in use.
        fs::write(&path, b"").unwrap();
        assert!(!is_named(&opened, &path).unwrap(), "replaced");
        drop(file);
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
                assert_eq!(left, [path.clone()], "only the lock is left");
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
