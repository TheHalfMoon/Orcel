//! SG-000132 WP1-10: `orceld fc-worker`. The request and reply contract on
//! every OS; on Windows, the real worker (the built `orceld.exe`) launched
//! into real, unnamed Job Objects made in this unelevated test process the
//! way the service makes them (an assign-only handle duplicated into this
//! process, the dispatch limits and UI restrictions), the operations inside
//! the roots, and the refusals: a revoke before the resume (the worker
//! never runs), a junction or a hard link out of the root. WP1-15
//! (SG132_SLICE4.md): real programs started by the worker inside the job
//! (a copy of this test binary as the program, driven by a mode file in
//! its working folder, since its environment is scrubbed), and real Git
//! against a repository whose hooks and configuration try to run programs.

use crate::fc_worker::{serve, WorkerOp, WorkerReply, WorkerRequest, WORKER_CONTRACT};
use orcel_contracts::FailureCode;

fn request_bytes(token: &str, op: WorkerOp, roots: Vec<String>) -> Vec<u8> {
    serde_json::to_vec(&WorkerRequest {
        contract: WORKER_CONTRACT.to_owned(),
        token: token.to_owned(),
        roots,
        op,
    })
    .expect("encode")
}

#[test]
fn fc_worker_acts_only_inside_a_job_and_echoes_the_token() {
    let input = request_bytes(
        "t-1",
        WorkerOp::Stat {
            path: r"C:\work\a.txt".to_owned(),
        },
        vec![r"C:\work".to_owned()],
    );
    let mut output = Vec::new();
    let exit = serve(&mut input.as_slice(), &mut output, false);
    assert_eq!(exit, 1);
    let reply: WorkerReply = serde_json::from_slice(&output).expect("one reply");
    assert!(!reply.ok);
    assert_eq!(reply.token, "t-1");
    assert_eq!(reply.code, Some(FailureCode::CapabilityDenied));
    // Bound to its launch: another token's reply is refused.
    let refused = reply.clone().into_result("t-2").err().map(|e| e.code);
    assert_eq!(refused, Some(FailureCode::InternalError));

    for bad in [
        b"not json".to_vec(),
        br#"{"contract":"other/1","token":"t","roots":[],"op":{"op":"stat","path":"C:\\x"}}"#
            .to_vec(),
        br#"{"contract":"orcel.fc-worker/1","token":"t","roots":[],"op":{"op":"delete_tree","path":"C:\\x"}}"#
            .to_vec(),
        vec![b' '; crate::fc_worker::MAX_FRAME_BYTES + 2],
    ] {
        let mut output = Vec::new();
        assert_eq!(serve(&mut bad.as_slice(), &mut output, true), 2);
        assert!(serde_json::from_slice::<WorkerReply>(&output).is_err());
    }
}

#[cfg(windows)]
mod windows {
    use super::*;
    use crate::fc_worker::exec::CHILD_ENVIRONMENT;
    use crate::fc_worker::{perform, JobLauncher};
    use crate::full_control_dispatch::{run_in_worker, AuthorityPort, JobGrant, WorkerLauncher};
    use crate::full_control_dispatch_tests::{lease, request, FakeApproval};
    use orcel_authority::caller::CallerFacts;
    use orcel_authority::core::dispatch_jobs::JobHost;
    use orcel_authority::lease::{LeaseBody, LeaseScope};
    use orcel_authority::protocol::{AuthorizeClaims, DispatchOutcome};
    use orcel_authority::win::jobs::{ClientProcess, ClientSlot, ServiceJobs};
    use orcel_contracts::ExecutorClass;
    use orcel_provider_fs::ProviderError;
    use serde_json::{json, Value};
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{Arc, Mutex};

    static NEXT: AtomicU32 = AtomicU32::new(0);

    fn unique() -> String {
        format!(
            "{:08x}{:08x}{:016x}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
            orcel_authority::now_ms()
        )
    }

    /// The `orceld.exe` cargo built for this test run (beside `deps`).
    fn orceld_exe() -> PathBuf {
        let exe = std::env::current_exe().expect("this test's path");
        let built = exe
            .parent()
            .and_then(Path::parent)
            .map(|dir| dir.join("orceld.exe"))
            .expect("the target directory");
        assert!(
            built.is_file(),
            "cargo builds orceld.exe for the orceld tests: {}",
            built.display()
        );
        built
    }

    fn root() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("orceld-wp110-{}", unique()));
        std::fs::create_dir_all(&dir).expect("root");
        std::fs::canonicalize(&dir)
            .ok()
            .and_then(|path| {
                path.to_str()
                    .and_then(|text| text.strip_prefix(r"\\?\"))
                    .map(PathBuf::from)
            })
            .expect("a drive path")
    }

    /// This test process as the service would observe it on the pipe.
    fn this_process() -> CallerFacts {
        let opened = ClientProcess::open(std::process::id()).expect("open this process");
        CallerFacts {
            pid: opened.pid,
            process_generation: opened.generation,
            image: String::new(),
            user_sid: orcel_authority::win::current_process_sid().expect("sid"),
            logon_session_id: 1,
            ts_session_id: 1,
            interactive: true,
            console_session: true,
            elevated: false,
        }
    }

    /// A stand-in authority service that makes a real, unnamed Job Object
    /// per dispatch, duplicates an assign-only handle into this process (as
    /// the service does into orceld), and ends the job on the outcome.
    struct JobPort {
        lease: LeaseBody,
        slot: ClientSlot,
        jobs: RefCell<ServiceJobs>,
        /// Authorization id to job id, while the job is held.
        held: RefCell<BTreeMap<String, String>>,
        /// Ends the job right after the answer (a revoke before the resume).
        revoke_after_authorize: bool,
        outcomes: RefCell<Vec<(DispatchOutcome, Option<FailureCode>)>>,
    }

    impl JobPort {
        fn new(root: &Path) -> Self {
            let scope = LeaseScope::DesktopFullUser {
                executors: vec![ExecutorClass::Filesystem, ExecutorClass::ShellProcess],
                roots: vec![root.display().to_string()],
                shells: true,
            };
            let slot: ClientSlot = Arc::new(Mutex::new(None));
            Self {
                lease: lease('5', scope),
                jobs: RefCell::new(ServiceJobs::new(slot.clone())),
                slot,
                held: RefCell::new(BTreeMap::new()),
                revoke_after_authorize: false,
                outcomes: RefCell::new(Vec::new()),
            }
        }

        fn make_job(&self) -> (String, u64) {
            *self.slot.lock().expect("slot") =
                Some(ClientProcess::open(std::process::id()).expect("open"));
            let id = format!("fcj-{}", &format!("{}{}", unique(), unique())[..32]);
            let job = self
                .jobs
                .borrow_mut()
                .create(&id, &this_process())
                .expect("job");
            (job.id, job.handle)
        }
    }

    impl AuthorityPort for JobPort {
        fn installed(&self) -> bool {
            true
        }
        fn deprecated_desktop_check(&self) -> Result<(), ProviderError> {
            Err(ProviderError::new(
                FailureCode::InternalError,
                "never consulted",
            ))
        }
        fn leases(&self) -> Result<Vec<LeaseBody>, ProviderError> {
            Ok(vec![self.lease.clone()])
        }
        fn authorize(
            &self,
            lease_id: &str,
            _executor: ExecutorClass,
            _claims: AuthorizeClaims,
        ) -> Result<Value, ProviderError> {
            let (id, handle) = self.make_job();
            let authorization = format!("az-{}", &format!("{}{}", unique(), unique())[..32]);
            if self.revoke_after_authorize {
                self.jobs.borrow_mut().terminate(&id);
            } else {
                self.held
                    .borrow_mut()
                    .insert(authorization.clone(), id.clone());
            }
            Ok(json!({
                "authorization_id": authorization,
                "lease_id": lease_id,
                "job_id": id,
                "job_handle": handle,
            }))
        }
        fn outcome(
            &self,
            authorization_id: &str,
            outcome: DispatchOutcome,
            code: Option<FailureCode>,
        ) -> Result<(), ProviderError> {
            if let Some(id) = self.held.borrow_mut().remove(authorization_id) {
                self.jobs.borrow_mut().terminate(&id);
            }
            self.outcomes.borrow_mut().push((outcome, code));
            Ok(())
        }
        fn dispatch_active(&self, authorization_id: &str) -> Result<(), ProviderError> {
            if self.held.borrow().contains_key(authorization_id) {
                Ok(())
            } else {
                Err(ProviderError::new(
                    FailureCode::LeaseInvalid,
                    "the dispatch's lease ended or its Job Object was terminated",
                ))
            }
        }
        fn release_job_handle(&self, handle: u64) {
            // SAFETY: a handle this test duplicated into itself.
            unsafe { windows_sys::Win32::Foundation::CloseHandle(handle as _) };
        }
    }

    fn run(port: &JobPort, op: WorkerOp) -> Result<Value, ProviderError> {
        let launcher = JobLauncher::with_program(orceld_exe());
        let request = request(
            "full_control.fs",
            op.name(),
            serde_json::to_value(&op).expect("op"),
        );
        run_in_worker(port, &launcher, &FakeApproval::default(), &request, None, 5)
    }

    #[test]
    fn fc_worker_runs_filesystem_operations_inside_the_service_job_end_to_end() {
        let root = root();
        let port = JobPort::new(&root);
        let file = root.join("note.txt").display().to_string();
        let written = run(
            &port,
            WorkerOp::WriteText {
                path: file.clone(),
                text: "hello from the job".to_owned(),
                create_new: true,
            },
        )
        .expect("write inside the job");
        assert_eq!(written["bytes"], 18);
        assert_eq!(
            std::fs::read_to_string(&file).expect("written by the worker"),
            "hello from the job"
        );
        let read = run(
            &port,
            WorkerOp::ReadText {
                path: file.clone(),
                max_bytes: 5,
            },
        )
        .expect("read");
        assert_eq!(read["text"], "hello");
        assert_eq!(read["truncated"], true);
        run(
            &port,
            WorkerOp::Mkdir {
                path: root.join("sub").display().to_string(),
            },
        )
        .expect("mkdir");
        let listed = run(
            &port,
            WorkerOp::List {
                path: root.display().to_string(),
                max_entries: 10,
            },
        )
        .expect("list");
        assert_eq!(
            listed["entries"],
            json!([{"name": "note.txt", "kind": "file"}, {"name": "sub", "kind": "dir"}])
        );
        let stat = run(&port, WorkerOp::Stat { path: file.clone() }).expect("stat");
        assert_eq!(stat["kind"], "file");
        // Replacing works on a file with one name.
        run(
            &port,
            WorkerOp::WriteText {
                path: file.clone(),
                text: "short".to_owned(),
                create_new: false,
            },
        )
        .expect("replace");
        assert_eq!(std::fs::read_to_string(&file).expect("replaced"), "short");
        // An existing file is not replaced by create_new; the failure is
        // the worker's, reported as the outcome.
        let again = run(
            &port,
            WorkerOp::WriteText {
                path: file,
                text: "x".to_owned(),
                create_new: true,
            },
        );
        assert_eq!(
            again.err().map(|e| e.code),
            Some(FailureCode::ProviderUnavailable)
        );
        let outcomes = port.outcomes.borrow();
        assert_eq!(outcomes.len(), 7);
        assert!(outcomes[..6]
            .iter()
            .all(|(outcome, _)| *outcome == DispatchOutcome::Succeeded));
        assert_eq!(outcomes[6].0, DispatchOutcome::Failed);
        assert!(port.held.borrow().is_empty(), "every job ended");
        assert!(JobLauncher::this_orceld().is_ok());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Review of 291e045e: a revoke between Authorize and the resume. The
    /// worker was assigned while suspended and is terminated without having
    /// run: the file it would have written does not exist.
    #[test]
    fn fc_worker_a_revoke_before_the_resume_means_the_worker_never_runs() {
        let root = root();
        let mut port = JobPort::new(&root);
        port.revoke_after_authorize = true;
        let file = root.join("never.txt");
        let refused = run(
            &port,
            WorkerOp::WriteText {
                path: file.display().to_string(),
                text: "x".to_owned(),
                create_new: true,
            },
        );
        assert_eq!(
            refused.err().map(|e| e.code),
            Some(FailureCode::LeaseInvalid)
        );
        assert!(!file.exists());
        assert_eq!(
            port.outcomes.borrow().as_slice(),
            [(DispatchOutcome::Failed, Some(FailureCode::LeaseInvalid))]
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The worker is in the job before it can run: while the launcher asks
    /// for confirmation the job already holds it (suspended); a refusal
    /// terminates it.
    #[test]
    fn fc_worker_is_in_the_job_before_it_runs_and_a_refusal_ends_it() {
        let root = root();
        let port = JobPort::new(&root);
        let (id, handle) = port.make_job();
        let launcher = JobLauncher::with_program(orceld_exe());
        let seen = std::cell::Cell::new(None);
        let refused = launcher.run(
            &JobGrant {
                id: id.clone(),
                handle,
            },
            &[root.display().to_string()],
            &WorkerOp::Stat {
                path: root.display().to_string(),
            },
            &|| {
                seen.set(port.jobs.borrow().active_processes(&id));
                Err(ProviderError::new(FailureCode::LeaseInvalid, "revoked"))
            },
        );
        assert_eq!(
            refused.err().map(|e| e.code),
            Some(FailureCode::LeaseInvalid)
        );
        assert_eq!(seen.get(), Some(1), "assigned before confirmation");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        while port.jobs.borrow().active_processes(&id) != Some(0)
            && std::time::Instant::now() < deadline
        {
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert_eq!(port.jobs.borrow().active_processes(&id), Some(0));
        port.jobs.borrow_mut().terminate(&id);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Review of 291e045e (low 3): a hard link inside the roots to a file
    /// outside them is never written through.
    #[test]
    fn fc_worker_never_uses_a_hard_link() {
        let root = root();
        let outside = root.with_extension("outside-hl");
        std::fs::create_dir_all(&outside).expect("outside");
        let target = outside.join("victim.txt");
        std::fs::write(&target, "original").expect("victim");
        let link = root.join("alias.txt");
        std::fs::hard_link(&target, &link).expect("a hard link needs no privilege");
        let roots = vec![root.display().to_string()];
        for create_new in [false, true] {
            let refused = perform(
                &WorkerOp::WriteText {
                    path: link.display().to_string(),
                    text: "planted".to_owned(),
                    create_new,
                },
                &roots,
            );
            assert!(refused.is_err(), "create_new {create_new}");
        }
        let refused = perform(
            &WorkerOp::WriteText {
                path: link.display().to_string(),
                text: "planted".to_owned(),
                create_new: false,
            },
            &roots,
        );
        assert_eq!(refused.err().map(|e| e.code), Some(FailureCode::PathEscape));
        assert_eq!(
            std::fs::read_to_string(&target).expect("victim"),
            "original"
        );
        // Re-review: nor is it read or described.
        for op in [
            WorkerOp::ReadText {
                path: link.display().to_string(),
                max_bytes: 64,
            },
            WorkerOp::Stat {
                path: link.display().to_string(),
            },
        ] {
            assert_eq!(
                perform(&op, &roots).err().map(|e| e.code),
                Some(FailureCode::PathEscape),
                "{op:?}"
            );
        }
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
    }

    #[test]
    fn fc_worker_resolves_links_and_stays_inside_the_roots() {
        let root = root();
        let outside = root.with_extension("outside");
        std::fs::create_dir_all(&outside).expect("outside");
        std::fs::write(outside.join("secret.txt"), "outside").expect("secret");
        let link = root.join("escape");
        let made = std::process::Command::new("cmd")
            .args(["/d", "/c", "mklink", "/J"])
            .arg(&link)
            .arg(&outside)
            .output()
            .expect("mklink");
        assert!(made.status.success(), "a junction needs no privilege");
        let roots = vec![root.display().to_string()];
        let through = link.join("secret.txt").display().to_string();
        for op in [
            WorkerOp::ReadText {
                path: through.clone(),
                max_bytes: 64,
            },
            WorkerOp::Stat {
                path: through.clone(),
            },
            WorkerOp::WriteText {
                path: link.join("planted.txt").display().to_string(),
                text: "x".to_owned(),
                create_new: true,
            },
        ] {
            let refused = perform(&op, &roots);
            assert_eq!(
                refused.err().map(|e| e.code),
                Some(FailureCode::PathEscape),
                "{op:?}"
            );
        }
        assert!(!outside.join("planted.txt").exists());
        // Writing over the junction itself is refused too.
        let over = perform(
            &WorkerOp::WriteText {
                path: link.display().to_string(),
                text: "x".to_owned(),
                create_new: false,
            },
            &roots,
        );
        assert_eq!(over.err().map(|e| e.code), Some(FailureCode::PathEscape));
        // Lexically outside, never touched.
        let lexical = perform(
            &WorkerOp::Stat {
                path: outside.display().to_string(),
            },
            &roots,
        );
        assert_eq!(lexical.err().map(|e| e.code), Some(FailureCode::PathEscape));
        let _ = std::fs::remove_dir(&link);
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
    }

    // -----------------------------------------------------------------
    // WP1-15: the process and git families (SG132_SLICE4.md).
    // -----------------------------------------------------------------

    /// The file in a helper's working folder that says what it does.
    const MODE_FILE: &str = "orcel-fc-helper-mode";
    /// The helper program's name inside the roots.
    const HELPER_EXE: &str = "fchelper.exe";
    /// A variable the test process holds and no started program may see.
    const SECRET: &str = "ORCEL_FC_WORKER_TEST_SECRET_TOKEN";

    /// Not a test of its own: the program the process tests run (a copy
    /// of this test binary inside the roots). Its environment is scrubbed,
    /// so it reads what to do from [`MODE_FILE`] in its working folder;
    /// without that file (every ordinary test run) it does nothing.
    #[test]
    fn fc_worker_helper_child() {
        let Ok(mode) = std::fs::read_to_string(MODE_FILE) else {
            return;
        };
        match mode.trim() {
            "env" => {
                for (name, _) in std::env::vars_os() {
                    println!("ENV:{}", name.to_string_lossy());
                }
            }
            "sleep" => std::thread::sleep(std::time::Duration::from_secs(30)),
            "flood" => {
                let line = "x".repeat(1_000);
                for _ in 0..200 {
                    println!("{line}");
                }
            }
            "spawn" => {
                // A grandchild that inherits stdout (so it holds the
                // worker's capture pipe) and writes late.txt after 5 s.
                let late = std::env::current_dir().expect("cwd").join("late");
                // Deliberately not waited for: it must outlive this process.
                #[allow(clippy::zombie_processes)]
                let _grandchild = std::process::Command::new(std::env::current_exe().expect("exe"))
                    .args(std::env::args().skip(1))
                    .current_dir(&late)
                    .stdin(std::process::Stdio::null())
                    .spawn()
                    .expect("start the grandchild");
            }
            "late" => {
                std::thread::sleep(std::time::Duration::from_secs(5));
                std::fs::write("late.txt", "the job did not end me").expect("late");
            }
            "exit7" => std::process::exit(7),
            _ => std::process::exit(3),
        }
    }

    /// A root holding a copy of this test binary as [`HELPER_EXE`], and a
    /// working folder `name` in it with the mode file.
    fn helper_root(name: &str, mode: &str) -> (PathBuf, PathBuf) {
        let root = root();
        std::fs::copy(
            std::env::current_exe().expect("this test binary"),
            root.join(HELPER_EXE),
        )
        .expect("copy the helper into the root");
        let cwd = root.join(name);
        std::fs::create_dir_all(&cwd).expect("cwd");
        std::fs::write(cwd.join(MODE_FILE), mode).expect("mode");
        (root, cwd)
    }

    fn helper_op(root: &Path, cwd: &Path, timeout_ms: u64, max_output_bytes: usize) -> WorkerOp {
        WorkerOp::Run {
            program: root.join(HELPER_EXE).display().to_string(),
            args: vec![
                "--exact".to_owned(),
                "fc_worker_tests::windows::fc_worker_helper_child".to_owned(),
                "--nocapture".to_owned(),
                "--test-threads=1".to_owned(),
            ],
            cwd: cwd.display().to_string(),
            timeout_ms,
            max_output_bytes,
        }
    }

    #[test]
    fn fc_worker_runs_a_program_in_the_job_with_a_scrubbed_environment() {
        std::env::set_var(SECRET, "must-not-reach-the-child");
        let (root, cwd) = helper_root("env", "env");
        let port = JobPort::new(&root);
        let ran = run(&port, helper_op(&root, &cwd, 30_000, 64 * 1024)).expect("ran in the job");
        assert_eq!(ran["exit_code"], 0, "{ran}");
        assert_eq!(ran["output_complete"], true);
        let names: Vec<String> = ran["stdout"]
            .as_str()
            .expect("stdout")
            .lines()
            .filter_map(|line| line.strip_prefix("ENV:"))
            .map(str::to_owned)
            .collect();
        assert!(
            names
                .iter()
                .any(|name| name.eq_ignore_ascii_case("SystemRoot")),
            "{names:?}"
        );
        for name in &names {
            assert!(
                CHILD_ENVIRONMENT
                    .iter()
                    .any(|allowed| allowed.eq_ignore_ascii_case(name)),
                "{name} reached the program"
            );
        }
        assert!(!names.iter().any(|name| name == SECRET));
        // The program's exit code is reported, not turned into a failure.
        std::fs::write(cwd.join(MODE_FILE), "exit7").expect("mode");
        let seven = run(&port, helper_op(&root, &cwd, 30_000, 1_024)).expect("ran");
        assert_eq!(seven["exit_code"], 7);
        let outcomes = port.outcomes.borrow();
        assert!(outcomes
            .iter()
            .all(|(outcome, _)| *outcome == DispatchOutcome::Succeeded));
        assert!(port.held.borrow().is_empty(), "every job ended");
        drop(outcomes);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A program's descendants stay in the dispatch's job (no breakaway),
    /// keep no pipe of orceld's, and end when the job is terminated.
    #[test]
    fn fc_worker_descendants_stay_in_the_job_and_end_with_it() {
        let (root, cwd) = helper_root("spawn", "spawn");
        let late = cwd.join("late");
        std::fs::create_dir_all(&late).expect("late");
        std::fs::write(late.join(MODE_FILE), "late").expect("mode");
        let port = JobPort::new(&root);
        let (id, handle) = port.make_job();
        let launcher = JobLauncher::with_program(orceld_exe());
        let ran = launcher
            .run(
                &JobGrant {
                    id: id.clone(),
                    handle,
                },
                &[root.display().to_string()],
                &helper_op(&root, &cwd, 30_000, 4_096),
                &|| Ok(()),
            )
            .expect("the worker replied although a descendant still runs");
        assert_eq!(ran["exit_code"], 0, "{ran}");
        assert_eq!(
            ran["output_complete"], false,
            "the grandchild held the capture pipe"
        );
        let held = port.jobs.borrow().active_processes(&id);
        assert!(
            held.is_some_and(|count| count >= 1),
            "the grandchild is in the job: {held:?}"
        );
        port.jobs.borrow_mut().terminate(&id);
        std::thread::sleep(std::time::Duration::from_secs(7));
        assert!(
            !late.join("late.txt").exists(),
            "terminating the job ended the grandchild"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn fc_worker_a_run_has_a_timeout_and_bounded_output() {
        let (root, cwd) = helper_root("sleep", "sleep");
        let port = JobPort::new(&root);
        let started = std::time::Instant::now();
        let slow = run(&port, helper_op(&root, &cwd, 1_500, 1_024));
        assert_eq!(
            slow.err().map(|e| e.code),
            Some(FailureCode::ProcessTimeout)
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(20));
        assert_eq!(
            port.outcomes.borrow().last().cloned(),
            Some((DispatchOutcome::Failed, Some(FailureCode::ProcessTimeout)))
        );
        std::fs::write(cwd.join(MODE_FILE), "flood").expect("mode");
        let flood = run(&port, helper_op(&root, &cwd, 30_000, 1_000)).expect("ran");
        assert_eq!(flood["stdout"].as_str().map(str::len), Some(1_000));
        assert_eq!(flood["stdout_truncated"], true);
        assert!(flood["stdout_bytes"].as_u64().is_some_and(|n| n >= 200_000));
        for (timeout_ms, max_output_bytes) in
            [(0, 1_000), (50_001, 1_000), (1_000, 0), (1_000, 65_537)]
        {
            let refused = perform(
                &helper_op(&root, &cwd, timeout_ms, max_output_bytes),
                &[root.display().to_string()],
            );
            assert_eq!(
                refused.err().map(|e| e.code),
                Some(FailureCode::InvalidRequest)
            );
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn fc_worker_runs_only_resolved_exe_programs_inside_the_roots() {
        let (root, cwd) = helper_root("paths", "exit7");
        let roots = vec![root.display().to_string()];
        let outside = root.with_extension("outside-exe");
        std::fs::create_dir_all(&outside).expect("outside");
        std::fs::copy(root.join(HELPER_EXE), outside.join(HELPER_EXE)).expect("copy");
        let attempt = |program: PathBuf| {
            perform(
                &WorkerOp::Run {
                    program: program.display().to_string(),
                    args: Vec::new(),
                    cwd: cwd.display().to_string(),
                    timeout_ms: 5_000,
                    max_output_bytes: 64,
                },
                &roots,
            )
            .err()
            .map(|e| e.code)
        };
        // Lexically outside, and through a junction out of the root.
        assert_eq!(
            attempt(outside.join(HELPER_EXE)),
            Some(FailureCode::PathEscape)
        );
        let link = root.join("escape");
        let made = std::process::Command::new("cmd")
            .args(["/d", "/c", "mklink", "/J"])
            .arg(&link)
            .arg(&outside)
            .output()
            .expect("mklink");
        assert!(made.status.success());
        assert_eq!(
            attempt(link.join(HELPER_EXE)),
            Some(FailureCode::PathEscape)
        );
        // A hard link inside the roots (in-box Windows programs have
        // WinSxS names too).
        std::fs::hard_link(outside.join(HELPER_EXE), root.join("alias.exe")).expect("hard link");
        assert_eq!(
            attempt(root.join("alias.exe")),
            Some(FailureCode::PathEscape)
        );
        // Shells, launchers and Git by name; scripts and batch files by
        // kind. A copy is refused by its name before it is ever started.
        for name in [
            "cmd.exe",
            "PowerShell.exe",
            "schtasks.exe",
            "wmic.exe",
            "explorer.exe",
            "rundll32.exe",
            "mshta.exe",
            "git.exe",
        ] {
            std::fs::copy(root.join(HELPER_EXE), root.join(name)).expect("copy");
            assert_eq!(
                attempt(root.join(name)),
                Some(FailureCode::CapabilityDenied),
                "{name}"
            );
        }
        for name in ["run.bat", "run.cmd", "run.ps1", "run.com", "noext"] {
            std::fs::write(root.join(name), "echo hi").expect("script");
            assert_eq!(
                attempt(root.join(name)),
                Some(FailureCode::CapabilityDenied),
                "{name}"
            );
        }
        // A working folder outside the roots.
        let refused = perform(
            &WorkerOp::Run {
                program: root.join(HELPER_EXE).display().to_string(),
                args: Vec::new(),
                cwd: outside.display().to_string(),
                timeout_ms: 5_000,
                max_output_bytes: 64,
            },
            &roots,
        );
        assert_eq!(refused.err().map(|e| e.code), Some(FailureCode::PathEscape));
        let _ = std::fs::remove_dir(&link);
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
    }

    /// Git for the test's own setup, with no system or global config.
    fn setup_git(cwd: &Path, args: &[&str]) {
        let status =
            std::process::Command::new(crate::fc_worker::exec::git_program().expect("Git"))
                .args(args)
                .current_dir(cwd)
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .status()
                .expect("git");
        assert!(status.success(), "{args:?}");
    }

    /// A repository whose hooks, configuration and attributes each try to
    /// run a program that leaves a marker file next to the repository.
    fn hostile_repository(root: &Path) -> (PathBuf, Vec<PathBuf>) {
        let repo = root.join("repo");
        std::fs::create_dir_all(&repo).expect("repo");
        setup_git(&repo, &["init", "-q", "-b", "main"]);
        setup_git(&repo, &["config", "user.name", "Orcel Test"]);
        setup_git(&repo, &["config", "user.email", "orcel@example.invalid"]);
        // A first commit, made before anything hostile is planted (the
        // provider's mutations need a HEAD).
        std::fs::write(repo.join("a.txt"), "zero\n").expect("a");
        setup_git(&repo, &["add", "a.txt"]);
        setup_git(&repo, &["commit", "-q", "-m", "initial"]);
        let marker = |name: &str| root.join(format!("marker-{name}"));
        let shell = |name: &str| {
            format!(
                "echo ran > '{}'",
                marker(name).display().to_string().replace('\\', "/")
            )
        };
        let hook = |name: &str| format!("#!/bin/sh\n{}\n", shell(name));
        let hooks = repo.join(".git").join("hooks");
        for name in [
            "pre-commit",
            "commit-msg",
            "post-commit",
            "post-checkout",
            "post-index-change",
        ] {
            std::fs::write(hooks.join(name), hook(name)).expect("hook");
        }
        let custom = repo.join("myhooks");
        std::fs::create_dir_all(&custom).expect("custom hooks");
        for name in ["pre-commit", "post-commit", "post-checkout"] {
            std::fs::write(custom.join(name), hook(&format!("custom-{name}"))).expect("hook");
        }
        setup_git(&repo, &["config", "core.hooksPath", "myhooks"]);
        for (key, name) in [
            ("core.fsmonitor", "fsmonitor"),
            ("core.pager", "pager"),
            ("diff.external", "diff-external"),
            ("gpg.program", "gpg"),
            ("core.sshCommand", "ssh"),
            ("core.askPass", "askpass"),
            ("credential.helper", "credential"),
            ("filter.evil.clean", "filter-clean"),
            ("filter.evil.smudge", "filter-smudge"),
            ("filter.evil.process", "filter-process"),
            ("diff.evil.textconv", "textconv"),
        ] {
            setup_git(
                &repo,
                &["config", key, &format!("!sh -c \"{}\"", shell(name))],
            );
        }
        setup_git(&repo, &["config", "commit.gpgSign", "true"]);
        setup_git(&repo, &["config", "log.showSignature", "true"]);
        setup_git(&repo, &["config", "filter.evil.required", "true"]);
        std::fs::write(
            repo.join(".gitattributes"),
            "*.evil filter=evil diff=evil\n",
        )
        .expect("attributes");
        std::fs::write(repo.join("a.txt"), "one\n").expect("a");
        let markers = [
            "pre-commit",
            "commit-msg",
            "post-commit",
            "post-checkout",
            "post-index-change",
            "custom-pre-commit",
            "custom-post-commit",
            "custom-post-checkout",
            "fsmonitor",
            "pager",
            "diff-external",
            "gpg",
            "ssh",
            "askpass",
            "credential",
            "filter-clean",
            "filter-smudge",
            "filter-process",
            "textconv",
        ]
        .iter()
        .map(|name| marker(name))
        .collect();
        (repo, markers)
    }

    #[test]
    fn fc_worker_git_honors_no_hook_or_hostile_configuration() {
        let root = root();
        let (repo, markers) = hostile_repository(&root);
        let port = JobPort::new(&root);
        let repository = repo.display().to_string();
        let status = run(
            &port,
            WorkerOp::GitStatus {
                repository: repository.clone(),
            },
        )
        .expect("status");
        assert!(
            status["porcelain_v2"]
                .as_str()
                .is_some_and(|text| text.contains("a.txt")),
            "{status}"
        );
        run(
            &port,
            WorkerOp::GitAdd {
                repository: repository.clone(),
                paths: vec!["a.txt".to_owned(), ".gitattributes".to_owned()],
            },
        )
        .expect("add");
        let diff = run(
            &port,
            WorkerOp::GitDiff {
                repository: repository.clone(),
                staged: true,
            },
        )
        .expect("diff");
        assert!(
            diff["diff"]
                .as_str()
                .is_some_and(|text| text.contains("+one")),
            "{diff}"
        );
        let committed = run(
            &port,
            WorkerOp::GitCommit {
                repository: repository.clone(),
                message: "first".to_owned(),
            },
        )
        .expect("commit with hooks and signing disabled");
        assert_eq!(committed["branch"], "main");
        run(
            &port,
            WorkerOp::GitBranchCreate {
                repository: repository.clone(),
                branch: "topic".to_owned(),
            },
        )
        .expect("branch");
        std::fs::write(repo.join("b.txt"), "two\n").expect("b");
        run(
            &port,
            WorkerOp::GitAdd {
                repository: repository.clone(),
                paths: vec!["b.txt".to_owned()],
            },
        )
        .expect("add b");
        run(
            &port,
            WorkerOp::GitUnstage {
                repository: repository.clone(),
                paths: vec!["b.txt".to_owned()],
            },
        )
        .expect("unstage b");
        let log = run(
            &port,
            WorkerOp::GitLog {
                repository: repository.clone(),
                max_count: 5,
            },
        )
        .expect("log");
        assert_eq!(log["commits"][0]["subject"], "first");
        // A file under a configured filter driver is refused, not filtered.
        std::fs::write(repo.join("x.evil"), "x\n").expect("x");
        let filtered = run(
            &port,
            WorkerOp::GitAdd {
                repository: repository.clone(),
                paths: vec!["x.evil".to_owned()],
            },
        );
        assert!(filtered.is_err(), "{filtered:?}");
        for marker in &markers {
            assert!(!marker.exists(), "{} ran", marker.display());
        }
        assert!(port.held.borrow().is_empty(), "every job ended");
        // Control: the same repository with plain Git does run its hook,
        // so the absence above is the worker's hardening, not a dead hook.
        let _ = std::process::Command::new(crate::fc_worker::exec::git_program().expect("Git"))
            .args(["-c", "commit.gpgSign=false", "-c", "core.fsmonitor=false"])
            .args(["commit", "-q", "--allow-empty", "-m", "control"])
            .current_dir(&repo)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .status();
        assert!(
            root.join("marker-custom-pre-commit").exists(),
            "plain Git runs the planted hook"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn fc_worker_git_refuses_injected_options_and_repositories_outside_the_roots() {
        let root = root();
        let (repo, markers) = hostile_repository(&root);
        let roots = vec![root.display().to_string()];
        let repository = repo.display().to_string();
        let code = |op: WorkerOp| perform(&op, &roots).err().map(|e| e.code);
        // Options where a branch name or a path belongs.
        for branch in ["-c core.sshCommand=evil", "--upload-pack=evil", "-f"] {
            assert_eq!(
                code(WorkerOp::GitBranchCreate {
                    repository: repository.clone(),
                    branch: branch.to_owned(),
                }),
                Some(FailureCode::InvalidRequest),
                "{branch}"
            );
        }
        for path in [
            "--upload-pack=evil",
            ":(glob)*",
            "../outside.txt",
            ".git/config",
        ] {
            assert!(
                code(WorkerOp::GitAdd {
                    repository: repository.clone(),
                    paths: vec![path.to_owned()],
                })
                .is_some(),
                "{path}"
            );
        }
        // A commit message that looks like an option is only a message.
        std::fs::write(repo.join("a.txt"), "one\n").expect("a");
        perform(
            &WorkerOp::GitAdd {
                repository: repository.clone(),
                paths: vec!["a.txt".to_owned()],
            },
            &roots,
        )
        .expect("add");
        let committed = perform(
            &WorkerOp::GitCommit {
                repository: repository.clone(),
                message: "--upload-pack=evil".to_owned(),
            },
            &roots,
        )
        .expect("commit");
        assert_eq!(committed["branch"], "main");
        // A repository outside the roots, or whose Git directory is
        // outside them (a .git file pointing out), is refused.
        let outside = root.with_extension("outside-repo");
        std::fs::create_dir_all(&outside).expect("outside");
        setup_git(&outside, &["init", "-q"]);
        assert_eq!(
            code(WorkerOp::GitStatus {
                repository: outside.display().to_string(),
            }),
            Some(FailureCode::PathEscape)
        );
        let pointer = root.join("pointer");
        std::fs::create_dir_all(&pointer).expect("pointer");
        std::fs::write(
            pointer.join(".git"),
            format!("gitdir: {}\n", outside.join(".git").display()),
        )
        .expect(".git file");
        assert_eq!(
            code(WorkerOp::GitStatus {
                repository: pointer.display().to_string(),
            }),
            Some(FailureCode::PathEscape)
        );
        for marker in &markers {
            assert!(!marker.exists(), "{} ran", marker.display());
        }
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
    }
}
