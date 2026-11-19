//! SG-000132 WP1-12: `orceld fc-worker`. The request and reply contract on
//! every OS; on Windows, the real worker (the built `orceld.exe`) launched
//! into real, unnamed Job Objects made in this unelevated test process the
//! way the service makes them (an assign-only handle duplicated into this
//! process), the operations inside the roots, and the refusals: a revoke
//! before the resume (the worker never runs), a junction or a hard link out
//! of the root.

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
    use crate::fc_worker::{perform, JobLauncher};
    use crate::full_control_dispatch::{run_in_worker, AuthorityPort, JobGrant, WorkerLauncher};
    use crate::full_control_dispatch_tests::{lease, request};
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
        let dir = std::env::temp_dir().join(format!("orceld-wp112-{}", unique()));
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
                executors: vec![ExecutorClass::Filesystem],
                roots: vec![root.display().to_string()],
                shells: false,
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
            "worker",
            serde_json::to_value(&op).expect("op"),
        );
        run_in_worker(port, &launcher, &request, None, 5)
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
    fn fc_worker_never_writes_through_a_hard_link() {
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
}
