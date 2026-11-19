//! SG-000132 WP1-12: `orceld fc-worker`. The request and reply contract on
//! every OS; on Windows, the real worker (the built `orceld.exe`) launched
//! into real Job Objects made in this unelevated test process the way the
//! service makes them (`Local\` namespace, a stand-in service SID), the
//! operations inside the roots, and the refusals: a job gone before the
//! launch, a job this session could terminate, a junction out of the root.

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
    use crate::full_control_dispatch::{run_in_worker, AuthorityPort, WorkerLauncher};
    use crate::full_control_dispatch_tests::{lease, request};
    use orcel_authority::core::dispatch_jobs::{job_name, JobHost};
    use orcel_authority::lease::{LeaseBody, LeaseScope};
    use orcel_authority::protocol::{AuthorizeClaims, DispatchOutcome};
    use orcel_authority::win::jobs::ServiceJobs;
    use orcel_contracts::ExecutorClass;
    use orcel_provider_fs::ProviderError;
    use serde_json::{json, Value};
    use std::cell::RefCell;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU32, Ordering};

    /// Any SID this process is not, standing in for the service's.
    const STAND_IN_SERVICE_SID: &str = "S-1-5-18";

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

    /// A stand-in authority service that makes a real Job Object per
    /// dispatch, as the service does, and ends it on the outcome.
    struct JobPort {
        lease: LeaseBody,
        jobs: RefCell<ServiceJobs>,
        /// Ends the job right after Authorize (a revoke in between).
        revoke_after_authorize: bool,
        outcomes: RefCell<Vec<(DispatchOutcome, Option<FailureCode>)>>,
    }

    impl JobPort {
        fn new(root: &Path) -> Self {
            Self::with_service_sid(root, STAND_IN_SERVICE_SID)
        }

        fn with_service_sid(root: &Path, service_sid: &str) -> Self {
            let scope = LeaseScope::DesktopFullUser {
                executors: vec![ExecutorClass::Filesystem],
                roots: vec![root.display().to_string()],
                shells: false,
            };
            Self {
                lease: lease('5', scope),
                jobs: RefCell::new(ServiceJobs::new("Local", service_sid)),
                revoke_after_authorize: false,
                outcomes: RefCell::new(Vec::new()),
            }
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
            let name = job_name("Local", &unique());
            let me = orcel_authority::win::current_process_sid()
                .map_err(|e| ProviderError::new(e.code, e.message))?;
            self.jobs
                .borrow_mut()
                .create(&name, &me)
                .map_err(|e| ProviderError::new(e.code, e.message))?;
            if self.revoke_after_authorize {
                self.jobs.borrow_mut().terminate(&name);
            }
            Ok(json!({
                "authorization_id": format!("az-{}", "4".repeat(32)),
                "lease_id": lease_id,
                "job_name": name,
            }))
        }
        fn outcome(
            &self,
            _authorization_id: &str,
            outcome: DispatchOutcome,
            code: Option<FailureCode>,
        ) -> Result<(), ProviderError> {
            self.outcomes.borrow_mut().push((outcome, code));
            Ok(())
        }
        fn jobs_are_service_owned(&self) -> bool {
            true
        }
    }

    fn fs_request() -> orcel_contracts::RequestEnvelope {
        request("full_control.fs", "worker", json!({}))
    }

    fn run(port: &JobPort, op: WorkerOp) -> Result<Value, ProviderError> {
        let launcher = JobLauncher::with_program(orceld_exe());
        run_in_worker(port, &launcher, &fs_request(), None, &op, 5)
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
        let stat = run(&port, WorkerOp::Stat { path: file }).expect("stat");
        assert_eq!(stat["kind"], "file");
        // An existing file is not replaced by create_new; the failure is
        // the worker's, reported as the outcome.
        let again = run(
            &port,
            WorkerOp::WriteText {
                path: root.join("note.txt").display().to_string(),
                text: "x".to_owned(),
                create_new: true,
            },
        );
        assert_eq!(
            again.err().map(|e| e.code),
            Some(FailureCode::ProviderUnavailable)
        );
        let outcomes = port.outcomes.borrow();
        assert_eq!(outcomes.len(), 6);
        assert!(outcomes[..5]
            .iter()
            .all(|(outcome, _)| *outcome == DispatchOutcome::Succeeded));
        assert_eq!(outcomes[5].0, DispatchOutcome::Failed);
        assert!(JobLauncher::this_orceld().is_ok());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn fc_worker_a_job_gone_before_the_launch_is_lease_invalid() {
        let root = root();
        let mut port = JobPort::new(&root);
        port.revoke_after_authorize = true;
        let refused = run(
            &port,
            WorkerOp::Stat {
                path: root.display().to_string(),
            },
        );
        assert_eq!(
            refused.err().map(|e| e.code),
            Some(FailureCode::LeaseInvalid)
        );
        assert_eq!(
            port.outcomes.borrow().as_slice(),
            [(DispatchOutcome::Failed, Some(FailureCode::LeaseInvalid))]
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn fc_worker_refuses_a_job_this_session_could_terminate() {
        let root = root();
        let me = orcel_authority::win::current_process_sid().expect("sid");
        // A job whose "service" is this very user: not the installed
        // service's, so orceld does not use it.
        let port = JobPort::with_service_sid(&root, &me);
        let launcher = JobLauncher::with_program(orceld_exe());
        let name = job_name("Local", &unique());
        port.jobs.borrow_mut().create(&name, &me).expect("job");
        let refused = launcher.run(
            &name,
            &[root.display().to_string()],
            &WorkerOp::Stat {
                path: root.display().to_string(),
            },
            true,
        );
        assert_eq!(
            refused.err().map(|e| e.code),
            Some(FailureCode::AuthorityUnavailable)
        );
        let _ = std::fs::remove_dir_all(&root);
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
