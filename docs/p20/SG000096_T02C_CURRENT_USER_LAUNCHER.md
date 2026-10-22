# SG-000096 T02 / T02-C: production current-user launcher (unexposed)

Status: implementation of the T02 native launcher and the T02-C identity binding. Tracking #264 and #271; program #260. The launcher is production code in `orcel-provider-process`, but **nothing calls it yet**: orceld, MCP, relay, CLI and Safe `process.spawn` are unchanged, and `executor_enabled_now(FullUser, ShellProcess)` stays `false`. T04 owns exposure.

## What is built

`orcel_provider_process::shell` (cross-platform types and checks) and `windows_contained_launch::shell` (Windows native):

- `ExpectedNativeOwner`: user SID and logon LUID from the MAC-verified Full User lease, owner PID and creation generation from the validated runtime session. orceld derives it from verified authority state; a caller never supplies it.
- `measure_executable` pins the executable by handle (share-read only, no reparse component, SHA-256 read through the same handle) and returns the identity a user approves.
- `run_one_shot` order:
  1. Bounds and environment checks. An environment entry outside the Safe allowlist, or with a secret-like or Orcel-internal name, is **refused**, not dropped, so what was approved is what runs.
  2. The owner process is reopened by PID. It must still run, have the recorded creation generation (PID reuse is refused), the lease's SID (`EqualSid`) and logon LUID, and must not be elevated (Full Admin is refused).
  3. The executable and cwd are pinned by handle. The executable's file ID and digest must equal the approved identity.
  4. `CreateProcessW` creates the child suspended, with no AppContainer, `CREATE_NO_WINDOW`, and an exact `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` of its three stdio handles. stdin is `NUL`.
  5. The child goes into a kill-on-close Job with an active-process limit (1 to 64). Breakaway is not permitted.
  6. Before `ResumeThread`: exact Job membership; the child token is not AppContainer, has the lease SID and LUID, the owner's Windows session, and is not elevated; it has a creation generation; the mapped image's file ID equals the pinned executable; the owner is still live and the same instance.
  7. Any failure in step 6 terminates the child and the Job and proves both empty (`Denied`). If that cannot be proven, the result is `TerminationUnverified`.
  8. After resume: stdout and stderr are pumped separately without blocking. Each keeps its first N bytes and counts `total_bytes` and `dropped_bytes`. `complete` is true only when EOF was seen. On a timeout the Job is terminated and the end is `TimedOut`, with no exit status. When the primary exits, any process left in the Job is terminated (`descendants_terminated`). An unclear wait or exit-code read becomes `OutcomeUnknown`. Nothing is retried.
- Reused, not duplicated: `OwnedHandle`, `JobObject` (new `kill_on_close_with_process_limit`), `ChildProcess::from_created_process`/`terminate_verified`/`resume`, `PrivatePipe`, `null_input`, `quote_arg`/`command_line_for_paths`, the environment allowlist (`environment_block`, factored out of `environment_from_plan`), and the T02-C `snapshot_native_owner`, `native_sid_equal` and `verify_member_before_resume`. These were `#[cfg(test)]` and are now production code. `native_path_identity_windows` (T02 path identity) is promoted from test-only to production, hashing with the crate's own SHA-256.
- macOS and Linux: `run_one_shot` and `measure_executable` return `Unavailable`. The lease binds a Windows SID and logon session, so SG-000096 defines no Full User shell on those hosts. They keep the Safe and contained tiers.

## Native Windows qualification (this host)

Expected owners come from a disposable store: `grant_local` → `load_store` (MAC) → `check_full_control` → `validate_runtime_session`. That is the derivation orceld will use. A test can only grant a lease to itself, so the SID and LUID are its own; they reach the launcher only through the verified lease.

| Test | Proves |
| --- | --- |
| `sg000096_t02_current_user_one_shot_is_verified_bounded_and_quiescent` | approved launch, exit 0, lease identity on the child, process gone |
| `sg000096_t02c_owner_mismatch_is_denied_before_any_process_exists` | wrong SID, wrong LUID, owner generation drift, exited owner, malformed SID: `Denied` with **zero** `CreateProcessW` calls |
| `sg000096_t02c_pre_resume_faults_terminate_a_child_that_never_ran` | foreign Job, failed token query, wrong SID, LUID, session, elevation, generation, image, owner drift: each child is created, then denied, proven gone, and its marker file is **never written**. The same fixture unfaulted writes it. |
| `sg000096_t02_executable_and_cwd_drift_are_denied_before_creation` | wrong digest, wrong file index, bytes replaced after approval, cwd through a junction: `Denied`, no process |
| `sg000096_t02_timeout_is_typed_with_no_exit_status_and_an_empty_job` | `TimedOut`, Job empty, child gone |
| `sg000096_t02_output_is_separated_bounded_and_counts_dropped_bytes` | 1 MiB stdout and 300,000 B stderr with 4 KiB caps: exact kept, total and dropped counts |
| `sg000096_t02_unicode_and_binary_output_is_returned_exactly` | UTF-8 and raw bytes (including NUL and 0xFF) unchanged |
| `sg000096_t02_a_descendant_left_behind_is_terminated_not_detached` | a grandchild still running after the primary exits is terminated |
| `sg000096_t02_job_process_limit_bounds_the_tree` | limit 1 refuses a spawn; limit 4 allows it |
| `sg000096_t02_child_environment_is_exactly_the_allowlisted_set` | the child sees only allowlisted names; `ORCEL_DAEMON` is refused |
| `sg000096_held_paths_deny_rewrite_rename_and_ancestor_rename` | a held file cannot be rewritten, renamed or deleted, and a held directory and its ancestor cannot be renamed |
| `sg000096_junction_components_are_refused` | junction components are refused for files and directories |

- **Elevated hosts.** GitHub's `windows-latest` runner runs tests elevated (an administrator with UAC off). There, each launching test instead asserts that the launcher refuses ("Full User never runs elevated") with zero `CreateProcessW` calls. That is native CI evidence that Full Admin is refused. The owner-mismatch and drift tests run unchanged on both kinds of host. The positive native paths in the table above (launch, faults after creation, timeout, output, descendants, process limit, environment) are qualified on a standard-user host: this PC.
- `cargo test -p orcel-provider-process`: 70 lib + 2 + 4 + 2 integration tests pass. Every earlier SG-000096 T02-A/B/C test still passes.
- `cargo clippy -p orcel-provider-process --all-targets -- -D warnings` passes for `x86_64-pc-windows-msvc`, `x86_64-unknown-linux-gnu` and `aarch64-apple-darwin`.
- `cargo fmt --all --check` passes.
- `cargo test -p orcel-lifecycle --test release_blocker_sweep`: 10/10.

## Residuals (stated, not hidden)

- **Not a sandbox.** A Full User child has the user's ambient filesystem and network power. The Job bounds its lifetime and process count only. A child can still start work outside the Job through an out-of-process broker the user may use (for example the Task Scheduler, WMI or a COM server). That is ambient user power, not a Job escape this launcher can stop.
- The cwd is pinned by handle up to resume. The child's own cwd handle then keeps the directory from being deleted. The child's cwd is not read back from its PEB.
- Ancestor-rename protection relies on NTFS refusing to rename a directory that has an open descendant. The test above shows this on NTFS. Other file systems are not qualified.
- The stdio pipes are created inheritable for the duration of `CreateProcessW`, as on the Safe path. A concurrent `std::process` spawn elsewhere in orceld could inherit one. If that happens, the stream reports `complete: false` instead of hanging, because the post-exit and post-termination drains are bounded.
- The cwd's components are checked for reparse points, then the directory is opened in a separate step. A process running as the same user could swap an ancestor for a junction in between. The executable is not affected, because its file ID and digest must match the approved identity. T04 must bind the cwd too: record the cwd's file identity or final path at approval and compare it after opening.
- The stdio write ends are inheritable while the child is being created. An unrelated `std::process` child spawned at that moment could inherit one and write bytes that would be attributed to the approved command. T04 must create these pipes under a spawn lock shared with orceld's other launches, or make them inheritable only inside that lock.
- The file identity is the volume serial plus a 64-bit file index. NTFS is qualified. ReFS uses 128-bit file IDs and is not qualified.
- The child inherits orceld's own token. The SID and LUID mismatch cases are therefore shown by fault injection (changing the expected values), not by a child that really holds a different token. The expected Windows session is the owner's session; when the owner is orceld itself, that check cannot fail.
- No orceld wiring, approval prompt, session registry, stdin, or MCP tool yet. T03 adds sessions and T04 adds governed dispatch.

No donor source is copied in this slice.
