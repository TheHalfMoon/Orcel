# SG-000096 T03: bounded interactive sessions (unexposed)

Status: implementation of #265 (program #260). It builds on the T02/T02-C launcher (#426). Nothing calls the session registry yet: orceld, MCP, relay, CLI and Safe `process.spawn` are unchanged, and `executor_enabled_now(FullUser, ShellProcess)` stays `false`. T04 owns dispatch, approvals and exposure.

## What is built

`orcel_provider_process::shell_session` (cross-platform types, `OutputRing`, the `SessionRegistry` facade) and `windows_contained_launch::shell_session` (Windows supervision).

- **Launch.** A session starts exactly like a T02 one-shot. The same owner reopening, handle pinning, suspended creation, Job with a process limit and pre-resume token, image and owner checks apply. A session refused before resume is never registered. The one difference is a stdin pipe: the child's read end is inheritable and the Orcel write end is not.
- **Registry.** It is server-owned. Session IDs are `sh_` plus 32 hex digits from `BCryptGenRandom`. A caller never names a PID. At most 8 sessions run at once and 16 are retained. An ended session is evicted only to make room, and a running one never is. An unknown ID is refused.
- **Generation.** Each session starts at generation 1. Every accepted write, stdin close, terminate or revoke bumps it. A write, close, terminate or remove approved against an older generation is refused with `StaleGeneration`, so a replayed or reordered approval cannot act on a changed session.
- **Output.** stdout and stderr each go into an `OutputRing` sized by the command's limits. Offsets are absolute and only grow. When a ring is full the oldest bytes are evicted. A read from an evicted offset starts at the oldest byte still held and reports `evicted_before`. A read past the end is refused. Each read returns at most 1 MiB. `end_of_stream` is true only when the stream's end was observed and the page reaches it. Bytes are returned exactly (UTF-8, split UTF-8 and binary).
- **Input.** A frame is 1 to `stdin_frame_bytes` bytes (at most 64 KiB), and a session accepts at most `stdin_total_bytes` (at most 16 MiB) over its life. Accepted frames are delivered in order by a writer thread. `stdin_accepted_bytes` and `stdin_delivered_bytes` are reported separately. A frame counts as delivered only after the pipe took all of it, and a failed write records how much of the frame was delivered. When accepted-but-undelivered bytes would exceed 4 frames, the write is refused with `InputBusy`; it is never dropped or retried. After stdin is closed, writes are refused with `InputClosed`.
- **End.** The supervisor thread pumps output with the T02 per-call budget, so endless output cannot starve it. It ends the session on:
  - exit;
  - its deadline (the command timeout or the lease expiry orceld passes, whichever is sooner);
  - an approved terminate;
  - `revoke_all` (orceld calls this on lease revoke or expiry);
  - the runtime owner exiting or changing generation.

  Each of these ends the whole Job and proves it empty. Otherwise the state is `TerminationUnverified`. A supervision error becomes `OutcomeUnknown`. After an exit, helpers get the same settling grace as in T02, and anything still running is terminated (`descendants_terminated`). No end state is inferred from output or a prompt.
- **Daemon exit.** Dropping the registry revokes every session and joins its threads. If orceld itself dies, the kill-on-close Job ends every tree.
- **Platforms.** macOS and Linux: `start` returns `Unavailable`, and the other calls see no sessions.

## Native Windows qualification (this host)

Expected owners come from a MAC-verified disposable lease, as in T02.

| Test | Proves |
| --- | --- |
| `sg000096_t03_session_round_trips_stdin_and_denies_stale_generations` | write, echo and delivered count; a replayed generation-1 write or terminate is refused and its bytes never reach the child; Unicode input; an empty frame is refused; close gives the child EOF and it exits 0; writing after close or after exit is refused; a stale remove is refused; remove, then the ID is unknown |
| `sg000096_t03_terminate_revoke_and_expiry_end_the_whole_job` | terminate gives `Terminated` and the process is gone; a second terminate is refused; `revoke_all` gives `Revoked` for every running session; a lease expiry of 1 s ends a session whose timeout is longer, as `TimedOut` |
| `sg000096_t03_rings_evict_oldest_output_and_report_the_gap` | after 200,004 bytes into a 4 KiB ring: start offset, `evicted_before`, the exact tail, and a read past the end is refused |
| `sg000096_t03_stdin_is_bounded_and_never_reported_delivered_early` | an oversized frame is refused; a child that never reads fills the pipe until `InputBusy`; pending bytes stay within 4 frames and delivered never exceeds accepted; after terminate, undelivered bytes are reported, not invented; remove joins the writer |
| `sg000096_t03_registry_is_bounded_and_ids_are_not_guessable` | 8 live sessions with distinct random IDs; a 9th is `RegistryFull`; an unknown ID is refused; removing a running session is refused |
| `sg000096_t03_dropping_the_registry_ends_every_session` | dropping the registry ends the child |
| `sg000096_t03_a_session_denied_before_resume_is_never_registered` | a pre-resume denial leaves the registry empty |
| `shell_session::tests::*` (4) | ring offsets, eviction and paging; split UTF-8 and binary; read bound; stdin limit bounds |

- `cargo test -p orcel-provider-process --lib -- shell`: 37 tests, 8 consecutive passes with no failure.
- `cargo test -p orcel-provider-process`: 86 lib + 8 integration tests pass.
- `cargo clippy -p orcel-provider-process --all-targets -- -D warnings`: passes on the Windows, Linux and macOS targets. `cargo fmt --all --check` passes.

## Donor provenance

The ring, pagination and stdin mechanics follow the bounded terminal-session behaviour of the pinned Desktop Commander `src/terminal-manager.ts` (blob `528e2872754315751dc1559922bbf9764cdcd702`, MIT) as a **design reference only**. No donor source, structure or text is copied, so no MIT notice is triggered by this slice. Not adopted from the donor: its MCP server, `shell: true` fallback, telemetry, prompt-based completion detection and PID-based process control.

## Residuals

- **Not a sandbox.** A session child has the user's ambient filesystem and network power.
- **No soft interrupt.** There is no Ctrl+C or Ctrl+Break delivery. Ending a session means terminating its Job. A console control event would need a shared console, which a `CREATE_NO_WINDOW` child does not have.
- **Lease checks are orceld's job.** The provider ends sessions on owner loss and on the deadline it was given. Lease revocation reaches it only through `revoke_all`, so T04 must call that whenever a lease check fails or the lease changes.
- **The registry lock is held during a launch.** Status calls wait for a start, which takes at most the executable hash plus the pre-resume checks.
- **T04 obligations from the T02 judge still apply:** bind the cwd's identity at approval, and serialise pipe creation with orceld's other spawns.
