# orcel-contain

The one-shot launcher behind Orcel's **contained** execution tier (XP-13): no
network, an exact read/write allowlist, no process creation, CPU, memory and
descriptor limits, and owned cleanup. Parsers and helpers (WI-05) run under it,
and a registered executable can opt in.

It is its own Cargo workspace so tokio never enters orceld's lockfile (AD-16).
orceld reaches it only through `crates/orcel-provider-process/src/contained.rs`,
which is std only.

## Protocol

1. orceld resolves the helper by a pinned absolute path (no `PATH` lookup),
   checks it is not writable by group or others, hashes it, and compares the
   SHA-256 with the pin. On Linux it executes the very file descriptor it
   hashed.
2. orceld starts it with an empty environment and writes one closed, bounded
   spec (at most 64 KiB) on stdin, then keeps stdin open. The format is in
   `src/spec.rs`.
3. The helper installs every boundary its platform advertises, or refuses and
   launches nothing:

   | | Boundaries |
   |---|---|
   | Linux | Landlock (ABI 3 or later) exact allowlist, seccomp (no sockets, `io_uring`, fork, `ptrace`, namespaces, mounts), `RLIMIT_AS`/`CPU`/`NOFILE`, `PR_SET_PDEATHSIG`, `PR_SET_NO_NEW_PRIVS`, `close_range` |
   | macOS | deny-by-default Seatbelt profile through `sandbox-exec`, `RLIMIT_CPU`/`NOFILE`, sampled memory ceiling, parent-death sentinel, descriptor closure |
   | Windows | capability-less AppContainer, Job Object (kill-on-close, one process, memory, CPU time, UI limits), private desktop, explicit handle list, no-follow ACL grants |

4. It runs the child, relays at most the spec's stdout and stderr bounds and the
   exit, writes one result on stdout and exits. It has no listener and reads no
   environment variable.

If orceld dies, the helper sees end of file and kills the child's tree. If the
helper is killed, the child dies through `PR_SET_PDEATHSIG`, the sentinel pipe
or the kill-on-close job.

No namespace of any type is created, so `RestrictNamespaces=yes` in
`orceld@.service` does not affect it (issue #369, item 1).

## Provenance

COPY_ADAPT of Cua's perception-worker containment,
trycua/cua@a802eaf26ca97616a6bf0de6a29729a9346fbb1f, MIT (transplant rows
T-CUA-21 and T-CUA-22). Each source file names its donor blob and lists
Orcel's changes. The notice is `docs/orcel/notices/cua-MIT.txt`.

## Tests

`cargo test --locked` here runs the unit tests and `tests/contain.rs`, which
drives the real helper through the kernel client. `orcel-contain-probe` is a
test fixture that tries each denied operation; it is never packaged.
