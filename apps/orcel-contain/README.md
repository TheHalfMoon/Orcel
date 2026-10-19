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

Roots and the executable must be named by their canonical path; a root
reached through a symbolic link or junction is refused, by the kernel client
and again by the helper, which opens it without following links.

No namespace of any type is created, so `RestrictNamespaces=yes` in
`orceld@.service` does not affect it (issue #369, item 1).

## Hard links and junctions

A hard link is a second name for a file, and the name can sit inside a root
while the file's other name is outside every root.

- Windows refuses it. A hard link shares its file's security descriptor, so an
  ACE on the link would land on the outside file. The grant walk refuses any
  file with more than one link, in every root and for the executable, and
  reads the count again after the ACE is applied; either refusal rolls back
  every grant made so far.
- Linux and macOS cannot refuse it, which is a residual risk (below). The
  boundary there is path based, so a hard link that already exists inside a
  granted root lets the contained process read (or, in a write root, write)
  the linked file through the granted path. The helper does not walk the
  roots to look for links. The contained process cannot create such a link
  itself: Landlock withholds `REFER` from every root that is not writable,
  and the Seatbelt profile grants no `file-link` at all, so on macOS even a
  file inside the write root cannot be linked. On Windows the AppContainer has
  no write-attributes right on read-only roots.
  `xp13_the_contained_process_cannot_create_a_hard_link` checks this on every
  OS, and `xp13_a_hard_link_already_in_a_granted_root` pins the behaviour of
  each OS for a link that already exists.

## Residual risks

- Linux and macOS: a hard link that already exists inside a granted root
  reaches its target, wherever that is (see above). Grant only roots that
  only Orcel and the user write to.
- Windows, denial of service by design: a junction, symbolic link or other
  reparse point anywhere inside a root, or a hard-linked file, makes every
  later launch that grants that root refuse with `launch_failed` until it is
  removed. Anyone with write access to a shared write root, a contained child
  included, can plant one. The launch fails closed: it never grants more.

- Linux: "exact executable" limits what `execve` may start, not which bytes
  run. Landlock does not mediate `mmap(PROT_EXEC)`, so readable code can be
  mapped (or run through `ld.so`), and `memfd_create` + `execveat` is not
  denied; all of it stays inside the same Landlock, seccomp and rlimit
  boundary. See `src/linux.rs`.
- Windows: a helper killed hard leaves its temporary ACEs and AppContainer
  profile behind (the child still dies with the job). They name a random,
  never-disclosed AppContainer SID. No cleanup runs on the next launch yet.
- Windows: the kernel client checks the helper's digest and holds it open
  without write or delete sharing, but does not yet check the install
  directory's DACL.
- macOS: `sandbox-exec` is deprecated by Apple (S-25).

## Provenance

COPY_ADAPT of Cua's perception-worker containment,
trycua/cua@a802eaf26ca97616a6bf0de6a29729a9346fbb1f, MIT (transplant rows
T-CUA-21 and T-CUA-22). Each source file names its donor blob and lists
Orcel's changes. The notice is `docs/orcel/notices/cua-MIT.txt`.

## Tests

`cargo test --locked` here runs the unit tests and `tests/contain.rs`, which
drives the real helper through the kernel client. `orcel-contain-probe` is a
test fixture that tries each denied operation; it is never packaged.
