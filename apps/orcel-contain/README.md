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

## Wiring in orceld (XP-13b)

The contained tier is opt-in per registered executable, through the existing
SG-000060 registry. There is no new capability and no new authority path:

1. `executable.registry.add` takes `"tier": "contained"` under the same STRONG
   approval. The registration digest binds the tier. Without it the entry
   stays in the Safe tier, so existing registries and their checksums are
   unchanged.
2. `process.spawn` keeps its policy check, per-run approval and pre-launch
   identity check. The tier is read before approval: the approval digest
   binds it, and the prompt shows `tier=contained`. A tier that changed
   during the approval fails as `TargetStale`.
3. A contained entry runs through `run_contained`:
   - the requested cwd is granted **read-only**;
   - the child works in a fresh private scratch directory under the state
     root (`contained-runs/`), which is removed after the run;
   - nothing else of the user's is writable;
   - there is no network and no process creation, and the CPU, memory and
     descriptor ceilings apply.
4. It never falls back to the Safe tier. A missing helper, a missing or
   malformed pin, a tampered helper or a refusal is an error, and a missing
   helper fails before any prompt.

`crates/orceld/src/contained_tier.rs` holds the wiring. CI runs it end to end
on every OS (`xp13b_a_registered_contained_executable_runs_under_the_helper`):
a registered probe reads the cwd, cannot write it, and the uncontained
positive control can.

On Windows a granted file must have exactly one link (see below). This
includes the registered executable, so register a plain copy, not, for
example, a Cargo `target/` output, which Cargo hard-links into `deps/`.

## Installation

orceld resolves the helper only beside its own executable. There is no `PATH`
lookup and no environment override. It reads two files there:

- `orcel-contain` (`orcel-contain.exe` on Windows);
- `orcel-contain.sha256`, one lowercase SHA-256 line that the helper must
  match.

| OS | Where | Built by |
|---|---|---|
| Windows | the release payload, beside `orceld.exe`; both files are in `manifest.json`, so the installer verifies them | `scripts/package-release.mjs` (`--contain-target-dir`) in `build-package-qualify`, and checked by `release_qualification` and the reproducibility check |
| Linux | `/usr/lib/orcel/` from the deb or rpm (root-owned, 0755 and 0644), or `~/.local/share/orcel/bin/` from the tarball | `distribution/linux/package.sh <version> <orceld> <orcel-contain> <out>` and `nfpm.yaml` |
| macOS | not packaged | see below |

**macOS is not packaged yet.** XP-16, the signed app bundle and LaunchAgent,
waits on the Apple Developer ID (FD-05). Until then:

- a developer can place a `cargo build --release --locked --bin orcel-contain`
  output beside their own `orceld` and write its SHA-256 to
  `orcel-contain.sha256`;
- such a helper is unsigned, so nothing about it may be published;
- XP-16 must ship it inside the bundle, signed with the same identity as
  orceld, and keep the pin file.

The deb, rpm and tarball include the helper's crates in
`THIRD_PARTY_NOTICES.txt`, and the Windows SBOM lists them
(`scripts/third-party-notices.mjs` and `scripts/generate-sbom.mjs` walk this
workspace too).

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
  itself, to a file it may only read or cannot reach: Landlock withholds
  `REFER` from every root that is not writable, Seatbelt allows a link only
  where both names are writable, and on Windows the AppContainer has no
  write-attributes right on read-only roots. A link between two names inside
  the write root is allowed on every OS; it widens nothing.
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
