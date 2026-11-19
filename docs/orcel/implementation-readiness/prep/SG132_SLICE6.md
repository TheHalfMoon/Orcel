# SG-000132 slice 6: the real MCP client at the desktop check, the host generation on every message, paths for every shell/process dispatch

Status: implemented and tested on branch `authority/wp110-followups`; not installed. Nothing in this slice was
installed or run elevated, no UAC, Windows Hello or Orcel dialog was shown or answered, and no system, registry,
firewall or ACL setting changed. No test drives real input. Earlier slices: [SG132_SLICE1.md](SG132_SLICE1.md),
[SG132_SLICE2.md](SG132_SLICE2.md), [SG132_SLICE3.md](SG132_SLICE3.md), [SG132_SLICE4.md](SG132_SLICE4.md),
[SG132_SLICE5.md](SG132_SLICE5.md); installing: [SG132_INSTALL_RUNBOOK.md](SG132_INSTALL_RUNBOOK.md). Spec:
`.specgrain/specs/SG-000132.json`.

Naming: [UNIFIED_INTEGRATION_SPEC.md](UNIFIED_INTEGRATION_SPEC.md) section 8.2 is authoritative. Everything here is
WP1-10 (the authority service and the dispatcher); test names keep the `wp110_` prefix on the service side and
`fc_dispatch_` in orceld.

**What this slice closes:** three residuals of earlier slices, all engineering only.

1. Slice 2 section 5 (and slice 3 next step 4, slice 5 next step 3): the desktop gate named the lease's own principal
   in `Authorize`. It now names the calling MCP client, and the service checks it against the lease's client binding.
2. Slice 5 residual 4: the gap between the leased host check and the action's first message to the host. Every
   message a leased action sends to the computer host is now checked against the lease's host generation.
3. Slice 4 section 5 (and next step 5): the service did not require paths for `shell_process` dispatches. It now
   refuses one without paths.

## 1. Design decisions

### 1.1 The calling MCP client at the desktop check

- **Which identity.** orceld already identifies MCP clients for browser Full Access leases (SG-000135 OB-08): the
  client reference `cl-` plus 32 lowercase hex, derived from the request's client session
  (`orcel_policy::browser_lease::client_ref(request.client_session_id)`), which the browser session start reply returns as
  `client_ref` and the browser lease binds. No new mechanism: the desktop gate
  (`full_control_dispatch::desktop_gate`) now derives the same reference from the desktop request and names it as
  `principal_id` in the dispatcher's lease choice and in `Authorize`, instead of the lease's own principal.
- **The lease's client binding** (`LeaseBody::admits_client`, used by orceld and by the service). A lease is bound
  to a client when its principal is a client reference: every browser lease, and a desktop lease granted with
  `orcel full-control grant --client cl-...`. A bound lease admits only that client; any other is refused
  (`CAPABILITY_DENIED`) by orceld before the service is asked, and again by the service before any allow record
  (fail closed). A desktop lease whose principal is a free label (the default `orcel-owner`, or any other text
  `--client` named before this slice) is unbound: it admits any client reference, which the service's allow record
  now names, and its own principal (what an orceld from before this slice names), but no other free label.
- **Why unbound leases stay usable.** Every desktop lease granted so far is unbound (`orcel-owner`), and the grant
  confirmation only shows the label. Treating such labels as bindings would refuse every existing lease. An unbound
  lease admitted any request before this slice too; the service now records which client asked.
- **Desktop input only.** The unbound relaxation applies to the desktop input executor alone, the one family whose
  gate names the real client today. Filesystem and shell/process keep the exact match with the lease's principal
  (`LeaseBody::admits_client(executor, client)`, in orceld and at the service), so wiring their request-side
  callers later cannot silently broaden what an unbound lease admits.
- **The deprecated store** (no service installed) is unchanged; it has no client binding.

### 1.2 The host generation on every message (slice 5 residual 4)

- Slice 5 checked, under the adapter's session lock, that the host serving a leased action is the one started into
  the lease's job (its generation) and still running, once, when the action took the adapter
  (`uia::computer_host`). A host replaced after that check (the lease ended, the service killed its host, and an
  observation on another thread started a plain host) could receive the action's later messages.
- Now the adapter checks it on every message: `orcel_provider_uia::require_host_generation(Some(g))` makes every
  message this thread sends through the adapter (`request`, `exchange_host`, `checked_host`, the only three paths
  that write to the host) go only to the host of generation `g`, and only while it runs. The check is made under
  the session lock, which every host replacement (`replace_session`) also takes and under which it moves the
  generation, and the message is written under the same lock, so nothing can replace the host between the check and
  the write. Anything else is refused with `LEASE_INVALID` before a byte is written.
- orceld sets the requirement in `desktop_host_job::require_for`, right after `ensure_lease_host` (the generation
  of the host in the lease's job), and clears it with the request (`clear_required`, at the start and end of every
  desktop request). The requirement is per thread, as slice 5's `REQUIRED` lease is: observation on other threads
  (no lease) is unaffected and keeps restarting a plain host as before.
- Slice 5's `uia::computer_host` check stays (it refuses before the action builds anything); the per-message check
  is what closes the gap.

### 1.3 Paths for every shell/process dispatch

- The service's `Authorize` (`AuthorityCore::check_dispatch_paths`) now refuses a `shell_process` dispatch without
  paths (`INVALID_REQUEST`), as it already refused a filesystem one, before any job or allow record exists. A run
  names its working folder and program and a git operation its repository (slice 4); every path is checked against
  the lease's roots as before. Desktop input and browser dispatches name no paths and need none.
- Slice 4 left this to the shell-session slice, whose sessions also name a working folder; nothing in orceld sends
  a pathless `shell_process` dispatch (the dispatcher refused one already), so the service can require it now.
- A lease with shells but no roots could therefore never authorize anything; `LeaseScope::validate` now refuses it
  at the grant (`INVALID_REQUEST`, before an intent is recorded). Leases granted before are not re-validated: such
  a lease's shell dispatches are refused at `Authorize` (fail closed).

## 2. Protocol changes

None on the wire: no new request, field or `FailureCode`. Two service rules change:

- `Authorize.claims.principal_id` is checked with `LeaseBody::admits_client` instead of equality with the lease's
  principal (equal for a bound lease; a client reference or the lease's own principal for an unbound desktop lease).
- `Authorize` for `shell_process` requires `claims.paths` (at least one).
- `GrantBegin` refuses a desktop scope with shells and no roots.

**Older peers fail closed.** A newer orceld at an older service: desktop input under an unbound lease is refused
(the older service compares the client reference with the label: `CAPABILITY_DENIED`); under a lease bound to the
calling client it works as before; filesystem, process and git are unchanged (orceld already sent paths). An older
orceld at a newer service: it names the lease's own principal, which the newer service still admits; it already
sent paths for process and git (slice 4), and its job-family dispatches are refused anyway when it predates job
acknowledgement (slice 5). **Upgrade order** as before: install the service and orceld together, or the service
first; the order only decides which desktop actions refuse until both are updated.

## 3. Threat model additions (same-user agent with Full Control)

Test names: `core_tests` in `crates/orcel-authority/src/`, `full_control_dispatch_tests` in `crates/orceld/src/`,
`computer_host::tests` in `crates/orcel-provider-uia/src/`.

| Attack | Claim | Evidence |
| --- | --- | --- |
| A second MCP client uses a desktop lease the owner granted to another client | A lease bound to a client reference admits only that client: refused in orceld before `Authorize`, and by the service before any allow record | `full_control_dispatch_tests::fc_dispatch_the_desktop_gate_names_the_calling_client`, `core_tests::wp110_desktop_authorize_checks_the_calling_client_against_the_lease` |
| The audit names the lease's label instead of the client that acted | The desktop gate names the calling client's reference; the allow record carries it | `core_tests::wp110_desktop_authorize_checks_the_calling_client_against_the_lease` (recorded principals), `full_control_dispatch_tests::fc_dispatch_the_desktop_gate_names_the_calling_client` |
| A free label passes as a client of an unbound lease | Only a client reference (exact shape) or the lease's own principal is admitted | `core_tests::wp110_desktop_authorize_checks_the_calling_client_against_the_lease` (`mcp-client-1`, `cl-short`, upper case refused) |
| A host replaced in the middle of a leased action receives the rest of it (slice 5 residual 4) | Every message is checked against the lease's host generation and its running state under the session lock that host replacement takes; refused before anything is written | `computer_host::tests::a_required_host_generation_is_checked_on_every_message` (fake host processes: the leased host stopping, a plain host adopted on another thread, nothing written to either). The wiring in `desktop_host_job::require_for` and `clear_required`: structural (no unit test drives the native host) |
| The requirement leaks into unrelated requests | Set per thread after the service admitted the action, cleared at the start and end of every desktop request; other threads unaffected | `computer_host::tests::a_required_host_generation_is_checked_on_every_message` (another thread sends to the plain host; cleared, this thread sends again) |
| An unbound lease admits any client for filesystem or shell/process once their callers name clients | The relaxation is desktop input's only; the other executors keep the exact match | `core_tests::wp110_desktop_authorize_checks_the_calling_client_against_the_lease` (filesystem and shell/process refused for a client reference under an unbound lease), `full_control_dispatch_tests::fc_dispatch_the_desktop_gate_names_the_calling_client` (filesystem refused before `Authorize`) |
| A lease is granted for shells that can never be used, or that a later rule change could widen | Shells without roots are refused at the grant | `lease::tests::widening_is_explicit_and_consistent` |
| A pathless shell/process dispatch escapes the roots check at the service | Refused (`INVALID_REQUEST`) before any job or allow record | `core_tests::wp110_shell_process_dispatches_name_their_paths` |
| A peer from before this slice | Refused or unchanged, never widened (section 2) | `core_tests::wp110_desktop_authorize_checks_the_calling_client_against_the_lease` (the lease's own principal still admitted on an unbound lease); structural for the newer orceld at an older service (equality refuses a client reference against a label) |

## 4. Residuals

1. **The client reference is session-asserted.** It derives from `RequestEnvelope.client_session_id`, which the MCP
   transport supplies and which is "never authority" on its own (`orcel_contracts::session`). A same-user process
   that can talk to orceld and claims another client's session id gets that client's reference. This is the same
   strength as OB-08's browser lease binding; the binding separates clients that do not impersonate each other, and
   the service still binds the Windows user, logon session and orceld instance.
2. **How the owner learns a desktop client's reference.** The browser session start reply returns `client_ref`, and every
   desktop allow record names the reference; there is no desktop-specific surface that shows a client its
   reference before a grant. Binding desktop leases by default (rather than `orcel-owner`) needs that surface and
   the grant confirmation to show the client: a founder product decision, together with the MCP tool surface.
   A bound desktop lease also stops working when the MCP kernel restarts: `apps/orcel-mcp` names a fresh session
   (a new UUID) as `client_session_id`, so the restarted client has a different reference and is refused
   (`CAPABILITY_DENIED`, fail closed) until the owner grants a lease to the new reference.
3. **Unbound leases admit any client for desktop input.** As before this slice, but now recorded per action.
4. **The per-message check is per thread.** A leased request that handed host work to another thread would not
   carry the requirement; no desktop request does (the whole request runs on one thread, as slice 5's `REQUIRED`
   lease assumes).
5. **Bounded desktop execution is outside the service lease.** The SG-000036 bounded execution shape
   (`orcel_provider_uia::is_input_execute_shape`, `uia.rs` -> `execute_with_approval`) runs in-process through
   `NativeAdapter` under its own SG-000036 bounded lease and per-action approval. It does not pass the Full Control
   dispatcher, the service's `Authorize`, the lease's client binding, the desktop host job or the host generation
   check. Moving it onto the dispatcher is next step 3. **Closed by [SG132_SLICE7.md](SG132_SLICE7.md):** with the
   service installed the shape now needs a service lease, `Authorize` and the lease's host (generation checked on
   every message); without the service it is unchanged.
6. Slice 5 residuals 1 to 3 and 5 to 9 stand unchanged (double loss of an acknowledgement reply, service restart,
   handle copies, what a job does not contain, observation outside a job, snapshots after a host switch, the
   15-second window, founder runs).

## 5. Not done; next steps

1. Founder runs for the UNVERIFIED rows of slices 3 to 5.
2. Retire `authority.key` and the deprecated store after the founder's first real desktop grant through the
   installed service (slice 3 section 6).
3. Move the SG-000036 bounded execution path (residual 5) onto the dispatcher: service `Authorize` with the
   calling client, the lease's host in its job, the host generation on every message. Done in
   [SG132_SLICE7.md](SG132_SLICE7.md).
4. Request capabilities and MCP tools for the filesystem, process and git operations (slice 4 section 6, step 1),
   and a surface that shows a desktop client its reference (residual 2): founder product decisions. Decided on
   2026-11-19; the request capabilities and `fc.status` (which shows the reference) are done in
   [SG132_SLICE8.md](SG132_SLICE8.md), the MCP tools are its next step.
5. Possibly a private global atom table for the desktop host job (`GLOBALATOMS`), once UI Automation inside such a
   job is verified on a real desktop with the installed service.
6. Then the indicator and its heartbeat (WP1-12) and standing approvals (WP1-14): founder decisions.

## Tests

At head (Windows, unelevated):

- `cargo test -p orcel-authority` (all targets): 2 new `core_tests::wp110_*` (the calling client against bound and
  unbound leases, and the exact match kept for filesystem and shell/process; pathless shell/process refused), 14
  existing shell dispatches updated to name a path, and `lease::tests::widening_is_explicit_and_consistent`
  extended (shells without roots refused). All pass.
- `cargo test -p orcel-provider-uia --lib computer_host`: 1 new test (the host generation on every message, with fake
  host processes and scripted transports). All pass.
- `cargo test -p orceld --bin orceld -- fc_worker full_control_dispatch`: 1 new dispatcher test (the desktop gate
  names the calling client); the test leases are now bound to the test request's client. All 33 pass.
- `cargo test -p orceld --test ob04_shadow_scan --test ob07b_vault_scan --test dependency_direction`: pass.
- `cargo clippy -p orcel-authority -p orcel-provider-uia -p orceld --all-targets -- -D warnings` on Windows: clean.
  Linux and macOS builds, the workspace-wide clippy and the full orceld suite are left to CI (some unrelated orceld
  tests fail on this PC because of its AppData permissions, `InsecureAcl`, before this slice).
