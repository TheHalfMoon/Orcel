# SG-000132 slice 7: the SG-000036 bounded execution shape on the Full Control dispatcher

Status: implemented and tested on branch `authority/input-execute-dispatcher`; not installed. Nothing in this slice
was installed or run elevated, no UAC, Windows Hello or Orcel dialog was shown or answered, and no system, registry,
firewall or ACL setting changed. No test drives real input. Earlier slices: [SG132_SLICE1.md](SG132_SLICE1.md) to
[SG132_SLICE6.md](SG132_SLICE6.md); installing: [SG132_INSTALL_RUNBOOK.md](SG132_INSTALL_RUNBOOK.md). Spec:
`.specgrain/specs/SG-000132.json`.

Naming: [UNIFIED_INTEGRATION_SPEC.md](UNIFIED_INTEGRATION_SPEC.md) section 8.2 is authoritative. This is WP1-10 (the
dispatcher); test names keep the `fc_dispatch_` prefix in orceld.

**What this slice closes:** slice 6 residual 5 (and its next step 3). The SG-000036 bounded execution shape
(`uia.input/execute`, `orcel_provider_uia::is_input_execute_shape`, `uia.rs` -> `execute_with_approval`) ran through
the in-process `NativeAdapter` under its own SG-000036 single-use input lease and per-action approval only. It never
passed the Full Control dispatcher, so neither the service's `Authorize` (with the lease's client binding) nor the
lease's computer host in its service-made Job Object nor the per-message host generation check applied to it.

## 1. Decision: on the dispatcher when the service is installed (not "by design")

The specs leave no room for a lighter, separate path for desktop input once the service is installed:

- SG-000132 scope: `crates/orceld/src/full_control_dispatch.rs` is "the only path for lease-gated executors", and
  the executor classes enabled through it include "DesktopInput and window actions (SG-000095)".
- SG-000132 invariants: "No lease-gated executor runs without a service Authorize whose audit record was written
  first", and "Every Orcel-started executor tree is in a Job Object created, owned and held by the service".
- SG-000132 dependency note on SG-000095: the desktop-input path (`orceld/src/uia.rs` -> `ComputerHostAdapter`)
  "moves behind the service's Authorize; its per-action approval stays unless a standing approval covers it".
- Unified spec 4.14: desktop input runs in the native host via `ComputerHostAdapter` in a service-owned Job Object,
  and "No Full Control operation runs inside the long-lived `orceld` process itself". Section 11 consequence 3:
  after WP1-10 desktop input also needs the service.
- orceld already classes the shape as Full User desktop authority: `uia::is_full_user_desktop_shape` includes
  `is_input_execute_shape`, so a remote caller is refused (`sg000039_main.rs`), and every sibling SG-000027 to
  SG-000036 actuation shape (invoke, value, select, toggle, scroll, capture) already calls
  `require_full_user_desktop` and runs in `computer_host()`. The bounded execution shape was the only one that did
  not.

SG-000036 itself does not argue the other way: its "input lease" is a registry-internal, single-use token bound to
one coordinate binding (minted, bound into the approval digest, consumed once). It is not a Full Control lease, and
SG-000036 predates the authority service. It stays, alongside the service lease, as one more check.

So the residual is closed by routing, not by documentation.

## 2. What changed

- `full_control_dispatch::bounded_execution_gate` (production wrapper `authority_link::bounded_execution_gate`):
  - **Service installed** (or an SCM that cannot be asked, which counts as installed): the shape goes through
    `desktop_gate`, the same gate every other desktop action takes: a service lease of this user and logon session
    that admits desktop input and the calling MCP client (slice 6), the service's audit-first `Authorize` naming the
    client, and the outcome reported by `with_desktop_outcomes`. The action digest the service records
    (`desktop_action_digest`, computed in orceld) is taken over the request with the server-resolved click added
    (`bounded_execution_audit_request`: process, window, window generation, handle, coordinates, operation, the
    SG-000036 input lease and the approval digest), so the audit names the click and not only the coordinate
    identity. Any refusal refuses the action (`LEASE_REQUIRED`,
    `CAPABILITY_DENIED`, `AUTHORITY_UNAVAILABLE`, ...); nothing falls back to the deprecated store or to the
    in-process adapter. A `None` from the gate while the service is installed (which the dispatcher never returns)
    refuses too.
  - **No service installed:** unchanged (DEPRECATED). The in-process route as before; the deprecated store is not
    consulted, as it never was for this shape (unlike slice 2's desktop gate, which consults it for the shapes that
    always called `require_full_user_desktop`).
- `uia.rs` `execute_with_approval`, in the journaled dispatch step (after the SG-000036 input lease was minted and the
  per-action approval consumed, where every sibling shape takes its gate):
  - leased route: refuses unless the computer host is selected (`ORCEL_COMPUTER_HOST_BIN`), then
    `desktop_host_job::require_for(lease)` (the lease's host in its service-made Job Object, and the host generation
    required on every message, slice 6), then `computer_host()` (which refuses any host that is not that lease's),
    then `UiaRegistry::execute_input` with that adapter. `NativeAdapter` is never built on this route.
  - deprecated route: `NativeAdapter`, exactly as before.
- **Approvals.** The SG-000036 single-use input lease and the fresh per-action SOFT approval stay on both routes. SG-000132
  invariant: "A lease alone never replaces an approval; only a standing approval for the same client, task and scope
  does" (standing approvals are WP1-14, not built). The approval prompt is orceld's Windows dialog, as before; nothing
  here approves anything.

**What actually actuates today.** Neither adapter implements `UiaAdapter::execute_click`: `NativeAdapter` and
`ComputerHostAdapter` both inherit the trait default, which refuses `PROVIDER_UNAVAILABLE`
(`sg000063_tests` asserts it for `NativeAdapter`). So this shape clicked nothing before this slice and clicks nothing
after it; on the leased route the service records the dispatch and then its failed outcome. The residual was latent:
this slice makes sure that whenever a click is implemented, it can only run under the service lease, in the leased
host, with the generation check.

## 3. Protocol changes

None: no new request, field or `FailureCode`, and no service change. The shape's `Authorize` is the existing desktop
input `Authorize` (executor `DesktopInput`, the calling client, capability `uia.input`, operation `execute`, the slice 2
action digest over the request with the resolved click added; the service treats the digest as opaque, so this is
not a wire change). **Older peers:** a newer orceld at an older service sends the same `Authorize` slice 6 sends for every
desktop action, so it is admitted or refused exactly as those are (slice 6 section 2), never widened. An older orceld
at a newer service keeps the in-process route for this shape, which actuates nothing (section 2). **Upgrade order** as
before: the service first, or both together.

## 4. Threat model additions (same-user agent with Full Control)

Test names: `full_control_dispatch_tests` in `crates/orceld/src/`.

| Attack | Claim | Evidence |
| --- | --- | --- |
| An agent reaches desktop input through the SG-000036 bounded execution shape and skips the service lease (slice 6 residual 5) | With the service installed the shape needs a service lease admitting desktop input and the calling client, and the service's audit-first `Authorize`; any refusal refuses the action | `fc_dispatch_bounded_execution_with_the_service_needs_a_lease_and_authorize` (no lease, a lease without desktop input, a lease bound to another client, an unreachable service, a refused `Authorize`) |
| The shape actuates through the in-process adapter while the service is installed | The in-process adapter is built only on the deprecated route; the leased route runs only in the lease's host after `require_for` | `fc_dispatch_bounded_execution_uses_the_in_process_adapter_only_without_the_service` (structural, over `uia.rs`); `bounded_execution_gate` returns the deprecated route only when the service is not installed (`fc_dispatch_bounded_execution_without_the_service_is_unchanged`) |
| The shape's dispatch leaves no audit outcome | The service authorization is reported with the request's outcome like every other desktop action (in production `Failed` today, since no adapter implements the click, section 2) | `fc_dispatch_bounded_execution_with_the_service_needs_a_lease_and_authorize` (an outcome is reported for the authorization; the fake gate call itself succeeds) |
| The service's audit names only the coordinate identity, not the click | The action digest the service records covers the server-resolved click the person approved: process, window, window generation, handle, coordinates, operation, SG-000036 input lease and approval digest | `fc_dispatch_bounded_execution_audit_names_the_resolved_click` (other coordinates or another handle give another digest) |
| A host outside the lease's job, or replaced mid-action, receives the click | The leased route uses `require_for` (lease host, generation on every message) and `computer_host()` (refuses another host) | `fc_dispatch_bounded_execution_runs_only_in_the_leases_host` (the gate's lease gets its host started into that lease's job after `Authorize`; a refused host job starts nothing; fake service and launcher); the `uia.rs` wiring: structural, `fc_dispatch_bounded_execution_uses_the_in_process_adapter_only_without_the_service`; the generation check itself: `computer_host::tests::a_required_host_generation_is_checked_on_every_message` |
| Removing the service store fallback widens the deprecated path | Without the service nothing changes: no store check was ever made for this shape and none is added | `fc_dispatch_bounded_execution_without_the_service_is_unchanged` (no store check, nothing authorized) |

## 5. Residuals

1. **The deprecated route stays outside any lease where no service is installed.** By the task's rule (as slice 2 did
   for the desktop gate), behaviour without the service is unchanged: the shape relies on its SG-000036 input lease and
   per-action approval only, and it actuates nothing (section 2). It disappears with the deprecated store (slice 6 next
   step 2).
2. **The approval is asked before the service gate.** As for every sibling shape, the per-action approval is consumed
   first and the service gate runs in the dispatch step, so with the service installed and no lease the person can
   approve a prompt that then refuses. This is the spec's order (`Authorize` checks the action's own approval) and
   costs a prompt, not authority.
3. **The `uia.rs` wiring of the leased route is checked structurally.** The dispatcher steps it composes (the gate,
   then the lease's host in its job) are tested behaviourally with the fake service and launcher; no unit test drives
   the native host (as slice 6's `require_for` wiring).
4. Slice 6 residuals 1 to 4 and 6 stand unchanged.

## 6. Not done; next steps

Slice 6 section 5 steps 1, 2 and 4 to 6 stand; its step 3 is done here.

## Tests

At head (Windows, unelevated):

- `cargo test -p orceld --bin orceld -- full_control_dispatch fc_dispatch`: 5 new tests (the deprecated route unchanged
  without the service; the service lease, client and `Authorize` required with it, and every refusal; the audit digest
  covering the resolved click; the lease's host for the leased route; the structural check of `uia.rs`). All pass.
- `cargo test -p orceld --test ob04_shadow_scan --test ob07b_vault_scan --test dependency_direction`: pass.
- `cargo clippy -p orceld --all-targets -- -D warnings` on Windows: clean. Linux and macOS builds, the workspace-wide
  clippy and the full orceld suite are left to CI (some unrelated orceld tests fail on this PC because of its AppData
  permissions, `InsecureAcl`, before this slice).
