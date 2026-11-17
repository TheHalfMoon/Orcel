# W2-01: Hybrid Computer Use semantic layer in the Orcel computer host

Status: first integration landed on branch `w2/hcu-semantic` (no PR). New action kinds stay denied. Not canonical:
nothing here activates or closes a grain.

Donor: microsoft/Hybrid-Computer-Use (HCU) at `00eaeebe8ac0d275e46f875bdb5347e5f326faa1`, MIT. Provenance:
`docs/orcel/hcu_semantic_provenance.json`; notice: `docs/orcel/notices/hybrid-computer-use-MIT.txt`; patch queue:
`apps/orcel-computer-host/third_party/hcu/PATCHES.md`.

## Authority model (unchanged)

orceld is the only authority. The Go host (`apps/orcel-computer-host`) acts only on frames orceld sends after its
policy (`orcel-policy`), approval and registry checks; the Rust `ComputerHostAdapter` (`orcel-provider-uia`) is the only
client. W2-01 adds no MCP server, no tool, no listener, no new process and no second control system. Every HCU-derived
check can only refuse: a stale snapshot, a changed live element or a changed layout stops an action that orceld already
approved. Nothing in the semantic layer can start an action.

## What HCU is, and what was taken

HCU is a Go core (about 84,000 lines in `computer-use/internal/core`: MCP tools, ref registry, snapshots, diff, batch,
waits) over three native providers run as sidecars: .NET 8 with FlaUI on Windows, Swift on macOS, Python AT-SPI on
Linux. The providers are separate runtimes with their own dependencies; the Windows one cannot be built into a Go
binary. W2-01 therefore copies and adapts the semantic-layer functions of the Go core (and ports one C# rule to Go) into
`apps/orcel-computer-host/third_party/hcu/semantic`, and keeps Orcel's existing native readers.

## Module map

| HCU module | Capability | Orcel today (before W2-01) | W2-01 destination | Status |
|---|---|---|---|---|
| `ax_ref_minting.go`, `ax_ref_registry.go` | short `rN` refs, identity reuse, lifecycle (active, stale, superseded), eviction | orceld `UiaRegistry` issues long element ids per tree generation; no short refs | `semantic/refs.go`; host supervisor keeps one registry per host process, scoped to the exact window binding | INTEGRATED, TESTED (Windows native) |
| `ax_snapshot_identity.go` | `f1:` semantic fingerprint, provider alias conflicts | registry checks control-type drift at action time | `semantic/identity.go`: fingerprint and `CheckLive` (control type, automation id, name) | INTEGRATED, TESTED |
| live-target staleness (registry resolve, provider rebind checks) | refuse an action whose live object is not the observed one | host finds the target by exact runtime id; registry checks tree generation and control type | worker compares `expected_element` with the live element before any pattern call; supervisor refuses a `snapshot_id` that is not the window's current snapshot | INTEGRATED; live-element refusal TESTED on CI only (calls a pattern on the test window) |
| `ax_renderer.go` | compact text tree `- role "name" [state] [ref=rN]` | JSON node list from the registry | `semantic/render.go`; `ref_tree.text` in `observe_window` replies | INTEGRATED, TESTED |
| `ax_semantic_diff.go` (+ render) | screen-diff observations between snapshots | none | `semantic/diff.go`; `ref_tree.diff` and `diff_text` against the window's previous snapshot | INTEGRATED, TESTED |
| `WindowsDesktopLayoutDiagnostics.cs`, `DesktopProvider.cs` | layout frame id; coordinate input refused with `stale_layout` | raw input is window-relative and bound to the exact window and the human-input tick | `semantic/layout.go`; `layout_frame_id` on ref-tree replies; pointer input with `layout_frame_id` refused before focus or input when the layout changed | Host-only: enforced by the host and exercised in host tests; not wired in production (the Rust `HostRequest` has no `layout_frame_id`; needs the grain amendment) |
| `ax_batch_plan.go`, `ax_batch*.go`, `ax_wait*.go` | batched actions with waits | one approved action per request | `semantic/batch.go` compiles and validates plans only; host op `semantic_batch` is advertised `refused` (`grain_amendment_required`) and every request is denied | DENIED BY DEFAULT |
| `provider_types.go`, `runtime_backend_{windows,darwin,linux}.go` | cross-platform native adapters | Go UIA reader (Windows); Rust `orcel-native-host` with vendored Cua Driver (macOS AX, Linux AT-SPI/X11) | `semantic/adapter*.go`: `TreeSource` interface; Windows verified through the host UIA reader; macOS and Linux compile and run the unit tests, marked UNVERIFIED | Windows TESTED; macOS/Linux UNVERIFIED |
| .NET/FlaUI Windows provider | UIA reading and actions | Go UIA reader in this host (an open-computer-use port) | not ported (a second runtime and NuGet dependencies for what the Go reader already does) | PUBLIC_SOURCE only |
| Swift macOS provider, Python Linux provider | AX and AT-SPI reading | `orcel-native-host` (Cua Driver) | not ported; mapping their stale and diff rules onto `orcel-native-host` is follow-up work | PUBLIC_SOURCE only |
| MCP server, CLI, daemon, SDKs, `COMPUTER_USE_*` switches, traces | HCU's own front end | orcel-mcp and orceld | not ported (no second MCP server or front end) | EXCLUDED |

## Wire changes (orcel-computer-host /1 and /2, additive)

- `observe_window` with `"ref_tree": true` (whole window only) returns `ref_tree`: `snapshot_id`, `generation`,
  `text`, `truncated`, `refs` (`ref`, `runtime_id`, `role`, `fingerprint`), `diff`, `diff_text`, `layout_frame_id`,
  `adapter`. The element tree is returned as before, so orceld registers the same elements.
- `semantic_action` accepts `expected_element` (`control_type`, `automation_id`, `name`) and `snapshot_id`. The
  supervisor refuses a snapshot that is not current or a runtime id outside it, fills `expected_element` from the
  snapshot, and the worker refuses (`target_stale`) when the live element differs. Any action on a window retires its
  snapshot.
- `input_move`, `input_click`, `input_drag`, `input_scroll` accept `layout_frame_id`; the worker refuses
  (`target_stale`) before focusing the window when the bound window's layout changed. This check is host-only today:
  the Rust adapter's `HostRequest` (`crates/orcel-provider-uia/src/computer_host.rs`) has no `layout_frame_id` field,
  so no production request carries it and the check runs only in host tests. Wiring it is part of the grain
  amendment below and is deliberately not done in W2-01.
- `ref_tree.diff_text` is capped at 64 KiB (`MaxDiffTextBytes`, matching the adapter's `MAX_REF_TREE_TEXT_BYTES`),
  cut on a change boundary with a `~ note: N changes truncated by the output budget` line, so a large diff no longer
  makes the adapter reject the whole observation.
- `semantic_batch` is named in the capability table as `refused` and denied for every request.
- Unset fields are omitted, so the /1 vectors are byte-identical; /2 strict decoding accepts only these new names.

## orceld and Rust adapter

- `ComputerHostAdapter` remembers the identity of every element it read (bounded) and sends `expected_element` with
  each semantic action to the Windows host, so existing actions now reject a changed live target; after a ref-tree read
  it also sends the snapshot id, spent by the first action. The native macOS/Linux host never receives these fields.
- This narrowing is best-effort hardening, not a gate. The adapter remembers at most 64 windows (a read of a 65th
  window clears the whole record) and 8192 element identities per window (elements past that are not remembered),
  and a record older than five minutes (`MAX_OBSERVATION_AGE`, counted from the last whole-window read) is not used.
  In each of these cases the action is sent without `expected_element` and `snapshot_id`, exactly as before W2-01,
  and orceld's policy, approval and registry stale checks still apply. Nothing may rely on the narrowing being
  present.
- `UiaAdapter::read_ref_tree` (default: refused) and `UiaRegistry::observe_ref_tree`: the same registration as
  `observe_tree`, plus `ref_tree` with each `rN` mapped to the element id the registry issued. Actions still take only
  registry element ids, approvals and stale checks.
- orceld `uia.tree observe` with `"view": "ref_tree"`: refused by `orcel-policy` (the argument is not in the
  authorized set) and, past policy, by orceld's own gate (`REF_TREE_VIEW_ACTIVATED = false`).

## Grain amendment needed

- Ref-tree view (observation): an amendment of the SG-000128 desktop observation surface (and the SG-000063 MCP
  exposure for the tool argument), migrating under SG-000132 with the rest of the SG-000095 path. It adds `view` to
  the `uia.tree observe` arguments in `orcel-policy`, flips `REF_TREE_VIEW_ACTIVATED`, and exposes the argument in
  orcel-mcp.
- Batched actions with waits (new action kind): SG-000132 (Windows Full Control), or an SG-000095 amendment before
  it, with per-step orceld approval or a standing approval bound to the plan, then `BatchDispatchEnabled` and the
  `semantic_batch` capability.
- Layout frames on raw input and `expected_element` on semantic actions only narrow existing SG-000095 actions; they
  still need review under the SG-000095 closeout rules before any canonical claim. Sending `layout_frame_id` from the
  Rust adapter (a new `HostRequest` field, and orceld returning the frame id to the caller) belongs to this
  amendment.

## Evidence (local, Windows 11, Go 1.25.14)

- Donor baseline (`go test` on a copy of the donor): contract 4/4; core 843 passed, 5 failed (4 Linux-only
  `read_text`, 1 test that assumes `/proc` is unwritable), 1 skipped; provider 38 passed, 1 failed (a timing test);
  transport 75 passed, 1 failed (a Linux-only ablation), 1 skipped; live probe and Python SDK tests skipped.
- Semantic package: 24 tests pass on Windows; it vets and its tests compile for Linux and macOS.
- Host: 17 protocol and supervisor tests plus the SG-000094 native tests and the W2-01 native ref-tree test pass
  locally; SG-000095 raw-input tests were not run locally (they send input).
- Rust: `orcel-provider-uia` 230 lib tests pass (6 new W2-01 tests); orceld gate test added.
- Baseline, disposable 3-node Windows Forms window, 30 rounds: UIA read p50 36.6 ms / p95 65.0 ms; ref-tree build
  p95 0.55 ms; heap 16 KB per observation; in-process working set 24 MB; host end to end (supervisor plus one
  sacrificial worker per request) p50 315 ms / p95 650 ms, supervisor peak working set 10.9 MB; element JSON 821
  bytes, ref-tree text 127 bytes. HCU's own .NET snapshot path was not measured (no .NET SDK on the host).

## Gaps

- The HCU Windows (.NET/FlaUI), macOS (Swift) and Linux (Python) providers are not ported; macOS and Linux have no
  TreeSource in the Go package (UNVERIFIED) and `orcel-native-host` has no ref tree yet.
- The layout frame check is host-only: the Rust adapter does not send `layout_frame_id` with raw input (its
  `HostRequest` has no such field) and orceld does not return the frame id, so production input is not checked
  against the layout until the grain amendment wires it.
- Observation narrowing is best-effort (window, element and age bounds above), not a security gate.
- Native tests: `TestW201RefTreeAgainstDisposableWindow` runs only with `ORCEL_W201_NATIVE_TESTS=1` (set in the CI
  "Go computer host tests" step on Windows). The SG-000095 tests (`TestSG95*`) are not gated by an environment
  variable; CI passes `-skip 'TestSG95'`, and a local `go test ./...` must pass the same `-skip` or it will send real
  input.
- The ref-tree view and batched actions are denied until the amendments above.
- The diff keys only on refs; HCU's weak-duplicate matching, order changes, waits, settle and post-action
  observation are not ported.
- The relayed W2 founder authorization is not recorded under `docs/orcel/grants`; the donor provenance entry waits
  for WP1-01 (`docs/orcel/notices/donor-provenance.json`).
- The Go host does not ship in releases, so `scripts/third-party-notices.mjs` does not bundle the HCU notice; add it
  if the host ships.
