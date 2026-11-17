# Hybrid Computer Use semantic layer: Orcel patch queue

Donor: microsoft/Hybrid-Computer-Use at commit
`00eaeebe8ac0d275e46f875bdb5347e5f326faa1`, licence MIT (`LICENSE` in this
directory, blob `aa706a7c365bb4dd3820dbe6710b762cea514bd2`). Packet W2-01.
The machine-readable record is `docs/orcel/hcu_semantic_provenance.json`;
the notice is `docs/orcel/notices/hybrid-computer-use-MIT.txt`.

This is a copy-adapt, not a verbatim vendor: the donor's Go core is one
84,000-line package bound to its own MCP server, daemon and sidecar
protocol, so Orcel took the semantic-layer functions and rewrote their
surroundings. Every file in `semantic/` names the donor blobs it adapts.

## What was taken

| Orcel file | Donor file (blob) | Taken |
|---|---|---|
| `semantic/roles.go` | `internal/core/ax_role_ontology.go` (`f5ed94ab`) | role ontology, gridcell rule |
| `semantic/identity.go` | `internal/core/ax_snapshot_identity.go` (`fa1efac8`) | `f1:` semantic fingerprint, alias conflict rule |
| `semantic/refs.go` | `internal/core/ax_ref_registry.go` (`36182c2f`), `ax_ref_minting.go` (`51f642f6`) | rN minting, lifecycle, identity reuse, supersession, eviction |
| `semantic/render.go` | `internal/core/ax_renderer.go` (`fc202bfb`) | node label and tree line shape |
| `semantic/diff.go` | `internal/core/ax_semantic_diff.go` (`cc30f95d`) | diff kinds, ref-keyed matching, signatures |
| `semantic/layout.go` | `native/windows/ComputerUse.Windows.Runtime/WindowsDesktopLayoutDiagnostics.cs` (`e6e158f1`), `DesktopProvider.cs` (`c9d9f4cc`) | layout frame id, stale_layout rule (C# ported to Go) |
| `semantic/batch.go` | `internal/core/ax_batch_plan.go` (`41b2560d`) | execution classes, boundaries, ordered keypress runs |
| `semantic/adapter*.go` | `internal/core/provider_types.go`, `internal/provider/runtime_backend_*.go` | the per-platform split only |
| `semantic/*_test.go` | `ax_ref_registry_test.go` (`306c28b6`), `ax_renderer_test.go` (`772253bd`), `ax_semantic_diff_test.go` (`f62294b7`), `ax_batch_plan_test.go` (`20d1f57c`) | tests marked PORT |

## Orcel changes

1. Renamed to Orcel: package `semantic`, Orcel error texts (each starts with
   the Orcel failure code `target_stale` where it is a staleness refusal),
   no "computer-use" or "HCU" identifiers in anything a caller sees.
2. Stripped: the donor MCP server, CLI, daemon, persisted ref counters,
   telemetry and trace files (`COMPUTER_USE_TRACE_FILE`,
   `COMPUTER_USE_WINDOWS_PROVIDER_TRACE`), every `COMPUTER_USE_*`
   environment switch, ablations, the JSON-schema contract package and its
   `santhosh-tekuri/jsonschema` and `golang.org/x/text` dependencies, the
   Python SDK, model instructions and the hosted benchmark overlay. The
   package imports only the Go standard library.
3. Refs are scoped to one exact Orcel window binding (HWND, PID, start
   generation, window nonce) and one host process (a random instance tag in
   every snapshot id). Only the provider-bound locator is kept: the UIA
   runtime id is the provider identity. Semantic, table-owner and
   process-instance scopes, app and window refs are not ported.
4. A ref resolves only through the window's current snapshot; any newer
   observation, and any action on the window, makes older snapshots stale.
5. Rendering: password values render as `[value=hidden]` and are never
   printed; unnamed, stateless group or generic nodes with no action pattern
   are flattened; the output has a byte budget with an omission note.
6. Diff: nodes are matched by ref only; the weak-duplicate LCS matching and
   order changes are not ported.
7. Layout: the frame covers the bound window (rectangle, client rectangle,
   DPI) and the virtual desktop, not every top-level window, because Orcel
   input is window-relative.
8. Batch plans compile and validate only. `BatchDispatchEnabled` is false and
   the host refuses the `semantic_batch` capability until a grain amendment.
9. The donor's native providers (.NET/FlaUI on Windows, Swift on macOS,
   Python AT-SPI on Linux) are not ported. Windows reads through the host's
   existing Go UIA reader; macOS and Linux compile the package and run its
   unit tests but have no TreeSource here and are marked UNVERIFIED.
