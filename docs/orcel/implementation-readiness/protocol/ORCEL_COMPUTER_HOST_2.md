# `orcel-computer-host/2`: private native host protocol

Status: specification for backlog task XP-04 (proposed grain SG-000110). Authority delta: none. This is a private protocol between `orceld` and the native host process it spawns. It adds no tool, scope, approval path or listener.

Implementations:

- Windows host (Go): `apps/orcel-computer-host/protocol.go` (`decodeRequest`, `handleFrame`, `helloV2`, `windowsCapabilities`).
- Kernel adapter (Rust): `crates/orcel-provider-uia/src/host_protocol.rs` (negotiation, capability table, refusal mapping) and `crates/orcel-provider-uia/src/computer_host.rs` (session framing).
- macOS and Linux host (Rust, `orcel-native-host`): XP-06.

## 1. Design rules

1. `/2` is a strict superset of `/1`. Every `/1` operation, field, bound and refusal keeps its meaning.
2. A host that speaks `/2` keeps answering `/1` frames byte for byte as before. The `/1` vectors in `apps/orcel-computer-host/protocol_test.go` (`TestProtocolV1VectorsAreByteIdentical`) are frozen.
3. The capability table is advisory to the kernel. It can only make the adapter skip a call that cannot work. It never grants a capability: the kernel registry still enforces every binding, lease and approval. `delivered` is not permission.
4. Omission means unavailable. An operation missing from the table, or carrying a `support` value outside the closed set, is unavailable.
5. Refusal codes form a closed set. The adapter maps each one to an existing `orcel_contracts::FailureCode`. A new public failure code needs governance; this protocol adds none.

## 2. Transport and frames

- Transport: JSON lines over the host process's inherited stdin and stdout pipes. One request line, then exactly one response line. No listener, socket, port or second channel. Stderr is discarded by the adapter.
- Environment: the adapter starts the host with a cleared environment plus `SystemRoot`, `WINDIR`, `COMSPEC`, `TEMP`, `TMP` and `PATH` (unchanged from `/1`).
- Request bound: 64 KiB per line (`maxRequestBytes`). A longer line ends the host's read loop.
- Response bound: 16 MiB per line (`maxResponseBytes`, `MAX_HOST_RESPONSE_BYTES`). The host replaces an oversized response with `output_limit`; the adapter refuses a longer line with `OutputLimit`.
- Other bounds (unchanged from `/1`): 64 windows, 256 tree nodes, tree depth 8, 8 MiB capture at most 7680x4320, 16 KiB text or value, 64-byte key, scroll of at most 20 ticks per axis, worker timeout 8000 ms, 2 worker attempts for observation and 1 for mutation.
- Request ids: the adapter numbers requests from 1 and never reuses an id within a session. Every response must echo the request `id`, the negotiated `protocol` and the host identity `host`. Any mismatch is `ProviderUnavailable`.

### 2.1 Request frame

```json
{"id": 7, "protocol": "orcel-computer-host/2", "op": "observe_window", "max_nodes": 256, "max_depth": 8,
 "window": {"kind": "hwnd", "id": 1312, "expected_pid": 4410, "expected_start_generation": 133702, "expected_window_nonce": 9}}
```

Request fields are the `/1` fields (`hwnd`, `expected_pid`, `expected_start_generation`, `expected_window_nonce`, `max_nodes`, `max_depth`, `element_runtime_id`, `semantic_action`, `window_action`, `value`, `x`, `y`, `to_x`, `to_y`, `button`, `click_count`, `scroll_x`, `scroll_y`, `text`, `key`, `expected_last_input_tick`) plus `window`.

Under `/2` the host refuses an unknown field with `invalid_request`. Under `/1` it keeps ignoring unknown fields, as it always did. In particular, a `/1` frame that carries `window` has that field ignored, whatever its JSON type: the `/1` request shape has no `window` field, and only the strict `/2` path decodes it.

### 2.2 Response frame

```json
{"id": 7, "ok": true, "protocol": "orcel-computer-host/2", "host": "orcel-windows-computer-host", "elements": [...]}
{"id": 7, "ok": false, "protocol": "orcel-computer-host/2", "host": "orcel-windows-computer-host", "error": {"code": "target_stale", "message": "..."}}
```

The payload fields (`pong`, `windows`, `elements`, `capture`, `cursor`, `action`) are unchanged from `/1`. `/2` adds `platform`, `backend` and `capabilities`, which appear only on a `/2` hello response. Clients ignore response fields they do not know. Hosts may add response fields within `/2`, but only fields that grant nothing.

A request that cannot be parsed as JSON is answered with id `0` in `/1` framing, as before, because its generation is unknown.

## 3. Operations

The operation set is exactly the `/1` set of 16. `/2` adds no operation.

| Operation | Window binding | Kind |
|---|---|---|
| `hello` | no | session |
| `ping` | no | session |
| `shutdown` | no | session |
| `list_windows` | no | observation |
| `cursor_position` | no | observation |
| `observe_window` | exact | observation |
| `capture_window` | exact | observation |
| `semantic_action` | exact | mutation |
| `window_action` | exact, plus fresh human-input tick | mutation |
| `input_move`, `input_click`, `input_drag`, `input_scroll`, `input_type_text`, `input_key`, `input_hotkey` | exact, plus fresh human-input tick | mutation |

Any other `op` is refused with `capability_denied`.

## 4. Version negotiation

1. The adapter sends `{"id": 1, "protocol": "orcel-computer-host/2", "op": "hello"}`.
2. A `/2` host answers `ok: true` in `/2` with the hello fields of section 5. The adapter checks `host`, `platform` (in the closed set and equal to the platform the build serves) and `backend` (in the closed set), and bounds the table at 64 entries. Every later frame in the session uses `/2`.
3. A `/1` host answers with a refusal with `error.code` `invalid_request` in `/1` framing (`ok: false`, `protocol: "orcel-computer-host/1"`; the `/1` host says "protocol generation mismatch"). Only such a refusal makes the adapter send `{"id": 2, "protocol": "orcel-computer-host/1", "op": "hello"}` and run the session in `/1`.
4. Any other answer is a failed handshake (`ProviderUnavailable`): a refusal with another code, a `/1` frame claiming success to a `/2` hello, a wrong host identity, or an unknown or foreign platform or backend.
5. A transport failure during hello (the host exits, the pipe closes, or the JSON is corrupt) is a failed handshake at once. The adapter does not retry the hello and does not respawn. The provider reports unavailable until the next adapter construction.

A `/1` session has no capability table. The 16 `/1` operations keep their historical availability, and every other operation is unavailable.

Future generations follow the same pattern. `/N` is offered first and the adapter falls back one generation only on `invalid_request` in the older generation's framing. A host must answer each generation it implements in that generation's framing.

## 5. Hello response

```json
{
  "id": 1, "ok": true, "protocol": "orcel-computer-host/2", "host": "orcel-windows-computer-host",
  "platform": "windows",
  "backend": "uia",
  "capabilities": {
    "list_windows":   {"support": "delivered"},
    "capture_window": {"support": "delivered", "delivery": "background"},
    "input_click":    {"support": "foreground_only", "delivery": "foreground"},
    "input_hotkey":   {"support": "refused", "reason": "background_unavailable"}
  }
}
```

| Field | Values | Notes |
|---|---|---|
| `platform` | `windows`, `macos`, `linux` | Closed. Required. |
| `backend` | `uia`, `ax`, `atspi-x11`, `atspi-wayland` | Closed. Required. |
| `capabilities` | object keyed by operation | At most 64 entries. Keys that name no operation are dropped at negotiation, so an advertised unknown operation stays unavailable. |
| `capabilities.*.support` | `delivered`, `foreground_only`, `refused`, `unavailable` | Closed. Any other value is read as `unavailable`. |
| `capabilities.*.delivery` | `background`, `foreground` | Optional and informational. |
| `capabilities.*.reason` | a refusal code from section 7 | Optional. The adapter keeps it only when it is ASCII and at most 128 bytes, and uses it only in error text. |
| `host_version`, `donor`, `permissions` | informational | Optional. Reserved for the macOS and Linux host (XP-06). The adapter ignores them. |

`delivered` and `foreground_only` are usable. Before sending a frame, the adapter refuses an operation whose support is `refused`, `unavailable` or absent, with `ProviderUnavailable` ("computer host does not deliver <op> on this machine (<reason>)"). `hello` itself is never gated.

### 5.1 Windows capability table

| Operation | support | delivery | Basis |
|---|---|---|---|
| `hello`, `ping`, `shutdown` | delivered | - | supervisor-only |
| `list_windows`, `observe_window`, `cursor_position` | delivered | - | Win32 enumeration, UIA in a sacrificial worker |
| `capture_window` | delivered | background | `PrintWindow`/DWM capture of the exact window |
| `semantic_action` | delivered | background | UIA patterns on the exact element |
| `window_action` | delivered | foreground | Win32 window commands, human-input tick required |
| `input_*` (7 operations) | foreground_only | foreground | `SetForegroundWindow` on the exact target, then `SendInput` |

The Go test `TestProtocolV2HelloReportsPlatformBackendAndCapabilities` requires exactly one entry for each of the 16 operations, with no extras.

## 6. Window identity

Every bound request carries a platform-tagged window reference:

```json
{"kind": "hwnd" | "cgwindow" | "x11" | "wl_toplevel", "id": u64,
 "expected_pid": u32, "expected_start_generation": u64, "expected_window_nonce": u64}
```

- `kind` is closed. A host serves only its platform's kinds (Windows: `hwnd`). It refuses any other kind with `invalid_request`.
- All five fields are required. A missing binding is refused with `invalid_request` ("exact window binding is required"), as in `/1`.
- `id` is opaque to the kernel. It is meaningful only to the host that issued it, together with `expected_pid`, `expected_start_generation` (process start generation; Windows: creation time) and `expected_window_nonce` (host-issued). If any of these no longer matches the live window, the host refuses with `target_stale`.
- The legacy `/1` fields (`hwnd` plus the three `expected_*` fields) stay accepted in `/2` frames from Windows callers. A frame that sends both `window` and any legacy window field is refused with `invalid_request`.
- The Windows host turns `window` into the `/1` fields before any native work, and gives the sacrificial worker a `/1` frame, so the worker and its response binding are unchanged. The Rust adapter sends `window` under `/2` and the legacy fields under `/1`.

Process facts in `list_windows` (`pid`, `start_generation`, `generation_source`, `session_id`, `session_verified`) are unchanged. XP-03 supplies the macOS and Linux generation sources.

## 7. Refusal codes

`error.code` is drawn from a closed set. In a `/2` session the adapter maps each code to an existing `orcel_contracts::FailureCode` (`host_protocol::map_refusal_code`). A `/1` session keeps the exact `/1` mapping (section 7.1), so `/1` meanings do not change.

| Host code | Meaning | `FailureCode` |
|---|---|---|
| `invalid_request` | malformed frame, unknown `/2` field, wrong generation, bad bounds | `InvalidRequest` |
| `capability_denied` | operation not exposed by the private host | `CapabilityDenied` |
| `target_stale` | window or element binding no longer matches the live target | `TargetStale` |
| `permission_missing` | OS permission (for example macOS Accessibility or Screen Recording) not granted | `ProviderUnavailable` |
| `background_unavailable` | the operation cannot be delivered without taking the foreground | `CapabilityDenied` |
| `background_occluded` | the target is occluded for background delivery | `CapabilityDenied` |
| `background_uipi_blocked` | integrity-level isolation blocks delivery | `CapabilityDenied` |
| `protected_surface` | secure desktop, password field, or other protected surface | `CapabilityDenied` |
| `output_limit` | response would exceed a bound | `OutputLimit` |
| `timeout` | native work exceeded its deadline | `ProcessTimeout` |
| `provider_unavailable` | native backend or worker failed | `ProviderUnavailable` |
| `postcondition_failed` | native action ran but its postcondition did not hold | `ProviderUnavailable` (as in `/1`) |
| `cancelled` | human input arrived after the bound tick, so the mutation was not sent | outcome state (below) |
| `outcome_unknown` | a mutation may have been delivered, but the host lost the result | outcome state (below) |

Any code outside this table maps to `ProviderUnavailable`.

### 7.1 `/1` session mapping (unchanged)

| Host code | `FailureCode` |
|---|---|
| `invalid_request` | `InvalidRequest` |
| `capability_denied` | `CapabilityDenied` |
| `target_stale` | `TargetStale` |
| `output_limit` | `OutputLimit` |
| anything else | `ProviderUnavailable` |

For raw input and window actions, `cancelled` and `outcome_unknown` are execution states, not errors. The adapter returns them as a `DesktopActionResult` with that `state`, exactly as in `/1`. A mutation is never retried after `outcome_unknown`. On any other path they map to `ProviderUnavailable`.

`postcondition_failed` keeps its `/1` mapping so this task changes no client-visible code. Moving it to `PostconditionFailed` is a separate, governed change.

The `background_*` codes come from the Cua Driver action-result contract (`libs/cua-driver/docs/action-result-contract.md`, used as reference only). The Windows host does not emit them today. It reports raw input as `foreground_only` instead.

## 8. Security properties

- No new authority. The table only narrows what the adapter attempts. Registry bindings, leases, approval classes and the human-input tick are unchanged.
- No new surface. Same 16 operations, same pipes, same environment scrub, same sacrificial worker. `/2` adds no field to any non-hello response.
- Fail closed. Unknown generation, platform, backend, window kind, `/2` field, support value or refusal code all lead to refusal or unavailability, never to a wider fallback.
- No retry storm. A failed hello is final for that adapter instance. Mutations keep their single attempt.

## 9. Compatibility and rollback

- `/1` callers (including `apps/orcel-mcp/src/sg000094-host-ci.test.ts`) see identical bytes.
- New adapter with an old host: negotiation falls back to `/1` on `invalid_request`.
- Old adapter with a new host: it sends `/1` and gets `/1` bytes.
- Rollback: revert the Go change and the adapter falls back to `/1` automatically. Revert the adapter change and it speaks `/1` only.

## 10. Test evidence

| Property | Test |
|---|---|
| `/1` byte identity | Go `TestProtocolV1VectorsAreByteIdentical`, `TestProtocolV1BoundRequestReachesWorkerUnchanged` |
| `/2` hello, platform, backend, one entry per operation | Go `TestProtocolV2HelloReportsPlatformBackendAndCapabilities` |
| `/2` unknown field, foreign kind, mixed or partial binding refused | Go `TestProtocolV2RefusesUnknownFieldsAndForeignWindowKinds` |
| Window reference normalized for the worker, refusals re-framed in `/2` | Go `TestProtocolV2WindowReferenceIsNormalizedForTheWorker` |
| Negotiation picks `/2` and stores the table | Rust `host_protocol::tests::negotiation_picks_v2_and_stores_the_capability_table` |
| Omitted or unknown capability is unavailable | Rust `omitted_or_unknown_capability_is_unavailable` |
| `/1` host still works | Rust `v1_host_that_refuses_v2_as_invalid_request_still_works` |
| Fallback only on `invalid_request` | Rust `other_refusals_never_fall_back_to_v1` |
| Host crash during hello is unavailable, no retry | Rust `host_crash_during_hello_is_unavailable_without_retry` |
| Identity, platform and backend checks; bounds | Rust `v2_hello_must_match_identity_platform_and_backend`, `capability_table_and_reasons_are_bounded` |
| Closed refusal mapping in `/2`; `/1` mapping unchanged | Rust `refusal_codes_map_onto_existing_failure_codes`, `v1_sessions_keep_the_v1_refusal_mapping` |
| Advertised unknown operation stays unavailable | Rust `advertised_unknown_operation_stays_unavailable` |
| Real Go host answers `/1` and `/2` hello on windows-latest | Node `apps/orcel-mcp/src/sg000094-host-ci.test.ts` |
| Per-generation framing of bound requests | Rust `computer_host::tests::bound_requests_are_framed_per_negotiated_generation` (Windows) |
| Real host negotiates `/2` | Rust `configured_host_handshake_is_exact` (Windows, with `ORCEL_COMPUTER_HOST_BIN`) |
