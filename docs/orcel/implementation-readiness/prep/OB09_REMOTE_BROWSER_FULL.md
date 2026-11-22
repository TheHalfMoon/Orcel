# OB-09: remote `browser_full` for ChatGPT

**Status: part 1 of 2 (orceld gating) implemented on `browser/ob09-remote` (SG-000135 work packet OB-09, acceptance FA-D). Not merged. Part 2, the MCP remote profile (tool contract, OAuth scope mapping, the tunnel and relay context, pairing for `browser_full`), follows in its own PR. Until part 2 merges, no MCP edge sends a remote `browser_full` request, so part 1 is inert. Unit and source-scan tests only. UNVERIFIED (founder run): acceptance D needs a real ChatGPT run, and that needs the installed SG-000132 authority service and the founder.**

## 1. Decision

The founder delegated the open remote-coverage choice on 2026-11-22. Engineering chose the conservative option. The record is "founder-delegated, engineering-chosen (2026-11-22)". It is not a founder quote.

1. A remote `browser_full` Full Access lease is valid only when the installed SG-000132 authority service issued it and it is bound to the identified client (`client_ref`). The interim per-user full-control store never covers a remote caller.
2. The remote session must also hold the existing SG-000055 STRONG remote-session lease, created for the `browser_full` tool-surface profile.
3. High-impact actions still ask per action, exactly as locally: form submit or Enter in a form, submit, send, buy, publish or delete controls, uploads, payments and destructive actions. Anything not positively classified routine asks too.
4. The spec section 4.15 lift (a standing lease covering a remote caller) applies only to remote `browser_full` and only for the client named in the lease.

This lifts SG-000079's "no remote mapping" for `browser_full` only. `browser_structured` stays local-only. The host's `remote_browser_mapping_enabled()` (`crates/orcel-browser-host/src/exposure.rs`) stays `false`: it is SG-000079's marker for the closed grain's shapes, and the closed-grain qualification tests pin it.

## 2. Design

```
ChatGPT -> Secure MCP Tunnel or relay -> device uplink (authenticated remote context)
  -> orceld profile gate: remote context names browser_full, shape is remote-safe
  -> SG-000055 remote-session lease (STRONG-created, browser_full profile, scopes, workstation, trust)
  -> broker as client "remote:<connection>:<principal>:<MCP session>", approvals stamped remote
  -> live browser: routine action under a service lease for this client_ref, or the Windows dialog
  -> receipt names caller {kind: remote, provider, device, connection}
```

**Remote-safe tools.** Each was decided from the specs:

| Tool | Shape | Remote scope | Why |
|---|---|---|---|
| `browser_session_create` | `create` | `orcel.execute` | Ephemeral profile only. Naming a persistent profile is refused, because it may be signed in to the owner's accounts. Visible mode still asks the owner first. |
| `browser_open`, `browser_click`, `browser_fill`, `browser_select`, `browser_tabs` | `open`, `click`, `fill`, `select`, `tabs` | `orcel.execute` | Each keeps its own SOFT approval, or a lease for routine actions only. Secret fields are refused, and a secret-looking or stored-secret value is never typed under a lease. |
| `browser_close` | `close` | `orcel.execute` | Ends the caller's own session. A window a person is using is never closed (OB-06). |
| `browser_snapshot`, `browser_verify`, `browser_extract`, `browser_screenshot`, `browser_task_status` | `snapshot`, `verify`, `extract`, `screenshot`, `status` | `orcel.read` | Reads of the caller's own session page. Screenshots mask secret fields, and URLs go through `agent_url`. |
| `browser_profiles`, `browser_profile_create`, `browser_profile_delete` | `profiles`, `profile_create`, `profile_delete` | local-only | These manage profiles that may hold the owner's sign-ins, and delete is destructive. |

No tool types into a secret field, handles a credential, or evaluates page script. `evaluate_in_page`, `credentials`, `payment_cards`, `solve_captcha` and `run` stay excluded. Uploads stay model-only and have no `browser_full` tool.

**Where the code is:**

- `crates/orcel-policy/src/remote_session.rs`. `browser_full` is now a second remote tool-surface profile (`REMOTE_PROFILES`). `required_browser_full_scopes` maps the twelve remote-safe shapes. `check_remote_dispatch` picks the scope table by the lease's own profile, so a `core` lease never covers a broker shape and a `browser_full` lease covers nothing else. `build_lease` accepts `browser_full`, under the same STRONG-gated local command. Its prompt names `profile=browser_full`. The core table and its cross-language test are unchanged.
- `crates/orceld/src/profile_gate.rs`. `REMOTE_BROWSER_FULL_SHAPES` lists the remote-safe shapes. A remote broker request passes the gate only when its authenticated remote context names `browser_full`, the shape is remote-safe, and `create` names no persistent profile. A local request whose MCP session id starts with `remote:` is refused, so it cannot pose as a remote client.
- `crates/orceld/src/sg000039_main.rs`. A remote broker request goes through `remote_session_gate` (the SG-000055 check, now shared with the core path) and then `handle_browser_full`. Its approval broker is the existing `OriginStamp`. Every prompt it raises is the owner's Windows dialog, marked remote with the provider, device and connection taken from the authenticated context. Nothing the remote caller sends can answer a prompt: the shapes take no approval or token field, and approvals come only from the local broker.
- `crates/orceld/src/browser_remote.rs`. `Caller` (local or remote). The broker client is `remote:<paired connection>:<principal>:<MCP session>`, so a remote client never reaches a local session or another remote client's session. The `client_ref` that a lease must name is derived from that client. `refuse_remote_profile` refuses persistent profiles a second time, after the gate.
- `crates/orceld/src/browser_lease.rs`. `FullAccess::for_remote_caller` marks a remote session. `LeaseSource::issuer` says who issues a source's leases. For a remote session, a lease from any issuer but the authority service, without the service's `al-` id, or naming another client or principal, is refused `lease_invalid` (CAPABILITY_DENIED, an existing code) at decide and again at confirm. Nothing is sent, and later actions ask. The routine and high-impact classification, the takeover gate, the epoch and revoke checks, and the service's audit-first `Authorize` are unchanged.
- `crates/orceld/src/browser_broker.rs` and `browser_receipts.rs`. Each session keeps its `Caller`. Its `session_start` event, every intent and every receipt carry `caller`: `{"kind":"local"}`, or `{"kind":"remote","provider","device","connection"}`. Each digest covers it.

**What is unchanged:** OB-06 takeover, OB-07 handoff (`HUMAN_VERIFICATION_REQUIRED`, which is refused before any lease is consulted), OB-07b sign-in and `agent_url`, the Shadow and Visible mode rules, and every local behaviour except the `remote:` prefix refusal.

## 3. Threat model

| Threat | Mitigation | Test |
|---|---|---|
| A remote caller with no STRONG remote-session lease drives the browser | The SG-000055 check runs after the profile gate and before anything else, and fails `REMOTE_SESSION_INACTIVE` | `ob09_remote_browser_full_without_a_strong_session_lease_is_refused` (policy), `ob09_remote_browser_full_without_a_strong_session_lease_never_reaches_dispatch` (orceld) |
| A `core` remote lease or token reaches browser tools, or a `browser_full` lease reaches files or processes | The scope table is chosen by the lease's profile, and lease and context profiles must match | `ob09_core_and_browser_full_leases_never_cover_each_other`, `ob09_a_browser_full_session_lease_covers_only_the_remote_safe_broker_shapes` |
| A remote caller uses or deletes a signed-in persistent profile | Gate, handler and dispatch each refuse it | `ob09_a_remote_session_never_names_a_persistent_profile`, `ob09_a_remote_caller_never_uses_a_persistent_profile`, `ob09_remote_browser_full_reaches_only_the_remote_safe_shapes` |
| An interim-store lease covers a remote caller | The remote session admits only `LeaseIssuer::AuthorityService` with an `al-` id; otherwise `lease_invalid` | `ob09_an_interim_store_lease_never_covers_a_remote_caller` |
| A lease issued to the local client, or to another remote client, covers this remote caller | `client_ref` and the principal are bound to connection, principal and MCP session | `ob09_a_service_lease_bound_to_another_client_is_refused_for_remote`, `ob09_a_remote_client_is_bound_to_its_connection_and_principal` |
| A remote caller submits, buys, publishes or deletes without the owner | High-impact and unknown actions are never covered and ask on the Windows dialog, marked remote | `ob09_high_impact_and_unclassified_remote_actions_always_ask`, `a_remote_requests_approvals_are_marked_remote` (existing) |
| A local process poses as a remote client to reach its sessions | Local ids with the `remote:` prefix are refused | `ob09_local_browser_full_is_unchanged`, `ob09_local_callers_are_unchanged` |
| Receipts cannot tell a remote action from a local one | `caller` is in every intent, receipt and session start, and digest-covered | `ob09_receipts_carry_the_remote_origin`, `ob09_receipts_name_the_remote_origin` |
| Routine remote actions under the right lease still prompt every time (FA-D usability) | They are covered as locally, after the service's `Authorize` | `ob09_routine_remote_actions_under_this_clients_service_lease_are_covered` |

## 4. Residuals

- **UNVERIFIED (founder run).** No real ChatGPT run has happened. It needs part 2, the installed authority service, a STRONG remote-session lease for `browser_full` created at the PC, a lease from `orcel browser grant` for the remote session's `client_ref`, and the founder at the dialogs. ChatGPT must also allow write tools in the founder's plan, and Orcel cannot turn them on.
- The remote-session lease lasts at most 15 minutes (SG-000055), and a reconnect does not extend it. A long remote task needs a new lease.
- No live-browser run was made with a remote context. The Windows `live-browser-dev` build compiles and passes clippy, and the remote path reuses the same live code as the local one.
- The OAuth scopes are reused (`orcel.read` for reads, `orcel.execute` for actions). There is no browser-only scope. The separation comes from the `browser_full` tool-surface profile, which the pairing and the STRONG lease bind. A dedicated scope would need SG-000054 vocabulary changes in the relay and the OAuth server.
- High-impact signals are still the OB-08 heuristics (open choice 4). An action that is wrongly classified routine would be covered. The host's GET-only binding while covered actions run still blocks a non-GET request.
- A per-request read mode asks for each remote read, which makes snapshots slow. A session read mode is the owner's choice at lease creation.

## 5. Tests run

`cargo test -p orcel-policy --lib remote_session` (16 passed). In the orceld unit tests, every `ob09`, `ob08`, `ob05`, `ob02` and profile-gate test passed. `cargo test -p orceld --test ob04_shadow_scan --test ob07b_vault_scan --test dependency_direction` passed, and so did `cargo test -p orcel-lifecycle --test release_blocker_sweep`. Clippy with `-D warnings` is clean for `orceld` and `orcel-policy` (default build), and for `orceld --features live-browser-dev`.
