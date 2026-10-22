# SG-000108 product caller: the live worker under Orcel's authority

Status: **PROPOSED, pending review** (revision 3: revision 1 was blocked in design review; revision 2 was closed with follow-ups, all settled here). This is a design record only. It adds no code, no tool, no listener and no authority. Each slice below is a separate implementation PR, qualified on its exact head.

## Why

SG-000108's `done_when` asks for a real Windows user journey that downloads and verifies a public PDF through the isolated browser, under the existing policies and approval broker. What exists today (closeout matrix on #290) does not reach that:

- **The live worker is proven** (A3–A6, A9–A11, #324), but only tests call `launch_worker`.
- **The browser host has its own approvals.** Its actuation checks its own one-shot `actuation::ApprovalToken`. Nothing ties that token to `orcel_approval::ApprovalBroker`, the broker repaired by #286.
- **`orceld` drives no browser.** It already dispatches the twelve qualified browser shapes through the broker (`crates/orceld/src/browser.rs`), with SOFT approval and exact digest binding. Its navigation only advances a state machine (`apply_navigation`). Its download writes caller-supplied bytes.
- **Nothing is exposed.** The SG-000079 live browser set is empty.

## What the code is today (facts the slices build on)

- **Host binary.** `orcel-browser-host` (`main.rs`) accepts only `--engine`, `--profile-dir` and `--host-id`. It spawns the engine itself (`spawn_engine_null`, SG-000074 `build_argv`) and serves only hello, ping and shutdown. It never calls `launch_worker`.
- **Supervision.** `Supervisor` (`host.rs`) spawns the host through `spawn_host_piped`, admits one live host at a time, and makes the host's profile with a marker (`setup_ephemeral_profile`, then `adopt_profile`). The host's environment sets TEMP to `%SystemRoot%\Temp`.
- **Worker frames.** Navigate, FetchText, Observe, Discover, Extract, Activate, Download and Execute. There is **no fill frame**.
- **What a live click can do.** `activate` follows only an observed, same-origin link; it does not model element state.
- **Pins.** The host pins every destination from its own DNS resolution: `AdmittedDestination::admit` is the only constructor, and the pin is fixed into `--host-resolver-rules` when the lifetime launches.
- **`orceld`'s digests bind material only `orceld` has:**
  - its profile identity and `page_id`;
  - `expected_state`;
  - its own resolved `pinned_address`;
  - for downloads, a declared `source_id` and the SHA-256 of caller-supplied bytes.
- **Host-side bindings for approval prompts already exist:** `download_binding` and `execution_binding`.
- **`orceld` reads no profile.** It does not read `tool_surface_profile` (only `remote_session.rs` does, admitting `core` only). In `apps/orcel-mcp/src/tool_contract.ts`, `desktop_structured` is every contract key, so a browser tool added to the contract would silently widen it.

## Topology

```text
MCP client ──> orceld                      (workspace, policy revision, approval broker, page store, profile gate)
                 │ Supervisor: spawn_host_piped, piped stdio, kill-on-close Job Object
                 ▼
               orcel-browser-host --worker (low authority: SG-000075 policy, own DNS pin, A10 window, host bindings)
                 │ launch_worker: private pipe, nested Job Object
                 ▼
               worker (Node, playwright-core) ──pipe──> installed Edge / Chrome (confined argv)
```

- **`orceld` stays the only authority** a caller talks to. Only it mints and consumes approvals, with the broker.
- **The host never mints, renews or stores approvals.** Its checks guard the action against staleness and redirection; they are not a second authority. The host trusts its parent, which is the only process holding its pipe, to have consumed the approval.

## Decisions proposed

### 1. The host binary gains a worker mode (an authority delta of slice 1)

- **What `--worker` changes.** In `--worker` mode the host never spawns the engine itself, so there is never a second browser for `classify_job` to refuse. It discovers the engine itself (`discover_engine`; there is no `--engine` argument), and A10 re-verifies it at launch. It serves capability frames over `launch_worker`. Arguments, all from `orceld` and never from a caller:
  - `--node` and `--worker-main` (see decision 7);
  - `--profile-root`;
  - `--temp-dir`, a `orceld`-owned staging root, so staging never lands in `%SystemRoot%\Temp`;
  - `--host-id`.
- **Profiles.** The host itself creates its ephemeral profile with `ephemeral_profile_dir(--profile-root)`. That keeps the creator's pid on the name, so the #298 sweep works. It also writes and re-checks the A9 fingerprint marker before launch, which this slice adds to the ephemeral path.
- **Destinations.** The destination arrives in an `open` frame, never in argv.
- **One host at a time.** `Supervisor` admits one live host per `orceld` process, so slices 1–3 support one browser lifetime at a time. A second concurrent lifetime is refused, typed. Lifting that is a later decision.
- **`Supervisor` worker mode.** Today `Supervisor::launch` and `shutdown` create and remove the host's profile themselves. A worker-mode variant leaves the profile to the host, and keeps the spawn, the job, the single-host rule and the deterministic shutdown.

### 2. The host's resolution decides the pin

- **`open` takes one destination.** The host resolves and admits it (`AdmittedDestination::admit`, with SG-000075's public-address rules), launches the worker with that pin, and replies with a lifetime nonce and the pinned address.
- **Approvals bind the host's pin.** `orceld`'s navigation approval binds the host-reported pin, not `orceld`'s own preview resolution, so round-robin DNS cannot make the two disagree after an approval is spent. `orceld` still runs its preview for SG-000075 validation before `open`.
- **`open` needs no approval.** It loads only `about:blank`, and no consequential action happens. It is counted against a lifetime limit.
- **Cross-origin navigation.** A lifetime admits exactly one destination, and one host runs at a time. So navigating a page to another origin works as follows:
  1. The current lifetime is shut down (profile removed) before the new one is opened and the prompt is shown, because the approval must bind the new lifetime's pin.
  2. The page becomes stale at that point, **whether the user then approves or denies**. A denied cross-origin navigation leaves the page without a live lifetime, and the next action on it needs a new navigation.
  3. The preview tells the user this before they decide.
  4. On approval, the page id is kept and its generation advanced. The prior lifetime's node ids are stale for good.

  A second, brief lifetime just for the switch would break the one-host rule and is not proposed.

### 3. Two-part approval binding

For each consequential action, `orceld` and the host each contribute what only they know:

1. **The host binding comes first.** `orceld` sends a `bind` frame describing the intended action. The host computes a host binding over its own material and returns it:
   - the lifetime nonce;
   - the action kind;
   - the committed document generation;
   - the host node identity;
   - the resolved target URL;
   - for downloads, the approved folder's real path, the file name and the size limit;
   - for any value-carrying action, the value's digest.
2. **`orceld` builds the approved digest** as H(`orceld`'s material ‖ host binding). Its material is the workspace, the policy revision, the page id and the store generation. It prompts the user, and the broker mints and consumes the approval as today.
3. **Dispatch.** `orceld` sends the action frame with the broker record id and the host binding. The host re-derives its binding from its current state and refuses unless:
   - the binding is unchanged: no generation advance, no node change, no other lifetime, no other target;
   - the record id is unused in this lifetime.

**Why this holds:**
- **No replay across lifetimes:** the nonce is in every binding.
- **No redirection to another node or target:** the host re-derives its own binding.
- **No approval from the host:** it never mints one.
- **The shared code is small.** Only the framing of the two parts is shared, with a test vector in each crate. Each side's material stays its own.

**Consume-first.** `orceld` consumes before dispatch, so a host refusal after consumption spends the approval. That fails closed. `orceld` records the approval as "consumed, not dispatched".

### 4. What is live in slices 1–3

- **Live:**
  - navigate;
  - observe;
  - link activation (`browser.dom/click` on an observed link);
  - staged create-only download of an observed node.
- **Not live:**
  - `browser.dom/click` on a button, menu item, tab or checkbox returns typed unsupported live.
  - `browser.dom/fill` is deferred to its own slice. It needs a new worker frame, a protocol generation bump and a postcondition that detects a changed element.
  - Uploads stay model-only.

### 5. The live download changes `orceld`'s download shape (authority delta, slice 3)

- **What changes:** the live form downloads an observed node of the committed document, keyed by node id. The current model-only form takes caller-supplied `body` bytes and binds their SHA-256.
- **What the approval binds:** the host binding (node, resolved URL, folder real path, file name, size limit), not a content digest. The bytes do not exist before approval.
- **What the evidence carries:** the committed file's SHA-256 and size.
- **The caller-supplied-bytes form is gone for live pages.** It is unreachable under `browser_structured`, which lists only the live form. The tables change together (decision 6).
- **`browser.download/preview` stays.** Under `browser_structured` it returns the host binding (the `bind` frame) and what the prompt will show. It writes nothing and consumes nothing.
- **Generations:** the store keeps its own page generation, which only increases. It records the host generation it corresponds to in the current lifetime. A committed download advances both, mirroring the host's `committed = (url, generation + 1)`. A new lifetime restarts the host generation, and the store maps it again from the next reply.

### 6. Exposure and profile selection (slice 3)

- **`ToolSurfaceProfile`** gains `browser_structured`.
- **`desktop_structured`** becomes an explicit list without browser tools, instead of every contract key, so adding browser tools cannot widen it.
- **Profile selection.** A local transport selects `browser_structured` only by explicit local configuration, never by a caller.
- **`orceld` gains a profile gate.** It refuses live browser dispatch unless the request is local and its profile is `browser_structured`.
  - The profile is the sender's own claim, not proof: anything that can write `orceld`'s stdin can write it too.
  - The gate guarantees that the MCP edge, which sends `browser_structured` only when local configuration selected it, reaches no live shape otherwise, and that no remote request reaches one. Every consequential live action still needs a broker approval (judge, PR #335).
  - **The source of truth for live shapes** is the TypeScript tool contract (`tool_contract.ts`), as for every other profile.
  - `orceld` receives the profile in the envelope and checks it against a Rust list of the live shapes.
  - A cross-language agreement test fails if the Rust list, the contract's `browser_structured` list and `exposure.rs`'s `LIVE_BROWSER_MCP_TOOLS` differ. The SG-000079 tests already do this between the contract and the documentation.
- **Why local configuration may pick a profile but never a program.** Selecting `browser_structured` widens only which shapes a caller may ask for, and every consequential one still needs a broker approval from the user. A Node or worker path decides what code runs inside the worker job, with no approval in between, so it is never configurable (decision 7).
- **OAuth.** `browser_structured` joins `UNMAPPED_REMOTE_PROFILES` (denied), so remote mapping stays disabled.
- **The SG-000079 tables change in one PR,** with the mechanical agreement tests:
  - `LIVE_BROWSER_MCP_TOOLS`;
  - discovery;
  - documentation;
  - the OAuth scope tables;
  - runtime.

### 7. Node and worker sources

- **Never from a caller, and never from a user-writable runtime setting.** `validate_launch` only checks a file name. A same-user config file could otherwise make `orceld` run any executable inside the worker job.
- **Until SG-000106: a build-time pin.** A non-default cargo feature, `live-browser-dev`, compiles the Node and worker paths in at build time, together with the SHA-256 of `node.exe` and of the worker's `main.js`, and the host verifies both hashes before every launch.
  - **Amended in slice 3b: the whole runtime tree, not `main.js`.** `main.js` imports the rest of `dist/` and `playwright-core`, so a hash of the entry point alone would pin nothing it loads. The pin is the SHA-256 of `node.exe` plus a digest of the runtime tree: `package.json`, every non-test file under `dist/`, and every file under `node_modules/playwright-core/`. Each file is hashed through a handle that shares reads only, refusing writes, renames and deletes, and the handles are held for the worker's whole lifetime, because Node loads modules lazily.
  - **Every directory on a pinned path is held too** (judge, PR #336). Each directory from the drive root down to every held file, and to `node.exe`, is held without delete sharing, and each handle is checked: none may be a link or other reparse point. No component of a pinned path can then be renamed, removed or swapped for a junction while the worker runs. This includes a junctioned `node_modules`, which the tree walk alone did not catch.
  - **The resolve guard covers what Node finds outside the tree.** Node also looks for modules outside the pinned tree. playwright-core's bundled `ws` runs an optional `require("bufferutil")` at import, which searches `<root>/node_modules` and every parent up to `C:\node_modules`, a folder any local account can create in. And a `node_modules` created inside `dist/` after the check would shadow playwright-core. Pinning cannot stop a new file appearing, so the worker's `main.js` is now a bootstrap that installs a resolve guard (`module.registerHooks`) before importing anything else. The guard refuses every module that is not a Node built-in or a file the runtime manifest names (round 2, below; it first allowed any file inside `dist/` or `node_modules/playwright-core/`). An optional require sees a refusal as "absent". The bootstrap also sets `WS_NO_BUFFER_UTIL` and `WS_NO_UTF_8_VALIDATE`, so `ws` does not probe for those modules at all. The worker now requires Node 22.15, the first version with `registerHooks`.
  - **`node.exe`'s folder must not be writable by the user.** Windows loads a DLL planted beside an executable before the system's. A pinned launch therefore refuses a `node.exe` in a folder whose security grants the current user any right to change it (round 2, below; it first tried a write). A standard Program Files install passes. CI's setup-node toolcache is user-writable, so there the native test requires that typed refusal instead.
  - **Digest framing.** Paths are length-prefixed, and file names with control characters are refused (judge LOW-1).
  - **What the pin is not.**
    - In a dev build the host and `orceld` binaries, and the worker's repository folder, are files the user can write. A same-user process able to rewrite them, or to inject into the running processes, is outside what the pin defends.
    - It guarantees four things:
      - local configuration cannot point the worker at other code;
      - the exact pinned files run unmodified from the check until the worker ends;
      - no path component above them can be swapped;
      - no module outside them loads.
    - Files a process could use without Node loading them as modules, such as Node's own built-in snapshot or ICU data inside `node.exe` (pinned with it), are covered only through `node.exe`'s hash.
    - SG-000106's signed payload replaces this pin.
  - Without the feature there is no live browser path; this is how a development build is told apart from a release build.
  - The release build commands never enable it, and release qualification asserts it is absent.
  - A changed Node or worker file is refused, typed, until rebuilt.
  - SG-000106 later replaces this with a signed, pinned Node runtime and the worker files in the payload.
- **Release builds** report the live browser as typed unavailable. This is stricter than SG-000108's scope, which allows a separately installed Node, and is intended until SG-000106 pins both.

### 8. Gating until the binding and exposure land

- **Slices 1 and 2** compile `orceld`'s live backing only under a test-only cargo feature, `live-browser-test`. The feature exists in both crates: in `orcel-browser-host` it also enables fixture admission and fixture-certificate trust in the **binary**, which today are `cfg(test)` only.
  - The fixture pin can be made only by `AdmittedDestination::fixture`, `#[cfg(test)] pub(crate)`.
  - The host binary that `Supervisor` spawns is not built with `cfg(test)`.
- **Release qualification asserts the feature is absent from both crates' artifacts,** as the spec's network delta requires for the fixture origin.
- **Release builds** of slices 1 and 2 therefore have no live browser path at all.
- **Slice 3** lifts the gate only together with the profile gate and the exposure change. Even then, the live path exists only in `live-browser-dev` builds (decision 7).

## Slices

1. **Host worker mode and the two-part binding, behind `live-browser-test`.**
   - The host binary gains `--worker`, the `open`, `bind`, navigate, observe, activate and download frames, the lifetime nonce and the ephemeral marker.
   - Native tests drive `orceld`'s dispatch functions against the controlled fixture.
   - **Feature relationship.** `live-browser-test` does not enable `live-browser-dev`. Native tests take Node and the worker from `ORCEL_SG108_NODE` and `ORCEL_SG108_WORKER_MAIN`, a source compiled only into test builds and unreachable from a `live-browser-dev` or release build.
   - **No gap between check and launch.** The hashed `node.exe` and worker files stay open, without write or delete sharing, from the hash check until the worker has started. Otherwise the launched handle is the one verified. The engine's A10 `reverify` adopts the same hold.
   - Binding negative tests:
     - a replayed record id;
     - a binding from another lifetime;
     - another node;
     - a stale generation;
     - another folder or file name.
2. **The full journey through `orceld` with a real `LocalApprovalBroker`, still behind the feature.**
   - The presence verifier is scripted only in test builds.
   - Failure paths:
     - host death after a commit, reconciled (open question 1);
     - a dead lifetime marks its page stale;
     - the MCP-side timeout versus the worker's longer waits (open question 3).
3. **Exposure and the public journey.**
   - Decisions 5 and 6. Live browsing becomes available in `live-browser-dev` builds (decision 7), and remains absent from release builds.
   - Native Windows evidence of the `done_when` journey on a public HTTPS site: a dated document list, the latest PDF downloaded create-only, and its bytes and SHA-256 verified by an independent checker. The site is chosen at that slice, and its URL and expected digest are recorded at evidence time.

## Open questions, each with an initial proposal

1. **Reconciliation after uncertainty.** If the host dies after `approved_folder::commit` renamed a file but before it replied, a committed file exists with no `orceld` evidence. Proposal: `orceld` records an intent (folder, file name, record id) before dispatch. After host death it checks the destination for that exact name, and never re-downloads automatically. It reports the file as **"present, unverified"** with its SHA-256 and size, or as absent. `orceld` cannot tell the host's committed file from one a same-user process placed there, so it never records the file as a committed download. Partial writes are already safe: the temp file is delete-on-close and the rename never replaces.
2. **Several `orceld` processes.** Each MCP connection runs its own `orceld` over a shared on-disk page store. Proposal: the store records which process and lifetime owns each page, and refuses a page owned by another live process, typed.
3. **Timeouts.** `KernelClient` waits 30 s by default; worker waits go up to 45, 75 or 90 s, plus approval time. Proposal: live browser requests get their own budget, and the action runs to its bounded completion. If the MCP side has given up, the outcome is still recorded in the store and the audit.
4. **FailureCode mapping.** Proposal, using existing `orcel_contracts::FailureCode` variants only, with no contract change:
   - `HostError::Unavailable(reason)` maps to `ProviderUnavailable`;
   - a timeout maps to `ProcessTimeout`;
   - a crashed or dead lifetime maps to `TargetStale` for the page;
   - an unverified postcondition maps to `PostconditionFailed`;
   - a host binding mismatch at dispatch maps to `TargetStale`, because the approved action no longer matches the page, after the approval was consumed;
   - a binding that cannot be computed before the prompt maps to `InvalidRequest`.
5. **Page data on disk and in logs.**
   - Raw accessible names stay in the host, keyed per lifetime.
   - `orceld`'s stores receive only the bounded, redacted observation it already models.
   - `orceld`'s stderr (forwarded by `kernel.ts`) must never contain URLs or page text.
6. **Process limits.** Proposal: raise the host's job limit to cover the nested worker job, which also has a limit of 32. Add a native test of the real `orceld` → `spawn_host_piped` → host binary death path. The existing host-death test uses a test binary as the host.
7. **Idle timeout and per-workspace lifetime limits.**

## What stays out

- Personal or signed-in profiles (SG-000100).
- Script evaluation, generic CDP, and selectors as authority.
- Remote browser control and relay mapping.
- Uploads beyond SG-000078's recorded sources.
- The SG-000106 packaging itself.

## Implementation status

**Slice 1a: host worker mode (test builds only).** Its authority delta is the worker-mode host vocabulary, generation 2.

**What it adds:**
- **Feature.** `orcel-browser-host` gains the test-only `live-browser-test` feature. With it, the binary has a `--worker` mode, and fixture admission and fixture-certificate trust become available to that mode.
- **Worker mode (`worker_host.rs`).** It serves a closed generation-2 vocabulary: hello, `open` (loopback fixture only), navigate, observe, close and shutdown. It allows one lifetime at a time.
  - **Profile.** Each lifetime runs in the host's own `ephemeral_profile_dir` profile, carrying the A9 marker that is checked by an adopt-back before launch.
  - **Lifetime nonce.** A 128-bit nonce from the system RNG.
  - **What crosses.** Observations cross as identities and digests only. A reply that does not fit one frame drops nodes and says so. Errors cross as closed codes, never as message text.
- **Supervision.** `Supervisor::launch_worker_host` keeps the single-host rule across both modes and leaves the profile to the host.

**What it does not add:**
- the `bind` frame and the two-part binding (slice 1b);
- link activation and download (slice 1b);
- any `orceld` dispatch;
- any exposure.

**Evidence:**
- `tests/sg000108_worker_host.rs`, run by `npm run browser-launcher:native` as a second, feature-enabled pass (4 tests). It drives the real binary under `Supervisor` against the fixture and checks:
  - open: 32-hex nonce, pin 127.0.0.1, the host-pid-named profile;
  - a second open is refused, typed;
  - navigate returns 200, and another origin is refused;
  - observe returns no raw page text;
  - close: job empty, profile removed;
  - a mid-lifetime shutdown takes the worker and the profile with it;
  - a second host is refused.
- **Managed-policy precondition.** The host binary reads the real registry (the SG-000074 managed-policy precondition), so on a host with a managed browser policy every `open` is refused, typed, before anything starts. CI's windows-latest runner has one.
  - There, the worker-host tests require exactly `unavailable:managedpolicy` with no profile left, and still check the single-host rule and shutdown.
  - The full lifetime journey is evidenced on the evidence host, which has no managed policy. This mirrors `the_real_registry_precondition_decides_the_launch`.
- **Without the feature:** `worker_mode_does_not_exist_without_the_test_feature` shows that `--worker` is an unknown argument.
- **Release guard:** `the_live_browser_test_feature_never_reaches_a_release_build` (release-blocker sweep) is a source scan. It allows the feature to be named only in:
  - the host crate's own definition and code;
  - its tests;
  - the native-suite launcher;
  - documentation.

  In the manifest it may appear only as its own empty definition: no default and no other feature enables it. No other crate depends on the host crate, and the release build compiles only `orceld` and `orcel-lifecycle`.
- **Cleanup paths:**
  - a refused `open` leaves no profile:
    - checks that need no profile come first (`a_refused_open_leaves_no_profile_behind`);
    - a launch refused after the profile exists removes it (`a_launch_refused_after_the_profile_exists_removes_it`). With only that removal deleted, the test fails (mutation run);
  - `Supervisor::shutdown` and its drop also shut a worker-mode host down.
- **Unit tests under the feature:** the native launcher also runs the feature-enabled `--lib` unit tests (the closed vocabulary, closed error codes, frame before hello).
- **Follow-ups recorded:**
  - **L1, the blocking hello and shutdown reads.** `Supervisor`'s hello and shutdown reads block without a deadline, as the classic handshake already does. They need a reader thread with `recv_timeout`, as `BrowserWorker` has. Slice 1b.
  - **L3, the committed URL.** `Navigated.url` is the committed URL, which a same-origin redirect chooses. Slice 1b decides whether `orceld` receives it or only the requested URL and a digest.
- **sg000085:** its certificate-flag rule accepts the feature gate, `cfg(any(test, feature = "live-browser-test"))`, besides `cfg(test)`.

**Slice 1b, host side: two-part binding and the bound actions (test builds only).** The worker-mode vocabulary moves to generation 3; generations 1 and 2 are refused at hello.

**`open` takes `policy_revision`.** It is bound into every host binding, together with the lifetime nonce and the workspace.

**New frames:**
- **`bind`** returns the host binding and the action's target, for the prompt. The binding is SHA-256 over a domain tag, the lifetime nonce, the workspace, the policy revision, and the action's material as the host sees it now:
  - **navigate:** the URL and the host's pin;
  - **click:** page, origin, document generation, node, role, and the link's resolved destination;
  - **download:** the same, plus the host's `download_binding` (the link, the approved folder's real path, the normalized file name).
- **`select_latest_dated_link`** is the host's typed selection. Raw names never leave the host. It replaces any caller-supplied selector.
- **`navigate`, `activate` and `download`** each carry the broker record id and the binding. The host refuses:
  - a record id already presented in this lifetime: `approval_replay`;
  - a binding it can no longer derive, or that differs: `binding_mismatch`. That covers another URL, node, file name or lifetime, and a page that moved on.

  A record id is spent once presented. Only then does the host build its own SG-000077 target and run its existing activation or download path: create-only commit, origin, type and size checks.
- **`downloaded`** returns the relative name, the SHA-256, the size and the source URL.

**`navigated` keeps returning the committed URL.** It is always on the lifetime's single origin, because the policy refuses anything else, and `orceld`'s page store records it. *Decision on 1a follow-up L3.*

**Supervision has deadlines.** `LiveWorkerHost` reads replies on a reader thread. Hello and shutdown wait at most 30 s, and each request at most `WORKER_HOST_REPLY_TIMEOUT` (150 s, above the worker's longest bound). A silent host is a typed timeout. *1a follow-up L1.*

**Evidence,** worker-host pass with 6 tests:
- **`the_journey_downloads_the_latest_report_through_bound_approvals_and_verifies_it`:**
  - the latest dated report, selected by the host, is committed create-only through a bound download;
  - an independent checker compares the bytes with the fixture's report and its SHA-256, `5523ba2d…994a`;
  - the same record is then refused as a replay;
  - a fresh record with the old binding is refused as a mismatch;
  - a second download to the same name is refused, and the file is unchanged.
- **`a_binding_names_one_lifetime_node_and_file_and_nothing_else`:**
  - a navigation binding presented for another URL is refused;
  - a download binding presented for another file name or another node is refused;
  - a binding from a previous lifetime is refused;
  - nothing was written.
- **Mutation runs:**
  - with the binding comparison removed, the binding test fails: another URL was navigated;
  - with record ids never remembered, the journey's replay check fails.
- **The launcher accepts the pass only with each lifetime test's evidence line,** or with the managed-policy refusal line. With `ORCEL_SG108_REQUIRE_JOURNEY=1`, set per run on the evidence host, the journeys themselves are required. *1a follow-up.*

**What remains for slice 1b:** `orceld`'s dispatch over these frames, behind the feature, with the broker's record ids.

**Slice 1b host side, review fixes (round 1).**
- **Replies stay in step.** Replies carry no request id, so a reply that missed its deadline would have been read as the answer to the next request.
  - `LiveWorkerHost` reads through a `ReplyChannel` that is poisoned after any timeout or channel failure. Every later request on that host is refused, and only shutdown remains (`is_usable` reports it).
  - Unit tests cover the late reply and a failed frame. The mutation that leaves the channel unpoisoned fails both.
- **Only sent nodes can be acted on.** When an observation reply drops nodes to fit one frame, the host forgets every node it did not send (`retain_host_nodes`). `bind`, `activate`, `download` and selection can therefore only target nodes Orcel received.
- **What runs is what was verified.** Dispatch builds the host's SG-000077 target from the state verified against the binding: the link's destination, or the host's `download_binding`. It never re-derives that state. The actuation path then checks the verified state against its current state, so a folder junction swapped between verification and dispatch is refused.
- **The size limit is bound.** Download bindings include the size limit, `MAX_TRANSFER_BYTES`, as decision 3 lists.
- **The digest is a pure function.** `binding_digest`'s unit test calls it directly. With the workspace dropped inside `binding_digest`, the test fails. If `host_binding` passed an empty workspace instead, no test would notice yet, because every lifetime under test uses one workspace and the nonce already separates lifetimes.
- **Replies are also poisoned on a failed or partial write.**
- **Follow-ups, closed in the orceld-side PR:**
  - **The workspace at the call site.** The binding test recomputes the host binding independently from the documented formula (nonce, workspace, revision, action) and requires an exact match. With the workspace replaced by an empty string where `host_binding` is called, the test fails (mutation run).
  - **A trimmed observation.** The fixture's `/crowded` page does not fit one reply frame. The host now trims depth-first, dropping the last leaf first, so a reply keeps the largest prefix of the tree: 483 of 512 nodes. Dropping whole top-level subtrees, the earlier behaviour, could empty a page whose content sits under one root. `nodes_a_trimmed_observation_dropped_cannot_be_acted_on` requires every node the host observed but did not send to be unbindable. Without `retain_host_nodes`, the dropped node `d1-e486` was bindable, and the test fails (mutation run).
- **Click path.** `a_bound_click_follows_the_approved_link_once`: a bound activation opens exactly the approved link. Its replay is refused, and the old binding with a fresh record is refused.
- **Exact codes.** The other-origin navigation and the create-only refusal both assert the exact code `invalid`: the binding matched, and the policy or the commit refused.
- **Launcher.** Under a managed policy, every lifetime-opening test must report the refusal itself: four journeys plus the shutdown test.

**Slice 1b, orceld side: the approval broker in front of the host (test builds only).**

**The feature.** `orceld` gains a test-only `live-browser-test` feature, which enables the host crate's feature, and an optional dependency on the host crate. A default or release `orceld` build has neither. The release-blocker sweep allows exactly that feature definition and that optional dependency in `orceld`'s manifest.

**`orceld/src/live_browser.rs` runs decision 3's two-part approval for each consequential action:**
1. The host binds the action (`bind`).
2. `orceld` builds the approval digest: SHA-256 over a domain tag, the workspace, `orceld`'s policy revision, the lifetime nonce, the action, and the host binding.
3. It prompts. The broker mints the approval, then consumes it against that exact digest, workspace and revision.
4. Only then does it send the frame, with the broker's record id and the host binding.

So a denied, unavailable or mismatched approval never reaches the host. Host refusals map onto existing `FailureCode`s: binding mismatch → `TargetStale`, replay → `ApprovalDenied`, timeout → `ProcessTimeout`, unavailable → `ProviderUnavailable`.

**No envelope dispatch yet.** The native tests drive the module directly. The live-backed page store arrives in slice 2, and exposure in slice 3.

**Deferred to slice 2, together with the page store** (review of this PR):
- **`orceld`'s half of the digest** does not yet bind the page id or the store generation that decision 3 lists. There is no store yet. Today it binds the workspace, the policy revision, the lifetime and the action.
- **The "consumed, not dispatched" record and reconciliation** (open question 1) are not implemented.
  - **What already fails closed:** a lost reply poisons the host connection, so later actions fail at `bind`, before any prompt, and no further approval is spent.
  - **What is still open:** a download the host committed whose reply was lost leaves a file with no evidence record.

**The download prompt names the destination.** Its summary carries the source URL, the approved folder and the file name, which are also bound into the digest.

**Evidence: a fourth native pass, `orceld` live tests, 2 tests.** The launcher first builds the host binary with the feature, then hands its path to the tests through a test-only variable, `ORCEL_SG108_HOST_BINARY`.
- **`the_journey_runs_under_the_broker_and_commits_the_verified_report`:** broker-approved navigation, observation, the host's selection, and a broker-approved, create-only download. An independent checker verifies the bytes and the SHA-256, `5523ba2d…994a`.
- **`a_denied_or_mismatched_approval_never_reaches_the_host`:**
  - a denied navigation and a denied download fail with `ApprovalDenied`;
  - an approval whose consume fails, because the token's digest was changed, is refused;
  - nothing was written;
  - the lifetime stays usable, and the next approved download commits.
- **Mutation run:** with the broker's consume removed, the mismatched approval's download is committed, and the test fails.
- **Under a managed policy** (CI), both tests require the typed refusal instead. The launcher requires their evidence lines, or the refusal lines. With `ORCEL_SG108_REQUIRE_JOURNEY=1` it requires the journeys.

**Slice 2a: the real ledger, lost replies and reconciliation (test builds only).**

**The real broker in tests.** `orcel-approval` gains a test-support-only constructor, `LocalApprovalBroker::with_path_and_soft_decider`. It replaces exactly one step, the SOFT consent dialog (a system-modal `MessageBoxW`), with a scripted decision. Everything else is the real broker: the ledger, the nonce, expiry, single use, digest and scope checks, and the records. STRONG approvals still need the presence verifier.
- `test-support` is enabled only through dev-dependencies, and the workspace uses resolver 2, so release builds never contain it.
- Unit tests over a real ledger: an approval is consumed once, a second consume is refused, a wrong digest is refused, the record is marked consumed, and a scripted denial issues nothing.

**A lost reply ends the lifetime.** `orceld`'s `LiveBrowser` dispatches every consequential frame through one path, which records each consumed approval's outcome: Executed, Refused (closed code), or Lost. This is decision 3's "consumed, not dispatched" record.
- A lost reply (timeout, or a dead or broken host) ends the lifetime. The next action fails with `TargetStale` before any prompt, so no further approval is spent.
- **A lost reply also ends the host.** A silent host may not be a dead one: a suspended or slow host could still commit the file after orceld gives up on it. So on any lost reply `LiveBrowser` shuts the whole host family down at once (job termination if it does not leave by itself) and records whether its end was confirmed. That record is set once and never revised, because a second shutdown finds no host and would report a vacuous success.
- Every dispatch error path records Lost, including a dispatch that found no host.
- Transport failures (a broken pipe, a platform fault) map to `ProviderUnavailable`; a silent host maps to `ProcessTimeout`.

**Reconciliation.** A download's intent (record id, folder, file name) is recorded before its frame is sent. After a lost reply, `reconcile()` reports what is at that destination: present, unverified (with SHA-256 and size), or absent. It never re-downloads and never records the file as committed.
- **Only after the host's end is confirmed.** Until then `reconcile()` refuses with `ProviderUnavailable` and keeps the intent; it is never silently dropped.
- **Path safety.** The file name must pass the host's own destination validator (`validate_relative_destination`: no root, traversal, alternate data streams, trailing dots or spaces, reserved device names, control or format characters). No segment below the approved folder may be a reparse point, intermediate segments must be directories, and the name must be a regular file; anything else is refused, not reported.
- The file is opened without following a reparse point (`FILE_FLAG_OPEN_REPARSE_POINT`), the opened handle's own metadata is checked again, and the hash is streamed from that handle, never past `MAX_TRANSFER_BYTES`. A larger file is refused.

**Evidence: the `orceld` live pass, 4 tests.**
- **The journey now runs on the real ledger** (scripted consent). The ledger holds exactly the two approvals, both consumed. Both outcomes are Executed. Reconciling the committed name reports exactly the committed file's SHA-256 and size.
- **`a_host_lost_after_the_consume_is_recorded_reconciled_and_ends_the_lifetime`:**
  - A test-only hook kills the host after the broker consumed the download's approval and before the frame reached it.
  - The approval is consumed in the ledger, and its outcome is Lost.
  - The lifetime is over: the next navigation is `TargetStale`, and no new prompt is recorded.
  - Reconciliation reports the destination absent.
  - The host process itself is confirmed exited (a handle opened before the kill is waited on), and the family's end is confirmed before reconciling.
  - **Mutation run:** with the lifetime kept after a lost reply, the test fails.
- **`a_suspended_host_is_ended_before_its_lost_download_is_reconciled`** (the judge's reproduction of the gap, now a regression test):
  - The hook suspends the host (`NtSuspendProcess`) instead of killing it, so the download's reply is lost while the host is alive. A test-only reply budget (5 s) stands in for the 150 s production one.
  - The outcome is Lost with `ProcessTimeout`, the family's end is confirmed, and the suspended process itself has exited.
  - Reconciliation reports the destination absent, and it is still absent 3 s later.
  - **Mutation run:** with the shutdown skipped (the end recorded as confirmed without it), the test fails: the suspended host is still running.
- **Unit tests:** the reconciliation gate (running or unconfirmed: refused and the intent kept), a hostless dispatch recorded Lost, the I/O and platform error mapping, and path safety (streams, trailing dots and spaces, reserved names, an intermediate junction, a junction at the name, the size limit at and past `MAX_TRANSFER_BYTES`). Mutations removing the gate, the size limit, or the hostless record each fail a test.
  - **Not covered:** removing the explicit reparse-attribute check is not caught, because junctions and symlinks are already refused as neither directory nor file. The check remains as defense in depth for reparse points that are not name surrogates (cloud placeholders such as OneDrive's, deduplicated files); the unit test cannot create one portably, so it is uncovered.
  - **Residual (accepted, judge round 2):** intermediate segments are checked by path and the file is then opened by path, so a same-user process swapping an intermediate directory for a junction in between could have an outside file's hash and size reported as present, unverified. That process could equally place the file at the destination itself, and the result is only reported, never adopted. Optional later hardening: compare the opened handle's final path with the canonical folder.
- **Deferred from slice 2a to slice 2b** (done below): the page id and store generation in `orceld`'s half of the digest, the live-backed page store, and persisting the intent across a `orceld` restart. The MCP-side timeout budget (open question 3) moved on to slice 3.

**Slice 2b: the page store and the intent journal (test builds only).**

**The lifetime's page lives in the page store.** `open` allocates a page in the SG-000022 `PageStore`, bound to the workspace and to the lifetime (profile identity `live-lifetime:{lifetime}`).
- Every approved navigation applies the committed document to the store: a new origin and a bumped generation.
- A lost reply or a shutdown closes the page. A closed page is stale for good, including after a reload from disk (`PageStore::close_page`).
- If the store cannot follow the host (a write fails, or the committed URL does not parse), orceld ends the lifetime rather than act on a page record that no longer matches.

**The page store's half of the digest.** `orceld`'s approval digest is now `orcel-sg108-live-approval/2`. It binds the page id, the generation and the origin, as well as the workspace, policy revision, lifetime, action and host binding. An approval prompted for one document cannot be spent on the next.

**Registry writes fail closed.** `PageStore::persist` used to drop write errors silently, so the in-memory registry could claim a state its file did not hold. A failed or unsynced append now fails the transition with `ProviderUnavailable` before the in-memory state changes. This applies to every page-store caller, not only the live browser.

**The intent journal (open question 1 across restarts).**
- **Durable before the approval is spent.** A download's `pending` line (record id, folder, file name, and the host's pid and creation time) is appended and synced before the approval is consumed. If it cannot be written, the approval is not consumed and nothing is sent.
- A reply, whether success or refusal, appends `settled`. An approval that failed to consume appends `abandoned`. A report of the destination appends `reconciled`, so each lost download is reported once.
- **Recovery at start.** `LiveBrowser::start` reconciles every open intent whose host is gone before launching a new host.
  - `orceld` holds the host's job, which is set to kill its processes when the job closes. When `orceld` ends, the kernel ends the host family, so after a restart the recorded host is gone.
  - "Gone" is checked against the OS, not assumed. The pid either names no running process, or names one with a different creation time (a reused pid).
  - An intent whose host still runs belongs to a live lifetime, possibly another `orceld` process's (open question 2), and is left untouched. A query the OS refuses to answer counts as running.
  - A report that cannot be made yet (the destination is unreadable for now) stays open for the next run.
- **Torn lines.** A crash mid-append leaves a torn line: a strict prefix of a valid line, written before the approval was consumed.
  - The next append seals it with a newline first, so a new line never fuses with it.
  - The reader skips a line only when its JSON ends early (the only way a prefix can fail), wherever it is. This includes a prefix that splits a multi-byte path character, because lines are read as bytes.
  - A torn `settled` or `reconciled` line leaves its intent open, and it is then reported again: still safe.
  - Any other unreadable line, unknown event or schema, or a pending line without its destination fails closed.
  - Zero bytes (allocated but never written, after a power loss) are never part of a written line, since JSON escapes control characters. Trailing zeros are dropped from each line, so a zero-filled run is skipped and a torn prefix followed by zeros still reads as torn (judge, PR #334; fixed in the slice 3a PR). A zero byte inside an otherwise complete line is corruption.

**Open question 3 (the MCP-side timeout budget) moves to slice 3.** No MCP path reaches the live browser until exposure lands there, so the budget is designed together with the `browser_structured` shapes it applies to.

**Evidence: the `orceld` live pass, 5 tests.**
- **The journey** now also checks:
  - the page store: generation 0 with an empty origin at open; after navigation, generation 1 with `https://fixture.test:443` and Active; Closed on disk after shutdown;
  - an unwritable journal refuses the download with `ProviderUnavailable`, leaves its approval unconsumed in the ledger, and sends no frame;
  - the download's journal lines are exactly `pending` then `settled`, with nothing left open.
- **The lost test** also checks that the page is gone (closed on disk) and that the intent stays open until reconciled.
- **`a_restart_reconciles_the_download_a_lost_host_left_open`:**
  - the host is killed after the consume, and `orceld`'s browser ends without reconciling, so only the journal remains;
  - the next `LiveBrowser::start` reconciles that exact record as absent, and nothing is left open;
  - a third start reports nothing.
- **Unit tests:**
  - the journal fold (settled, abandoned and reconciled close an intent; a torn tail is skipped and is sealed, not fused, by the next append; a torn multi-byte character; five kinds of corruption fail closed);
  - liveness (running, exited, and a reused pid by creation time);
  - recovery (gone-present reported with SHA-256 and size; gone-absent; reused pid; a live host untouched; each reported once);
  - the page store: close is idempotent and survives a reload, a closed page refuses navigation and actuation, and an unwritable registry changes nothing;
  - the digest covers page id, generation and origin, with a fixed vector computed independently.
- **Mutation runs,** each failing a test:
  - recovery that ignores host liveness;
  - recovery that does not journal its report;
  - a lost lifetime that leaves its page open;
  - consuming the approval before the intent is durable;
  - appending without sealing a torn tail.

**Accepted residuals (judge, PR #334), to handle in slice 3:**
- A recorded host pid reused by a protected or other-user process answers "unknown", so its intent stays open (safe, but unreported) until that pid is free. Fix: an intent whose host started before the current boot is gone; and expose the intents left open, not only the reconciled ones.
- Pages of lifetimes ended by a orceld crash, or whose close failed to write, stay open on disk and count toward the per-workspace page bound. They can never be acted on again, so this affects availability only. Recovery should close them, keeping open question 2 in mind: another orceld may own a page.
- In-session `reconcile()` drops its in-memory intent on an error (the journal keeps it for the next start), and journals a non-transient error only at startup.
- Slice 3 must re-derive the page fields at consume time if prompting and consuming are ever separated.

**Still deferred to slice 3:**
- the profile gate;
- `browser_structured` exposure;
- the MCP timeout budget;
- routing the SG-000022 page shapes to the live page;
- the public-PDF journey.

**Slice 3a: the profile plumbing (decision 6, no live tool yet).**

**The profiles.** `ToolSurfaceProfile` gains `browser_structured`.
- `desktop_structured` is now an explicit, frozen list (`DESKTOP_STRUCTURED_TOOLS`) instead of every contract key, so adding a tool to the contract, a browser tool in particular, never widens it. A test requires it to list every non-live contract tool and nothing else.
- `browser_structured` is `desktop_structured` plus `LIVE_BROWSER_TOOLS`, which is empty until slice 3b.

**Selection by local configuration only.** A local transport (stdio or loopback HTTP) reads `ORCEL_TOOL_SURFACE_PROFILE` once, at transport start, from the MCP client's server launch environment, which the user writes.
- Unset selects `desktop_structured`. `browser_structured` must be named exactly.
- Any other value, including `core`, fails startup with `TOOL_SURFACE_DENIED`, and the value is not echoed back.
- No tool argument and no remote value reaches it. The relay transport ignores it.

**OAuth.** `browser_structured` joins `UNMAPPED_REMOTE_PROFILES`, so remote mapping denies it. Every known remote provider still maps to `core`.

**The profile travels with each request.** `orceld`'s request line (`RemoteRequestEnvelope`) gains an optional `profile`, beside `remote` and outside the unchanged internal request.
- The kernel client of a local transport stamps its profile on every request, and the `process_spawn` kernel inherits it.
- Remote dispatch sends none; its profile is in the remote context.
- An absent profile is omitted from the line, so existing lines and clients are unchanged.

**`orceld`'s profile gate (`profile_gate.rs`).** This runs before any lease, policy or dispatch step.
- A live browser shape is refused, with `CapabilityDenied` and audited `PROFILE_DENIED`, unless the request is local and names `browser_structured`.
- A remote request is refused whatever profile it names.
- Every other shape passes unchanged: the profile grants nothing by itself.
- `LIVE_BROWSER_SHAPES` is empty until slice 3b, so the gate is wired in but has nothing to refuse yet. Its logic is unit-tested over a test shape list.

**One table, three places.** `browser-exposure.test.ts` reads the two Rust tables strictly: each must be defined exactly once, with its exact type, and hold only string literals. A named constant, a comment, a `cfg` duplicate or another type fails the test rather than reading as empty (judge, PR #335). It fails unless these three agree:
- the contract's `LIVE_BROWSER_TOOLS`, mapped to their capability shapes;
- `orceld`'s `LIVE_BROWSER_SHAPES`;
- the host's `LIVE_BROWSER_MCP_TOOLS`.

It also requires every live tool to be local-only.

**Guards amended, transparently.** The earlier guards forbade the word "browser" in MCP sources and in `server.ts`. They now allow only the governed exposure-table names: `LIVE_BROWSER_TOOLS` in `tool_contract.ts`, and the `browser_structured` profile name. They still forbid any `"browser.` capability string and any browser registration anywhere, and they now also require `LIVE_BROWSER_TOOLS` to be empty until slice 3b.

**Evidence:**
- `npm run test --workspace @orcel/mcp`: 195 tests, 194 passed, 0 failed, 1 skipped (the pre-existing Go-toolchain test, which CI runs).
- The 6 new exposure tests cover:
  - the cross-language agreement;
  - the explicit `desktop_structured` list;
  - `browser_structured` membership;
  - local-only selection (unset, exact, and six refused values);
  - no remote mapping;
  - the kernel stamping the profile.
- `orcel-contracts`: the profile parses beside the request and is omitted when absent.
- `orceld` `profile_gate`: 3 unit tests. Mutation runs that drop the remote check or the profile check each fail a test.
- **The gate's wiring in `handle_envelope`:** not covered by a committed test until slice 3b, because no live shape exists for one to reach. The judge probed it by adding a temporary shape, and the probe was reverted:
  - no profile, or `desktop_structured`: refused;
  - `browser_structured`: passed on to the workspace check;
  - remote with `browser_structured`: refused as local-only;
  - each refusal was audited `PROFILE_DENIED`.
- `desktop_structured` must hold no tool with a `browser.*` capability, so a browser tool left out of the live list cannot land there instead.

**Slice 3b-i: the worker runtime pin (decision 7 as amended).**

- **`runtime_pin.rs`** (host crate):
  - `runtime_files` walks the runtime tree. A link or any other reparse point anywhere in it, or a missing `package.json`, refuses the whole tree.
  - `tree_digest` frames each (relative path, file SHA-256) pair under the domain `orcel-worker-runtime-tree/2`. Its fixed vector is computed independently.
  - `measure_and_hold` opens `node.exe` and every tree file with read-only sharing and without following a reparse point, rechecks each handle, and hashes through it.
  - `RuntimePin::verify_and_hold` requires an exact match and keeps the handles.
- **Judge round 1 blocked this slice** (PR #336). The findings and their fixes:
  - **HIGH:** an optional module outside the tree, found up to `C:\node_modules`, ran inside a pinned worker. Fixed by the resolve guard and the `WS_*` switches.
  - **HIGH:** links were checked only inside the tree, and a junctioned `node_modules` could be swapped after the check. Fixed by checking and holding every directory on the path.
  - **MEDIUM:** a `node_modules` added later inside `dist/` could shadow a pinned file. Fixed by the resolve guard.
  - **MEDIUM:** a DLL beside `node.exe` was not covered. Fixed by refusing a `node.exe` in a user-writable folder.
  - **MEDIUM:** the honesty section was not accurate enough. Rewritten above.
  - **LOW:** the digest framing could collide. Fixed by length-prefixed paths.
- **`WorkerLaunch.runtime_pin`.** When it is set, `launch_worker` verifies and holds the runtime after the managed-policy check and before anything is swept or spawned. `BrowserWorker` keeps the held files for the worker's lifetime, and they are released when it ends. Launches without a pin (every caller so far) are unchanged.
- **Not yet in this slice:** the `live-browser-dev` feature that compiles a pin in, and the destinations it may open. Those arrive with slice 3b-ii, which uses this mechanism.

**Evidence:**
- **Native** (`a_pinned_runtime_runs_held_and_a_changed_one_never_starts`, Edge 155, Node under Program Files):
  - the real runtime measures as 140 files, and 180 handles counting every directory on their paths;
  - a mismatched pin is refused with `UnsupportedRuntime` before the profile is touched;
  - the matching pin launches, the worker answers, and all 140 files stay held;
  - while the worker runs, `main.js` and `node.exe` cannot be opened for writing, and both are released after shutdown.
- **Unit tests:**
  - the tree is the loadable runtime only (tests and other packages are excluded);
  - held files cannot be written, renamed or deleted;
  - a changed file, an added runtime file or a changed `node.exe` is each refused;
  - changes to tests or to other packages do not affect the pin;
  - junctions inside the tree and unexpected entry points are refused;
  - the digest's framing has a fixed vector.
- **After the round-1 fixes:**
  - the matching pin still launches with all 180 handles held;
  - with a user-writable `node.exe` folder, the pinned launch is refused typed;
  - a junctioned `node_modules`, and a worker root reached through a junction, are each refused even though the tree walk alone accepts them;
  - a mutation that skips the directory holds fails two tests.
- **Worker** (`resolve-guard.test.ts`): a real Node run, with the guard installed, refuses modules planted in a parent folder's `node_modules`, a sibling package and a shadowing `dist/node_modules`, through both `require` and `import`. Built-ins and `playwright-core` still load. Worker suite: 130 of 130.
- The native launcher now expects 27 lib native tests.

**Slice 3b-i, judge round 2 (after the port onto main).** The judge found the port faithful and blocked on two gaps in the pin's guarantees:
- **MUST-FIX: the resolve guard admitted files the pin never measured.** It allowed any file under `dist/` or `node_modules/playwright-core/`, and holding a directory does not stop files appearing in it. playwright-core's CommonJS code requires names like `./lib/coreBundle` without an extension, and Node tries the extensionless name first, so a file planted beside a pinned one after the check would have loaded. `dist/*.test.js` files, excluded from the pin, were allowed too.
  - **Fix: an exact allowlist.** The worker build writes `dist/runtime-manifest.json` (`scripts/runtime-manifest.mjs`), naming every runtime file but itself. It is part of the tree, so it is pinned and held, and `measure_and_hold` reads it through its held handle and refuses it unless it names exactly the tree's other files, in order. The guard loads only Node built-ins and the files the manifest names (compared case-insensitively). A missing or malformed manifest installs no guard, and the worker does not start.
  - **Tests:** `the_manifest_names_exactly_the_measured_tree` (an extra name such as `lib/coreBundle`, a missing one, another order, another schema, an unknown field and no manifest each refuse the tree); in a real Node run, a file planted after the guard is installed under the extensionless name of a lazily loaded pinned module is refused, as is a test file; the built worker's manifest equals its runtime tree. A mutation that allows the manifest's directories instead of its files fails two tests.
- **MUST-FIX: the folder check was a write probe.** A folder the user owns keeps an implicit `WRITE_DAC`, so a same-user process could plant a DLL beside `node.exe`, deny itself writes so the probe failed, and the folder would pass.
  - **Fix:** `node_folder_writable` now asks `AccessCheck` with the process token, against the folder's security descriptor, whether it grants any of `FILE_ADD_FILE`, `FILE_ADD_SUBDIRECTORY`, `FILE_DELETE_CHILD`, `DELETE`, `WRITE_DAC` or `WRITE_OWNER`. Anything it cannot decide counts as changeable. `verify_and_hold` checks the folder after it is held, so it cannot be swapped after the check.
  - **Test:** `a_folder_the_user_owns_stays_changeable_when_it_denies_writes` (an `icacls` deny of WD and AD makes a write fail and the folder still counts as changeable). A mutation that counts only the add rights fails it. An elevated process may change system folders, so the test prints which case it saw rather than asserting on `System32`.
- **NITs fixed:**
  - a Node without `module.registerHooks` again gets the typed startup refusal (the bootstrap checks the version first and imports `node:module` as a namespace);
  - `measure_and_hold` is no longer exported;
  - the write probe, and the probe file it could leave behind, are gone;
  - the mangled `C:\node_modules` above is repaired.
- **Accepted:** every pin failure is the one typed `UnsupportedRuntime`, with no finer reason, so nothing about the files crosses to a caller. A `package.json` planted inside playwright-core can change how pinned files are parsed, but not make an unlisted file load, so it can only stop the worker.
- **Evidence:** the real runtime is 141 files and 181 held handles; the matching pin launches from `C:\Program Files\nodejs` (`AccessCheck`: unchangeable); worker suite 131 of 131.

**Slice 3b-i, judge round 3: APPROVE, with three hardening fixes taken.**
- **Nothing runs outside the guard.** The guard governs one thread's module loads. Before the worker loads, the bootstrap's `closeUnguardedRuntimes` therefore makes these throw: `worker_threads.Worker`, `child_process.fork`, `exec` and `execSync`, any spawn of Node's own executable (by path, or by the name `node` for a PATH lookup), and any spawn through a shell. playwright-core starts the engine, which is not Node, and that still works: the worker suite passes, real-Edge tests included. A real Node run checks that eight such attempts are refused and another program still starts.
- **Exact names.** Allowlist paths now compare exactly, except for the drive letter. Case-folding could admit a differently cased twin of a pinned file: NTFS can make a single directory case-sensitive, and JavaScript folds U+212A KELVIN SIGN to `k`. Manifest names must be printable ASCII.
- **The ACL test now tests the owner's implicit right.** It denies the user WD, AD, DC, DE, WDAC and WO, so only the owner's implicit `WRITE_DAC` is left, and the folder must still count as changeable. A mutation that drops `WRITE_DAC` from the change rights fails it.
- **Wording.** The earlier descriptions of the guard and of the folder check are updated.

**Slice 3b-ii: the `live-browser-dev` host and the destinations it may open (decision 7).**

- **The feature.** `orcel-browser-host` gains `live-browser-dev`, a development-only feature. It is never a default and no other feature enables it. No other manifest names it yet; `orceld`'s dispatch over it arrives with exposure (slice 3c). The release-blocker sweep (`the_live_browser_dev_feature_never_reaches_a_release_build`) allows it to be named only in:
  - the host crate's own definition and code;
  - its dev-host test;
  - the native-suite launcher and the pin script;
  - documentation.
- **The worker runtime is the build's own.** The binary's worker mode in a dev build runs only the runtime compiled into it from four build variables: `ORCEL_LIVE_BROWSER_NODE`, `ORCEL_LIVE_BROWSER_WORKER_MAIN`, `ORCEL_LIVE_BROWSER_NODE_SHA256` and `ORCEL_LIVE_BROWSER_TREE_SHA256`.
  - They are read with `option_env!` only, at compile time. rustc tracks them, so a new pin means a rebuild. The sweep requires that `main.rs` reads them in no other way and that nothing else names them.
  - `compiled_runtime` accepts only a whole, well-formed pin: absolute paths, a `<root>/dist/main.js` entry point and two lowercase SHA-256 digests. Anything else is no runtime at all, and every lifetime is then refused with `unavailable:unsupportedruntime`.
  - Every launch passes the pin to slice 3b-i's `verify_and_hold`, so a changed `node.exe` or runtime tree is refused, typed, until rebuilt.
  - `--node` and `--worker-main` are unknown arguments of a dev host, which exits on them. Only a test-only build takes them, from the test harness.
- **The pin script.** `apps/orcel-browser-worker/scripts/dev-pin.mjs` prints the four variables for the built worker. It is a second, independent implementation of `runtime_files` and `tree_digest`: the same fixed vector (computed with Python) and the same selection test as the Rust unit tests. A disagreement can only refuse a launch, because the host measures the files itself at every launch.
- **Destinations.** A dev host serves `open_public { workspace, policy_revision, url }` (worker-mode generation 4).
  - The host resolves the name itself and admits it only through `AdmittedDestination::admit`: SG-000075's rules, HTTPS on port 443, a public address, no IP literal, no single-label or metadata name. Its pin is the host's lowest public address, as before, and every host binding names it.
  - The resolution is bounded (10 s); a resolver that never answers is a typed timeout.
  - Everything that can be refused without a profile is refused first.
  - One destination per lifetime: the navigation policy still refuses every other origin.
  - The fixture `open` exists only in builds that also have `live-browser-test`.
- **Supervision.** `WorkerHostLaunch.node` and `.worker_main` are now optional. `orceld` passes neither to a dev host.

**Evidence:**
- **Unit tests (dev feature):**
  - `a_public_open_admits_only_public_https_and_refuses_before_any_profile`: no runtime → `unavailable:unsupportedruntime`; plain HTTP, another port, an IP literal, `localhost`, userinfo, `file:`, `javascript:` and the metadata name → `invalid`; loopback, private, link-local, ULA and metadata addresses → `invalid`; nothing is left in the profile root;
  - `a_development_build_has_no_fixture_open`;
  - `a_compiled_runtime_is_whole_and_well_formed_or_absent` (12 malformed or partial pins).
- **Worker:** `scripts/dev-pin.test.mjs`, the fixed vector and the same tree selection as the Rust unit test.
- **Native** (`tests/sg000108_dev_host.rs`, 2 tests). The launcher runs them twice, rebuilding the binary each time:
  - **built with a pin of another tree:** the public open is refused with `unavailable:unsupportedruntime` and no profile is made;
  - **built with the runtime's real pin:** a lifetime on `https://example.com/` opens with the host's public pin, the worker's entry point cannot be opened for writing while it runs, a bound navigation returns 200, the observation carries no raw page text, another public origin is refused, and close leaves an empty job and no profile, after which the runtime is released;
  - **both builds:** `--node` and `--worker-main` make the dev host exit before its hello.
  - Under a managed policy (CI) the open is refused with `unavailable:managedpolicy` instead, and with a user-writable `node.exe` folder with `unavailable:unsupportedruntime`; each prints its own evidence line. With `ORCEL_SG108_REQUIRE_JOURNEY=1` the launcher requires both lifetimes themselves.
