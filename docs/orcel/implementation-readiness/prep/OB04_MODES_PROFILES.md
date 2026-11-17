# OB-04: Shadow and Visible modes, persistent Orcel-managed profiles

**Status: implemented on `browser/ob04-modes-profiles` (SG-000135 work packet OB-04), stacked on OB-03 (PR #806). Not merged. Scripted-consent evidence only; the founder-present run has not happened.**

Grain: SG-000135 (PR #801). OB-04 owns acceptance SH-1, SH-2, SH-8, FA-F, FA-H, the Shadow half of FA-E and the modes part of FX-6. What this branch proves, and what it does not, is listed at the end.

## 1. Modes

`browser_session_create` takes an optional `mode`. The broker records it for the session's whole life (`SessionMode` in `crates/orceld/src/browser_broker.rs`) and passes it to the session's host. The host builds the matching engine argv (`EngineMode` in `crates/orcel-browser-host/src/confinement.rs`).

| | `shadow` (default) | `visible` |
|---|---|---|
| Engine | headless | headed: one window of its own |
| argv | the SG-000108 argv, unchanged | the same argv without `--headless`, plus `--window-name=Orcel agent session` right after the frozen flags |
| Attachment | `--remote-debugging-pipe` only | the same |
| Profile | isolated (ephemeral or a named Orcel profile) | the same |
| Destination policy | SG-000075 / SG-000108, unchanged | the same |
| Page input | CDP over the pipe (never OS input) | the same |
| Replies say | `no_interference: true` | `no_interference: false` |

### The Visible argv amendment (SG-000108 frozen argv)

This is the one change to the frozen command line, and it applies to `browser_full` Visible sessions only. `browser_structured` always launches Shadow; a test checks its host launch names `EngineMode::Shadow` and never `Visible`.

- Removed: `--headless`.
- Added: `--window-name=Orcel agent session`, a fixed value with no caller text, placed right after the frozen flags.
- Everything else is the same as Shadow, element for element: `--user-data-dir`, `--remote-debugging-pipe`, the resolver pin map, the no-route proxy, the bypass list, the WebRTC and QUIC rules, the SharedWorker refusal, the disabled network features and `about:blank`.
- The host builds it (`build_worker_argv_in`) and checks it exactly (`assert_worker_argv_exact_in`). Neither mode's argv passes as the other's, and a different window name is refused.
- The worker checks it again (`launchRefusal` and `isVisibleArgv` in `apps/orcel-browser-worker/src/protocol.ts`). It accepts exactly the Shadow form or exactly the Visible form. The engine runs headless unless the argv is exactly the Visible form (`entry.ts`: `headless: !isVisibleArgv(spec.argv)`).
- Nothing in either argv raises, maximises or focuses the window. Both refuse `--start-maximized`, `--start-fullscreen`, `--kiosk`, `--app` and `--remote-debugging-port`.

### The foreground

Orcel itself never activates the window. No code on the browser path calls a foreground, activation, input, cursor or clipboard API (section 3). The engine does activate its own window when it opens and when it creates a page, whenever Windows allows it (section 2a, item 2). A Visible session therefore asks the owner first and never claims no-interference. The scripted run records whether the window took the foreground and requires the cursor and clipboard to be unchanged.

## 2. Persistent Orcel-managed profiles (FA-H, SH-8)

Store: `crates/orceld/src/browser_profiles.rs`, rooted at `<browser-profile>/live/named-profiles` in orceld's own protected browser state, beside the broker's root.

```
named-profiles/
  locks/<name>.lock          OS file lock held by the one live session on <name>
  locks/.store               store-wide lock around create and delete
  <name>/profile.json        {schema: orcel-ob04-profile/1, name, created_at_ms, created_by_client}
  <name>/data/               the engine user-data-dir for every session on <name>
```

- **Names, never paths.** A profile is named by 1 to 32 lowercase letters, digits and inner hyphens. orceld builds every path from the checked name. A path, `Default`, `..`, a separator or a person's profile folder is refused by the MCP schema, by orceld's parser and by the store.
- **Real directories only.** The store root, the lock folder, each profile folder and each data folder must be real directories, never a junction, symbolic link or other reparse point. Every data folder must lie inside the store root. Removal never follows a reparse point.
- **Host check.** The host checks the data folder again before each lifetime (`crates/orcel-browser-host/src/persistent_profile.rs`). It must be an absolute path whose leaf is `data`, with no `User Data` component (the folder name every Chromium-family browser gives a personal profile root). Neither it nor its parent may be a reparse point. On first use an empty folder is marked with Orcel's profile marker; afterwards the marker must match, or the launch is refused and nothing is repaired. A persistent profile's marker binds the engine family and path, not the version, so an Edge update keeps it usable (`Engine::profile_family`). The host never removes a persistent profile, and the #298 leftover sweep never runs for one.
- **One live session per profile.** `browser_session_create {profile}` takes the profile's lock before the worker starts. The lock is device-wide, across every orceld, and a crashed orceld's lock frees itself. A second session is refused (`TARGET_STALE`). The lock is released when the session ends, after its worker is gone, or with a refused create.
- **Kept across sessions and restarts.** A session on a profile uses `<name>/data` in place of an ephemeral profile. Its cookies and site storage stay there when the session ends, through any number of orceld restarts, until the profile is deleted. Session ids still die with their orceld (OB-01).
- **Isolation.** Two sessions on different profiles have different data folders, and each keeps its own session folder (staging, downloads, page store, host state). The session folder is removed at close as before. Nothing is shared.
- **Owner-approved writes.** `browser_profile_create` and `browser_profile_delete` each ask a fresh SOFT approval. The title is `create an Orcel-managed browser profile` or `delete an Orcel-managed browser profile`, the target is `orcel-browser-profile:<name>`, and the digest binds the operation, the workspace and the name. The request is refused before any prompt when it could not succeed (name taken, 16 profiles already, profile missing, profile in use). Delete checks the lock again under the lock after approval. `browser_profiles` lists names, creation times and whether each profile is in use; it never shows a path, cookie or stored value. Using a profile asks once per MCP session (section 2a), and every action in it still asks its own SOFT approval, which names the profile; no lease exists yet (OB-08).
- **Ephemeral stays the default.**

"Reused by the same owner-approved client": no client identity survives an MCP session today (`client_session_id` is per session), so a profile belongs to the local owner, and each MCP session must get the owner's approval before its first use of a profile (section 2a). That means the owner's Windows account, whose Orcel state holds it, and any local client the owner configured for `browser_full`. Remote callers never reach these shapes (section 4). Binding a profile to one named client needs the client identity that OB-08's lease scope introduces.

On the grain invariant "the profile is chosen by local configuration, never by a tool argument": this branch reads it as the MCP tool surface profile (`ORCEL_TOOL_SURFACE_PROFILE`), which stays configuration-only. A browser profile name in `browser_session_create` selects only among profiles the owner approved, and it grants no authority. The security judge should confirm this reading.

## 2a. After the security judge on 3204448b

The fresh-context judge failed the first head. Each finding and what changed:

1. **Blocking: another local client could drive a signed-in profile with no approval.** Fixed:
   - The first time an MCP session (`client_session_id`) uses a persistent profile, orceld asks a fresh SOFT approval. The title is `use an Orcel-managed browser profile in a session` and the target is `orcel-browser-profile:<name>`. The prompt names the profile and the client, and says the profile may be signed in to sites. The digest binds the workspace, the client and the name.
   - The approval is remembered per workspace, client and profile, for that MCP session only, and is forgotten whenever every session ends: an emergency stop, an approval epoch that moved (an emergency revoke in any orceld) or could not be verified, or orceld's input closing. After a revoke, the same MCP session is asked again before it reuses a signed-in profile. The checks that need no prompt run first: the profile exists, no session holds it, no engine runs in it.
   - `profile.json` records `created_by_client`, the MCP session whose approved write created the profile. `browser_profiles` shows it, for display only; it grants nothing.
   - Every navigation, link click and new-tab prompt in a persistent profile names it: the first preview line says "Profile: the Orcel-managed browser profile <name>; it may be signed in to sites", and the summary ends with `profile=<name>`. Every fill and select prompt has the same preview line; its summary is the shown value and stays unchanged.
   - Every receipt carries `profile`. The receipt digest domain is now `orcel-ob04-receipt/2` and includes it.
   - Binding a profile to one named client beyond this needs a client identity that survives MCP sessions. That waits for the authority service (SG-000132) and OB-08's lease scope.
2. **Medium: Visible mode.**
   - A Visible session asks a fresh SOFT approval before anything launches. The title is `open a visible Orcel browser window`, the target is `orcel-browser-session:<session id>`, and the digest binds the workspace, the client and the session id.
   - **File choosers.** Every page of every session, Visible or Shadow, has a file-chooser listener, so Playwright intercepts the chooser and the engine never opens an OS file dialog. The chooser is left unanswered (denied). Uploads keep their own SG-000026 path (`setInputFiles`).
   - **Clipboard.** Every launch calls Playwright `grantPermissions([])`, which the engine applies as "grant these and reject all others" for every origin. Clipboard read and write, notifications, geolocation and every other permission are denied. A page's asynchronous clipboard calls reject, even right after an approved click gave it a user activation. A refusal fails the launch. The native test (`desktop-guard.native.test.ts`) checks the permission state on the installed Edge, on the page and on a second page. It never writes or reads the real clipboard.
   - **Clipboard residual.** The legacy `document.execCommand("copy")` path is not governed by permissions. After an approved click it could still place text on the system clipboard, in Visible and in today's headless Edge alike. No engine flag or permission blocks it. Measuring it would write the person's real clipboard, so it is recorded here, not tested.
   - **Window activation residual (measured, not fixed).** Edge 157 activates its own window when it opens and again whenever the engine creates a page (a navigation's fresh page, a new tab). That happens when Windows lets a process take the foreground, as it does once the person has been idle past the foreground-lock timeout. These were tried on this PC (Edge 157) and none prevents it:
     - `--start-minimized` is not honoured.
     - Chromium has no show-without-activation switch.
     - Playwright exposes no `STARTUPINFO` show state.
     - Minimising the window over CDP (`Browser.setWindowBounds`) hands the foreground back at once, but the next page creation restores and activates the window. That holds even for a target created with `background: true`.

     Two runs measured it: in the first the window stayed behind the person's window, in a later one (after the person had been idle) it took the foreground. Orcel itself never calls an activation API, and the cursor and clipboard stay untouched. So a Visible session now asks the owner first, its prompt says the window may come to the front and take keyboard focus, and it never claims no-interference. Fixing this needs either a worker that reuses one page in Visible mode or an engine change (OB-10's BrowserOS build).

3. **Low: a worker not confirmed gone.** When a session's worker cannot be confirmed gone at its end, its persistent profile stays locked (quarantined) for the rest of that orceld's life, and the end report says `profile_quarantined: true`. In addition, before any prompt and again at acquire, a profile is refused while a running engine holds its data folder: Chromium's Windows `lockfile` is present and cannot be opened for writing, or a `SingletonLock` exists. A stale lockfile left by an engine that is gone is not held, and the engine reuses it.
4. **Low: junction swap.** While a session holds a profile, orceld keeps handles on the store root, the profile folder and the data folder. They are opened on the path itself (never through a reparse point) with list access and without delete sharing. None of the three can be renamed or deleted meanwhile; files inside stay writable.
5. **Low: incomplete folders.** `browser_profile_delete` also removes a real folder of a valid name that an interrupted create left incomplete (no `profile.json`). It does so under the profile's lock and the store lock, never following a link.
6. **Info: the 16-profile cap.** Create and delete take a store-wide lock (`locks/.store`, a name no profile can have), so the cap and the names hold across processes.

## 3. Shadow: Orcel uses no OS input, clipboard, focus or foreground

This is about Orcel's own calls. A page is a different matter: it gets no async clipboard permission, but in Shadow as in Visible it can still copy text to the system clipboard with the legacy `execCommand("copy")` after an approved click (section 2a, item 2). The scripted mission's clipboard check covers the fixture pages, which do not do that.


- `crates/orceld/tests/ob04_shadow_scan.rs` scans every non-test source on the browser path for foreground, activation, synthesized-input, cursor and clipboard calls (`SetForegroundWindow`, `SendInput`, `SetCursorPos`, `OpenClipboard`, `bringToFront`, `navigator.clipboard` and more). The scanned code is the browser host crate, the session-state crate, the browser provider, orceld's broker, profiles, live browser, dispatch and takeover gate, and the Node worker. It finds none. The test also checks that the host crate cannot compile those calls: its `windows-sys` has no keyboard-and-mouse, clipboard or windowing feature.
- `apps/orcel-browser-worker/src/shadow.test.ts` does the same for the worker sources. It also checks that the headless decision comes only from the argv.
- The scripted run reads the foreground window, cursor position and clipboard sequence number before `browser_session_create` and again after `browser_close` (read-only Win32 calls through a PowerShell probe). They must be unchanged. It also checks that the Shadow session has no visible window while it lives. If the person at the PC gave any input meanwhile (`GetLastInputInfo` moved), the three comparisons are recorded as inconclusive, never as passed.

## 4. MCP surface

| Tool | Shape | Effect | Approval | Remote |
|---|---|---|---|---|
| `browser_session_create` (adds `mode`, `profile`) | `browser.session/create` | write | SOFT for a Visible window or a profile's first use in the MCP session; none otherwise | local only |
| `browser_profiles` | `browser.session/profiles` | read | none | local only |
| `browser_profile_create` | `browser.session/profile_create` | write | SOFT | local only |
| `browser_profile_delete` | `browser.session/profile_delete` | destructive | SOFT | local only |

The contract (`apps/orcel-mcp/src/tool_contract.ts`), orceld's profile gate (`BROWSER_FULL_SHAPES`), the host's exposure list (`BROWSER_FULL_MCP_TOOLS`, `BROWSER_FULL_TOOL_SHAPES`) and `docs/p16/TOOL_CONTRACT.md` list the same 15 broker tools; `browser-full.test.ts` checks that they agree. Remote mapping stays disabled: the profile gate refuses every broker shape for a remote request.

## 5. browser_structured through the broker: deferred

Routing the 12 `browser_structured` shapes through the broker is not low-risk, so it is deferred:

- **Behaviour would change.** A structured lifetime would take a broker device slot (4 per device across every orceld). Then a `browser_structured` request could be refused where it is accepted today, and a `browser_full` session could be refused because a structured page holds a slot. The grain requires `browser_structured` to keep SG-000108 behaviour exactly.
- **Identity does not map.** Structured shapes name a `page_id` from the shared page store (`live/pages.jsonl`), not a broker session. Mapping them needs an implicit per-client session and a translation of page ids. That touches the SG-000120 journal and recovery path (`live/intents.jsonl`) and the takeover gate's tickets, all of which are keyed to the structured slot today.
- **Receipts and budgets would appear.** Broker sessions add receipts and action budgets. Structured replies would change unless both were hidden, and hiding them is a second code path, not "the same behaviour".

The broker and the structured slot already share every authority: the profile gate, policy, the takeover gate, the approval broker and the live host. Only the session bookkeeping differs. The move belongs with OB-05, whose receipts on the audit chain change the reply contract anyway, or with a packet that may change `browser_structured` replies.

## 6. Tests

- Host (`orcel-browser-host`): `ob04_visible_argv_differs_from_shadow_by_exactly_the_headless_and_window_name_flags`, plus three `persistent_profile` tests (mark then adopt and keep; foreign or personal folders refused; junctions never followed).
- orceld: `browser_profiles` (seven tests: names; create, list, hold, keep; two profiles share nothing; delete; count bound; foreign folders ignored; links and junctions refused), `browser_broker` (four OB-04 tests: a profile outlives its session and serves the next one in a new orceld instance; two sessions on different profiles share no profile, staging or host folder; the mode is recorded and only Shadow claims no-interference; a refused session releases its profile), `browser_full` (the mode and profile forms are closed and never a path), the profile gate, the scripted consent (profile writes approved only for `ob04-e2e-*`), and `tests/ob04_shadow_scan.rs`.
- Worker: the Visible launch form in `protocol.test.ts`, and `shadow.test.ts`.
- MCP: `browser-full.test.ts` (15 tools agree; the schemas refuse a bad mode or any path as a profile; each tool forwards only its own fields).
- After the judge:
  - `browser_profiles`: the creating client recorded; create and delete under the store lock; a data folder a running engine holds refused; held folders cannot be renamed or deleted; incomplete folders deletable.
  - `browser_broker`: an unconfirmed worker quarantines its profile; profile approvals per client; receipts name the profile.
  - `live_browser`: every prompt in a persistent profile names it.
  - The scripted consent: profile use and the Visible window.
  - Worker: `desktop-guard.native.test.ts` (permission state on the installed Edge, file chooser intercepted) and `shadow.test.ts`.
- Scripted end-to-end (`scripts/browser-full-e2e.mjs`, section 7).

## 7. Scripted end-to-end run

See `OB01_E2E.md`, section "OB-04 extension", for the phases. Scripted run on this PC, 2026-11-17, Edge 157 (scripted consent, not human acceptance):

- Shadow: the foreground window, cursor and clipboard sequence were unchanged across the mission, with no human input, and the session had no visible window.
- A cookie set in a persistent profile was sent again by a new session in a new orceld. Two concurrent sessions on two profiles each ran their own Edge in their own profile, and no cookie crossed.
- Visible: one window titled `Orcel agent session`. It did not take the foreground, was not above the foreground window, and left the desktop unchanged.

Run after the security judge's fixes, 2026-11-18 (Edge 157, scripted consent):

- Shadow desktop unchanged, with no visible Shadow window.
- The cookie was kept across the orceld restart. Two concurrent profiles each ran their own Edge, and no cookie crossed.
- 16 OB-04 prompts, all approved by the scripted decider:
  - three first uses of a profile, each saying it may be signed in;
  - one Visible window;
  - every page prompt in `ob04-e2e-keep` and `ob04-e2e-other` named its profile.
- The profile session's receipts each carried `profile` and recomputed under `orcel-ob04-receipt/2`.
- Visible: one `Orcel agent session` window took the foreground this time, with no human input. This is the recorded residual (section 2a). The cursor and clipboard were unchanged.

## 8. Not proven here

- **SH-1 as written.** The founder's 10-minute run, with a person typing and moving the mouse while a Shadow session fills a two-page form, has not run. The scripted run compares the desktop across a mission of about 20 seconds and marks the comparison inconclusive if the person gave input.
- **SH-2.** Toggling Shadow mid-mission, moving the task to an isolated session without repeating a submit, needs OB-05's receipts to carry the task across sessions. Not implemented. The mode is fixed for a session's life.
- **FA-F with a person browsing.** The concurrent-session isolation is checked (two sessions, two profiles, no cookie crossing). The person's own browsing in another browser during two missions is the founder run.
- **FA-E and FX-6 close in OB-08.** This branch provides the Shadow half and the two modes only. There is no lease, so every routine action still asks.
- **Window z-order.** Windows decides where a new top-level window is placed. The run records whether the Visible window ended up above the foreground window, and Orcel never activates it. No `SW_SHOWNOACTIVATE`-style placement control exists through Playwright's launch, so "never above" cannot be promised beyond what the run shows.
- **Engine updates for persistent profiles.** The marker survives an Edge update. Downgrading Edge below the version that last wrote a profile is refused by Edge itself.
- **A named client.** A profile is owned by the local owner, not by one named MCP client (section 2).
- **Founder-present run.** Every approval above was scripted consent.
