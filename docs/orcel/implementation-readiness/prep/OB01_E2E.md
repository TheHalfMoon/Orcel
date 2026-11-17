# OB-01 end-to-end mission over local stdio MCP

**Status: PROVISIONAL (SG-000135 acceptance FA-C).** The scripted-consent run below passed on the founder's Windows PC. That is scripted consent, not human acceptance. The founder-present run, where every Orcel approval dialog is answered by the founder, has not run yet.

## What the mission proves

One local MCP client drives the whole Orcel Browser path, with no internet:

```
MCP client (scripts/browser-full-e2e.mjs, JSON-RPC over stdio)
  -> orcel-mcp (local transport, ORCEL_TOOL_SURFACE_PROFILE=browser_full)
    -> orceld (Orcel Browser Session Broker, profile gate, policy, takeover gate, approval broker)
      -> orcel-browser-host --worker (supervised, worker runtime pinned at build time)
        -> browser worker (Node, playwright-core)
          -> installed Edge 157 (qualified), headless, over a pipe, Orcel-managed ephemeral profile
            -> test-only HTTPS fixture on 127.0.0.1:443 (fixture.test, its own certificate)
```

The mission, in order:

| # | Tool | What it does | Approval |
|---|---|---|---|
| 1 | `browser_session_create` | New broker session: own worker, own ephemeral profile folder | none |
| 2 | `browser_open` | `https://fixture.test/ob01-form` | SOFT |
| 3 | `browser_snapshot` | Finds the `Full name` text field, the `City` list and the one link | none |
| 4 | `browser_fill` | `Full name` = `Ada Lovelace` | SOFT |
| 5 | `browser_select` | `City` = `Porto` | SOFT |
| 6 | `browser_verify` | URL is the form; the field holds the value; the list holds the option | none |
| 7 | `browser_click` | The link to `https://fixture.test/ob01-done` (new generation) | SOFT |
| 8 | `browser_verify` | URL is the second page; its result text is visible | none |
| 9 | `browser_extract` | The second page's text, untrusted and bounded | none |
| 10 | `browser_task_status` | The session's provisional receipts | none |
| 11 | `browser_close` | Worker ends, profile folder removed | none |

The script then checks, itself:

- 8 receipts (open, snapshot, fill, select, verify, click, verify, extract), each `done`, each chained to the one before, and each receipt digest recomputed independently from the fields (the same length-prefixed SHA-256 as `crates/orceld/src/browser_broker.rs`). Four of them carry an approval record id.
- While the session lives: its folder holds one profile, and the one Edge browser process of this run is `--headless`, uses `--remote-debugging-pipe`, has its profile inside the session folder and has no `--remote-debugging-port`.
- After `browser_close`: `worker_ended` and `profile_removed` are true, the session folder is gone from disk and the closed session id is refused (`TARGET_STALE`).
- After the MCP session ends: orceld exits, no Edge process of this run is left and no session folder is left.

## Two consent modes

| | `--consent scripted` | `--consent founder` |
|---|---|---|
| Who answers each approval | The approval crate's existing test-support SOFT decider (`LocalApprovalBroker::with_path_and_soft_decider`, the mechanism orceld's native live-browser tests use) | The founder, in the real Orcel dialog |
| orceld features | `live-browser-test,live-browser-dev,browser-full-scripted-consent` | `live-browser-test,live-browser-dev` |
| Dialogs on screen | None | Four (open, fill, select, click) |
| What it is | Test harness | Founder acceptance run |

`browser-full-scripted-consent` is new and test-only:

- It enables nothing but `orcel-approval/test-support`. orceld refuses to compile it without both live browser features, and refuses to start without an absolute `ORCEL_E2E_CONSENT_LOG` (checked: `orceld fatal: this is a test-only OB-01 harness build with scripted consent; it refuses to start without an absolute ORCEL_E2E_CONSENT_LOG`).
- The decider approves only the mission's four exact action titles (navigate, type a value, choose an option, open a link) whose whole target is `https://fixture.test`, with an optional `:443` and an optional path, and no whitespace. It denies every other prompt. STRONG approvals have no presence verifier and fail closed.
- Every decision goes to the consent log with the exact dialog text a person would have seen.
- The release-blocker sweep (`the_browser_full_scripted_consent_feature_never_reaches_a_release_build`) keeps its name out of every place except orceld's manifest, entry point and consent module, this script and docs, and requires its one definition.
- In a scripted build, `browser_open` of any other URL takes the public path, which resolves the host name (a DNS lookup) before the approval prompt; only then does the scripted consent deny it. The mission opens only the fixture, but a scripted build given another URL is not network-silent.
- Each mode builds into its own target folder (`<CARGO_TARGET_DIR or target>\ob01-scripted` and `ob01-founder`), with `cargo build --locked`, so a founder run, even with `--skip-build`, can never pick up the scripted-consent orceld.
- In scripted mode the script reads the consent log's start line right after `browser_session_create`, before any approval. If the line is missing, the binary is not the scripted build and the run stops there, so no real dialog can come up unanswered.

Both modes also build with the test-only `live-browser-test` feature. With both live features, `browser_open` of `https://fixture.test/...` opens a fixture lifetime that trusts exactly the fixture certificate (SPKI in `ORCEL_E2E_FIXTURE_SPKI`; host pinned to 127.0.0.1). A development build alone admits only public HTTPS, so it cannot reach a loopback fixture. Neither build is a development or release build.

Edge is launched only through Orcel's own discovery and launch: the host discovers and verifies the installed Edge, gives it a fresh Orcel-marked profile under the session folder and drives it over a pipe. The user's own Edge profile is never touched.

## Isolation

Each run makes its own state root, `%USERPROFILE%\orcel-ob01-e2e-<mode>-<time>`, and passes it to orcel-mcp and orceld as `USERPROFILE`, with `LOCALAPPDATA` and `APPDATA` under it. The approval ledger, audit log, broker sessions and profiles all live there. The user's real `%USERPROFILE%\.orcel` is never touched. The root is outside `AppData`, so its folders pass orceld's private-folder checks without any ACL change. It is removed at the end unless `--keep-state` is given. The evidence folder is kept.

## Founder run (not run yet)

Nothing in this run answers, clicks or scripts a dialog. The script only waits, up to 11 minutes per step, and records what happened.

1. Close any running Orcel desktop app or Orcel MCP client, so only this run's orceld is up.
2. Make sure nothing else listens on 127.0.0.1:443.
3. Install the locked dependencies once, in the repository (this downloads packages, so it is the founder's call):
   ```
   npm ci
   npm ci --prefix apps/orcel-browser-worker --ignore-scripts
   ```
4. Run, from the repository root (the build takes a few minutes the first time):
   ```
   node scripts/browser-full-e2e.mjs --consent founder
   ```
5. Four Orcel approval dialogs come up, one at a time. Read each one and decide yourself. The scripted run showed these texts, so expect the same apart from the lifetime, digest and approval code:
   - `Action: navigate isolated browser page`, `Target: https://fixture.test/ob01-form`
   - `Action: type the value on the line after Target into a field of an isolated browser page`, `Target: https://fixture.test:443`, then `Ada Lovelace`, then `Field name (page-supplied): Full name`
   - `Action: choose the option on the line after Target in a list of an isolated browser page`, `Target: https://fixture.test:443`, then `Porto`, then `Field name (page-supplied): City`
   - `Action: open a link on an isolated browser page`, `Target: https://fixture.test/ob01-done`
6. If you deny one, the run stops with that tool's refusal (`APPROVAL_DENIED`) and records it. That is a valid result, not a pass.
7. A pass ends with a line starting `OB01-E2E-EVIDENCE founder consent:`. The evidence folder (`%USERPROFILE%\orcel-ob01-e2e-evidence-founder-<time>`, or `--evidence <dir>`) holds `summary.json`: each tool call's outcome and time, every receipt, the chain head, the approval record ids, the close report, the leftover checks and the fixture's request log.

## Scripted run on this PC, 2026-11-17

Edge 157 (qualified), Node 24.19.0, Windows 11 Home 10.0.26300, no managed Edge policy. Head of `browser/ob01-e2e`: see the branch.

| Step | Outcome | Time |
|---|---|---|
| `browser_session_create` | ok | 188 ms |
| `browser_open` | ok, 200, `https://fixture.test/ob01-form` (includes the Edge launch) | 13162 ms |
| `browser_snapshot` | ok: field, list and one link found | 136 ms |
| `browser_fill` | ok; the reply does not carry the value | 77 ms |
| `browser_select` | ok | 44 ms |
| `browser_verify` (form) | ok, verified | 39 ms |
| `browser_click` | ok, `https://fixture.test/ob01-done`, generation 1 to 2 | 119 ms |
| `browser_verify` (second page) | ok, verified | 34 ms |
| `browser_extract` | ok, holds the result text, not truncated | 13 ms |
| `browser_task_status` | ok, 8 receipts | 3 ms |
| `browser_close` | ok: `worker_ended` and `profile_removed` true | 1999 ms |

- Whole MCP session: 19458 ms. orcel-mcp exit code 0.
- Receipts: 8, all `done`, chain recomputed, head `e8436b8ff86ccd3f...`. Approval record ids on open, fill, select and click.
- Live session: 1 profile in the session folder; Edge browser process headless, over a pipe, profile in the session folder, no remote debugging port (14 Edge processes in all, renderers included).
- After: closed id refused `TARGET_STALE`; 0 Edge processes and 0 session folders left.
- Scripted consent: 4 SOFT prompts, all approved by the scripted decider, dialog texts recorded (quoted above). **Not human acceptance.**
- A second run on the final code passed the same way: open 8450 ms (Edge launch included), snapshot 189, fill 142, select 73, verify 62, click 152, verify 44, extract 35, status 7, close 1297 ms; whole session 14548 ms; 8 receipts chained (head `5c1543e168f92f2b...`); nothing left.
- A third run after the security judge's low fixes (exact action titles, whole-target match, per-mode target folders, `--locked`) passed the same way: open 13926 ms, close 1623 ms, whole session 20629 ms, 8 receipts chained (head `0c107e148e46f87f...`), nothing left.

## OB-03 extension: screenshot and tabs (SG-000135 OB-03)

After `browser_extract`, the mission adds seven steps:

| # | Tool | What it does | Approval |
|---|---|---|---|
| 10 | `browser_screenshot` | Viewport PNG of the second page, as MCP image content; its SHA-256, size and byte count are checked against the reply | none |
| 11 | `browser_tabs` new | A second tab on `https://fixture.test/ob03-secret` (a navigation, title `navigate isolated browser page`) | SOFT |
| 12 | `browser_tabs` list | Two tabs, the first inactive, its URL without query or fragment | none |
| 13 | `browser_screenshot` | The second tab: the PNG is decoded and the pixels read. The ordinary field stays green (positive control). The password, one-time-code, card-number and secret-named fields are black (masked) | none |
| 14 | `browser_tabs` switch | Back to the first tab | none |
| 15 | `browser_verify` | The first tab still holds the second page | none |
| 16 | `browser_tabs` close | The second tab closes, and one tab is left | none |

Then `browser_task_status` must show 15 chained receipts, 5 with an approval record (open, fill, select, click and the new tab), and both screenshot receipts must carry the image digest only (`evidence_kind: screenshot`). Scripted consent must show 5 prompts. A founder run now shows 5 dialogs; the fifth is `navigate isolated browser page` with target `https://fixture.test/ob03-secret`.

Scripted run on this PC, 2026-11-17 (Edge 157, Node 24.19.0): every step passed.

- Step times: open 8368 ms (Edge launch included), screenshot 111 ms, new tab 780 ms, list 5 ms, masked screenshot 179 ms, switch 7 ms, verify 839 ms, close tab 26 ms, close 4495 ms.
- Whole session 19812 ms. 15 receipts chained, head `6813401cfaa44cfc...`. 5 approval records. No Edge process and no session folder left. MCP exit 0.
- Mask pixels: ordinary `[0,255,0]`, password, one-time code, card number and secret name all `[0,0,0]`.
- **Scripted consent, not human acceptance.**

A second run, after the security judge's fixes (tab-checked replies, no promotion when a tab closes itself, the wider mask, the pending-popup cap), also passed:

- Step times: open 8544 ms, screenshot 173 ms, new tab 1005 ms, masked screenshot 267 ms, close 4339 ms.
- Whole session 19837 ms. 15 receipts chained, head `bc00091fe0c48bad...`. 5 approval records. Same mask pixels as the first run. Nothing left.
- Scripted consent, not human acceptance.

A third run, after the re-judge's fixes (every page reply tab-checked, a crash handled like a self-close, and the mask census by place), also passed: open 8081 ms, masked screenshot 360 ms, close 915 ms, whole session 15590 ms, 15 receipts chained (head `9602290b018913a7...`), 5 approval records, the same mask pixels, nothing left. Scripted consent, not human acceptance.

### OB-03 limits and rules (after the security judge on b4ed449a)

- **A tab that closes itself.** When the active tab's page closes itself (`window.close()` from page script) or its renderer crashes, the worker makes no other tab active. Every action and screenshot is then refused (`TARGET_STALE`) until orceld sends a tab request (`browser_tabs`) and learns the tabs. Every page reply names the worker tab it ran on, and a screenshot reply also names the page's URL. That covers navigate, text fetch, observe, discovery, activate, form action, WebMCP execute, download, upload, wait, verify, extract and screenshot. The host checks the tab against the one it acts on and checks the URL against its committed document. A read from another tab is refused as stale. A navigation, click, form action, execute, download or upload reported from another tab ends as outcome unknown, with nothing observed kept. The host's check names every reply kind, so a new kind must be classified before it compiles.
- **What the mask does not cover.** It paints fields matching the secret selector in every frame present right before the capture, open shadow roots included. That means password inputs, secret `autocomplete` tokens, secret-looking names and ids (pass, pwd, otp, cvc, cvv, csc, cc-, pin, ssn, iban, card, token, secret, security), editable regions, and inline `-webkit-text-security`. The capture is refused if the frames change while it runs, or if the place (bounding box) of any secret field in any frame changes; adding one field and removing another counts as a change. A frame with more than 256 secret fields is refused. Not masked:
  - fields inside closed shadow roots;
  - secret text drawn on a canvas, or shown as ordinary text;
  - a text-security style applied by a stylesheet rule;
  - a page script that removes or hides Playwright's mask overlay while the capture runs (the overlay is page-visible DOM for the capture's duration).
- **Closing a tab runs its handlers.** It runs the page's own `unload` and `pagehide` handlers, which may send requests such as beacons. The worker's route stack still decides each request, so only the lifetime's admitted site can receive them. orceld asks the takeover gate first, as for any write on that tab.
- **Popups.** At most 4 popups wait for admission at once; any further popup is closed at once.
- **Where the image is kept.** It is in the tool reply only. The broker's receipt (`ActionRecord`, `browser_task_status`) keeps the SHA-256 digest (`evidence_kind: screenshot`) and never the image or its base64; the mission checks that no receipt holds `png_base64`.

## Not covered

- The founder-present run (above).
- Emergency stop during a session, a crashed orceld, the per-client and device session caps, and a second MCP client naming this session: these are covered by orceld's unit tests, not by this mission.
- Public HTTPS sites: this mission uses the loopback fixture only.
- macOS and Linux.
