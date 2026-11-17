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
- The decider approves only prompts whose action is an isolated browser action and whose target host is `fixture.test`. It denies every other prompt. STRONG approvals have no presence verifier and fail closed.
- Every decision goes to the consent log with the exact dialog text a person would have seen.
- The release-blocker sweep (`the_browser_full_scripted_consent_feature_never_reaches_a_release_build`) keeps its name out of every place except orceld's manifest, entry point and consent module, this script and docs, and requires its one definition.
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

## Not covered

- The founder-present run (above).
- Emergency stop during a session, a crashed orceld, the per-client and device session caps, and a second MCP client naming this session: these are covered by orceld's unit tests, not by this mission.
- Public HTTPS sites: this mission uses the loopback fixture only.
- macOS and Linux.
