# OB-06: human takeover and the 3000 ms quiet timer

**Status: merged as #817 (aa622184) (SG-000135 work packet OB-06, acceptance FA-G). The first head (f86e3819) failed its security review; section 8 lists each finding and its fix. Unit and Windows probe tests only; the founder-present run has not happened, and no real takeover was driven on a headed window.**

Founder requirement: when a person takes over the browser, the agent pauses at once, and it resumes only 3 seconds after the person's LAST input. Then it observes the page again, and the person's edits win. Shadow Mode uses no OS input, focus or clipboard.

The state machine itself is B1 (`crates/orcel-browser-session`, PR #802): `RUNNING -> HUMAN_OVERRIDE -> QUIET -> REOBSERVE -> REPLAN -> RUNNING`. OB-07 turned its gate on for every `browser_full` broker session. Until this packet, nothing fed it a person's input. OB-06 adds four things for Visible sessions: that input source, a contract code for the refusal, a hold over the whole session, and the rules for prompts and actions in flight.

## 1. What happens

```
person types or clicks while a Visible session's own window is in front
  -> human_input.rs reads it (25 ms poll, and again before every gate decision):
       GetLastInputInfo moved, and GetForegroundWindow's process is in this session's browser job
  -> takeover gate: every page of the session -> HUMAN_OVERRIDE, dated when the input happened
agent action on the session (a page read or write, a tab opened, switched or closed, closing the session)
  -> refused HUMAN_TAKEOVER ("browser session paused: human_override ..."), before any approval prompt
3000 ms after the last input (monotonic clock; each input restarts the count)
  -> REOBSERVE: a write is refused TARGET_STALE (reobserve_required) until a fresh browser_snapshot
  -> after the snapshot, writes planned on it go on (REPLAN -> RUNNING)
```

- **The whole session is held.**
  - The operating system says that input reached the window, not which tab, so every page of the session is held.
  - A page that opens during the hold is held from the person's latest input, like the rest. This covers a new tab and a popup the session adopts.
  - Operations on the session as a whole are refused while the person's latest input is under 3000 ms old or any page is in `HUMAN_OVERRIDE` or `QUIET` (`TakeoverGate::hold_session`). These are opening a tab (before `Tabs` and `TabNew` are sent), switching tabs, closing a tab (before `TabSwitch` and `TabClose`, and also when a refused new tab would be closed again), and the agent's `browser_close`.
  - Other sessions are not held: a person in session A's window never pauses session B.
- **3000 ms, never less.**
  - The quiet period is B1's `QUIET_MS`. It ends when `now - last_input >= 3000` on the gate's monotonic clock (`SystemClock`, an `Instant`).
  - The source dates each input by its age as the OS reports it, not by when orceld noticed it, so a late reading never stretches the pause.
  - `GetTickCount` moves in steps of the system timer (10 to 16 ms), so an age can read up to one step too large. Each input is therefore dated 16 ms later than its age says (`TICK_MARGIN_MS`), and never later than now, so the pause never ends before 3000 ms.
  - The tests check 2999 ms (held), 3000 ms (released) and the margin.
- **Refused, never queued.** orceld answers each request at once. A queued action would run on a plan made before the person acted, and the person's edits must win. The agent gets `HUMAN_TAKEOVER`, reads `browser_task_status` (its `page_state` is `HUMAN_OVERRIDE` or `QUIET`), and observes the page again once the hold ends.

## 2. Open choice 2: where a person's input comes from (recorded)

Page script stays forbidden (SG-000108), so no listener can run in the page. The options:

| Option | Verdict |
|---|---|
| DOM event listeners in the page | Forbidden: page script. |
| A CDP-observed signal | Chromium's `Input` domain only dispatches input; it reports none. Learning of trusted DOM events needs `Runtime` bindings or injected listeners, which are page script. |
| A low-level OS hook (`SetWindowsHookEx` `WH_KEYBOARD_LL` or `WH_MOUSE_LL`) | Rejected. It sees every keystroke's contents on the whole desktop, needs a message loop, and slows the person's input if orceld stalls. |
| **The OS last-input instant plus the window in front** | **Chosen.** Read-only, no contents, no hook and no message loop. |

The chosen source (`crates/orceld/src/human_input.rs`), Windows only:

- **When.** `GetLastInputInfo` gives the tick of the session's last keyboard or mouse input. `GetTickCount` turns it into an age, with the timer-step margin of section 1. The reading has no key, character, position or window in it.
- **Where.**
  - The window in front comes from `GetForegroundWindow`, and its process from `GetWindowThreadProcessId`.
  - The window counts as the session's when that process is in the session's browser job: `IsProcessInJob` against an owned duplicate of the kill-on-close job orceld put the browser host in.
  - The host, its worker runtime, the engine and the engine's children all stay in that job, because it allows no breakaway.
  - Only a definite answer is cached, per window and process. If the process cannot be opened or the query fails, the reading is marked unknown, and new input then counts as a person's on the session (fail closed: the agent waits). The next reading asks again, so a passing failure never blinds the source.
- **The rule.** A reading counts as a person's input when the last-input tick changed since the previous reading and the session's window is in front. The first reading is a baseline, so input from before the session watched never counts.
- **When it is read.** A thread reads it every 25 ms (`POLL_MS`). The gate reads it again before every decision: a read, a write, the check before the frame is sent, the end of a write, a page opening, a session-level operation and a status read.
- **Fail closed.**
  - If `GetLastInputInfo` fails, the reading counts as a person's input now, so the agent waits.
  - A Visible session that cannot get a source (no job handle) is not launched (`PROVIDER_UNAVAILABLE`), and its worker is shut down.
- **Orcel's own approval prompt.**
  - The click or key that answers an Orcel prompt can reach the browser window once the prompt closes. `LiveBrowser::request_token` tells the gate when a prompt opens and closes, and whether a person answered it (approved or denied).
  - Only for an answered prompt is input from 500 ms before to 250 ms after it closed not counted.
  - Why 250 ms after: a dialog acts on the key's press or the button's release. What can follow is the key's release, 50 to 150 ms after the press for ordinary typing, which lands within tens of milliseconds after the prompt closed.
  - A prompt that failed without an answer excuses nothing. It may have been refused before any dialog or been unavailable. A Windows prompt that timed out is still denied and recorded as a denial, but `orcel-approval` now reports it distinctly: `ApprovalDecision::Unanswered`, with the denial message `UNANSWERED_DENIAL`. orceld therefore does not count it as answered (`prompt_answered`). So an agent that repeats a fast-failing prompt cannot mask a person's input.
  - Input during the prompt with the browser in front still counts, so a person who takes the page over while the prompt is up stops the send.
- **Orcel's own input is not a person's.**
  - The agent's page input is CDP `Input.dispatch*Event` over the engine's debugging pipe. Chromium delivers it to the renderer directly, never through the OS input queue, so it does not move the last-input tick.
  - This is how Chromium's input domain works. It was not measured on this PC, because that needs a headed window on the developer's desktop (section 7).
  - If it ever did not hold, the agent would pause itself for three seconds after its own input. That costs time; it never lets the agent act under a person's hand.
- **Nothing on the desktop changes.**
  - orceld's `windows-sys` gains `Win32_UI_Input_KeyboardAndMouse`, `Win32_UI_WindowsAndMessaging`, `Win32_System_SystemInformation` and `Win32_System_JobObjects`.
  - Because those features are crate-wide, `tests/ob04_shadow_scan.rs` now scans every source under `crates/orceld/src`, not only the browser path, with no exemption. It looks for foreground, activation, focus (`SetFocus`), input-injection, cursor and clipboard calls.
  - The browser host crate still cannot compile those calls. It gains only `job_handle()`, a std handle duplicate.
- **Shadow sessions** have no window, so no source is started and no person's input can reach them (`takeover_input: "none"` in the status). Only an explicit control could hold one (section 4).
- **Other operating systems** have no source yet. The live browser is Windows-only today, so no Visible session runs there. macOS needs its own source: the `CGEventSourceSecondsSinceLastEventType` idle time and the frontmost application's pid are the analogue, in a later packet.

## 3. Contract

- **New failure code `HUMAN_TAKEOVER`** (HTTP 409).
  - It is appended to `FailureCode` as `HUMAN_VERIFICATION_REQUIRED` was in #810. The schemas are regenerated, the wire spelling and index are frozen in `crates/orcel-contracts/tests/contracts.rs`, and orceld's legacy code-name maps are updated.
  - B1's `HumanOverride` and `Quiet` refusals now map to it, and so does the session-level hold. Their message still starts `browser session paused:`.
  - `Paused` (an explicit pause), the stale reasons and `Cancelled` keep `TARGET_STALE`.
- **orcel-agent.** `HUMAN_TAKEOVER` joins `AWAIT_PERSON`: the refusal is not final, but the agent owes a fresh observation before any mutation. Its guidance says nothing was done, a person is using the window, wait about three seconds after their last input, then observe again. It never says approve, grant, lease or try again.
- **MCP and docs.** The `browser_task_status` description and `docs/p16/TOOL_CONTRACT.md` (and its generator) describe the takeover. The status reply gains `takeover_input` (`visible_window` or `none`). No tool was added or removed.
- **Receipts.** A refused action's receipt has outcome `refused` and failure code `HUMAN_TAKEOVER`.

## 4. Explicit controls, closing and emergency stop

The grain's scope lists `browser_pause`, `browser_takeover` and `browser_resume`. No MCP tool for them is added here:

- An agent-callable resume could end a person's hold, and an agent-callable takeover is not a person taking over.
- The founder's Take Over, Pause and Return to Shadow are the person's controls in the Orcel UI, which the Design session owns. Approvals stay with Windows dialogs.
- B1's gate already has the operations: `take_over`, `return_control`, `pause`, `resume` and `cancel`, reachable through `TakeoverGate::session_gate`. They wait for that UI's control path. `browser_full.test.ts` still checks that no tool is named after takeover.

**Closing (decided):** the agent's `browser_close` is refused with `HUMAN_TAKEOVER` while a person holds the session, so the agent never closes a window under the person. The person's own closing of the window, an emergency stop, the end of the MCP session and orceld's shutdown still end it.

Emergency stop is unchanged and does not go through the gate. A moved approval epoch ends every session before any session or gate is touched, and `end_all` shuts every worker down. The test `ob06_a_held_session_can_still_be_stopped_and_closed` covers cancel and close of the pages during a takeover.

## 5. An action in flight when the person acts

- **Checked twice before sending.** The gate is checked before the approval is spent or the lease is checked (`gate_confirm`). It is checked again inside `LiveBrowser::dispatch`, right before the frame is sent, because spending can take seconds: the ledger lock, the lease guard and service confirm, a download intent's write. Each check re-reads the OS first.
- **A late refusal sends nothing.** If the person acted in between, the approval is already spent but nothing is sent. The outcome is recorded as refused (`orceld:human_takeover`), the write ends `failed`, and a download does not end the lifetime, since nothing reached the host.
- **A sent frame runs to its end.** A frame already sent to the engine is not recalled: an action cut off halfway is worse than one that finished. Its outcome is recorded as usual.
- **Input during the flight supersedes the action.**
  - When the write ends, the gate reads the OS again (`after_write`, before `finish_write`). Input during the flight starts a new intervention, so the write is settled as superseded.
  - The next action is refused with `HUMAN_TAKEOVER`. After the quiet period, nothing planned before the person acted is sent until the page was observed again.
  - A consequential write whose outcome is unknown stays uncertain and is never admitted again until reconciled (B1 idempotency guard, unchanged).
- **Full Access (OB-08).** A takeover refusal of a write ends the session's Full Access lease (the existing OB-08 rule: "a person interrupted this browser session"). In a Visible session, a person's input on the window therefore stops lease-covered actions for that session until the owner issues a new lease. That is OB-08's decision, kept as is.

## 6. Tests

- **B1** (`crates/orcel-browser-session/tests/transitions.rs`): an event reported late counts its quiet from when it happened, exactly 3000 ms; a future instant is taken as now; an unowned resource is ignored.
- **Input source** (`human_input.rs`):
  - The first reading is a baseline. Only a new input with the session's window in front counts, dated by its age plus the timer-step margin, never after now. The latest wins.
  - An unreadable OS counts as input now.
  - The answer to an answered prompt is not counted, and input during the prompt is.
  - A prompt that fails unanswered about once a second masks nothing.
  - Only a definite membership answer is cached.
  - The monitor reads before handing input over, and a polling monitor's thread stops on drop.
- **Input source, Windows, read-only:**
  - A process belongs to a job only once assigned to it (a fresh test job and a windowless `cmd /C ping` child), the test process does not, and an unopenable pid answers "could not tell".
  - The real probe reads the last input and changes nothing; an empty job owns no window.
  - No test moves the mouse, sends input or touches the clipboard.
- **Gate with a scripted OS** (`takeover_gate.rs`, `ob06_tests`):
  - The first input pauses reads and writes. The agent is held at 2999 ms and released at 3000 ms into `REOBSERVE`, and a write is stale until a fresh observation.
  - Every input restarts the count.
  - A late reading counts from the input's own time plus the margin.
  - Input in another window, and the agent's own actions, hold nothing.
  - Input during an action in flight supersedes it and holds the next.
  - A takeover during the prompt stops the send, and the check right before the send sees input that came while the approval was spent. The click that answers a prompt does not stop it, and an unanswered prompt masks nothing.
  - A page opened during a hold (a new tab, an adopted popup) is held with the rest, until 3000 ms after the input.
  - No tab opens, switches or closes, and the session does not close, during a hold, even with no page yet.
  - Two sessions are independent, and Shadow has no source.
  - A held session can still be cancelled and closed.
  - An unreadable OS holds the agent.
- **The scan:** every orceld source is checked for desktop-touching calls.
- **Contracts, agent, MCP:** the frozen spelling, index and HTTP status; `AWAIT_PERSON` and the guidance; the status description.

## 7. Not done, and limits

- **Founder G as written.** The founder-present run has not happened: a person edits a Visible session's page, and the agent waits three quiet seconds, re-observes and keeps the edits. No test here sends real input; that would need `SendInput` on the developer's PC, which is not allowed. CI has no Visible-session harness.
- **CDP input not measured.** The claim that the agent's CDP input does not move `GetLastInputInfo` rests on how Chromium's input domain works and is not measured. The founder-present run should record it: a Visible session that only acts, with no one at the PC, must never report `HUMAN_OVERRIDE`.
- **Which tab is not known.** The whole session is held.
- **Gaps in what is seen.**
  - Input that reaches the window less than one poll (25 ms) before the person switches away from it can be missed. Input while the window stays in front is never missed, because the source is read again before every decision.
  - Windows scrolls an inactive window under the pointer by default ("scroll inactive windows"). Such wheel input moves the last-input tick, but with another window in front, so it is not counted.
- **The prompt edge.** For an answered prompt, input from 500 ms before to 250 ms after it closed is not counted, whatever window it reached. Input that goes on past that edge is counted.
- **A press held still.** A mouse button held down without moving produces no new input, so the quiet period can end during such a press. The B1 begin and end brackets for ongoing input have no source here. A key held down auto-repeats and does count.
- **The job.** A window counts when its process is in the session's browser job. Any process in that job is the session's family, by construction of the kill-on-close job. A window whose process cannot be opened (for example a protected process) is unknown. New input while it is in front holds the session, so typing in such a window pauses the agent (the safe side).
- **Other software.** Input another program injects while the session's window is in front counts as a person's (the safe side).
- **A locked or disconnected desktop** has no window in front, so nothing counts.
- **A refused new tab stays open.** If a new tab's navigation is refused because a person took over, the blank tab is not closed until the hold ends.
- **Shadow take-over.** Taking over a Shadow session needs the UI's Take Over control, which would move the task to a Visible window. It is not built.
- **macOS and Linux:** no source (section 2).
- **Review.** OB-06 is on the grain's list of packets that need a fresh-context security judge. d1-local is advisory only.

## 8. After the security review of f86e3819

1. **High, tabs bypassed the gate.** Fixed in section 1: session-level hold before `Tabs`/`TabNew`, `TabSwitch` and `TabClose`; new and adopted pages inherit the hold. The test that allowed a new page to run free was inverted.
2. **Medium, a fast-failing prompt could mask input.** Fixed in section 2: only an answered prompt excuses input, and the after-edge is 250 ms.
3. **Medium, the last check was not right before the send.** Fixed in section 5: a second check inside `dispatch`.
4. **Medium, a failed membership check was cached.** Fixed in section 2: membership now comes from the browser job (`IsProcessInJob`), and only definite answers are cached.
5. **Low, the timer resolution could end the pause early.** Fixed in section 1: a 16 ms margin.
6. **Low, undocumented gap.** Wheel input to an inactive window is now listed in section 7.
7. **Low, the agent could close a held window.** Decided in section 4: `browser_close` is refused during a hold.
8. **Info, features enabled crate-wide.** The scan now covers all of orceld's sources (section 2).

After the re-review of 2632a662 (pass, two lows):

1. **A timed-out prompt counted as answered.** The Windows prompt reported a timeout as a plain denial. `orcel-approval` now returns `Unanswered` for it. The prompt is still denied and recorded as a denial, but its message (`UNANSWERED_DENIAL`) marks it, and orceld treats it as unanswered. Tests cover the approval crate and `prompt_answered`.
2. **A failed membership lookup failed open.** It now fails closed: new input with an unchecked window in front holds the session. Tests cover the feed and the gate.
