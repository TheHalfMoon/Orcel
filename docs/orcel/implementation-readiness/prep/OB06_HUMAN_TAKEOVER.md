# OB-06: human takeover and the 3000 ms quiet timer

**Status: implemented on `browser/ob06-takeover` (SG-000135 work packet OB-06, acceptance FA-G). Not merged. Unit and Windows probe tests only; the founder-present run has not happened, and no real takeover was driven on a headed window.**

Founder requirement: when a person takes over the browser, the agent pauses at once, and it resumes only 3 seconds after the person's LAST input. Then it observes the page again, and the person's edits win. Shadow Mode uses no OS input, focus or clipboard.

The state machine itself is B1 (`crates/orcel-browser-session`, PR #802): `RUNNING -> HUMAN_OVERRIDE -> QUIET -> REOBSERVE -> REPLAN -> RUNNING`. OB-07 turned its gate on for every `browser_full` broker session. Until this packet, nothing fed it a person's input. OB-06 adds that source for Visible sessions, a contract code for the refusal, and the prompt and in-flight rules.

## 1. What happens

```
person types or clicks while a Visible session's own window is in front
  -> human_input.rs reads it (25 ms poll, and again before every gate decision):
       GetLastInputInfo moved, and GetForegroundWindow's process descends from this session's browser host
  -> takeover gate: every page of the session -> HUMAN_OVERRIDE, dated when the input happened
agent action on the session (read or write)
  -> refused HUMAN_TAKEOVER ("browser session paused: human_override ..."), before any approval prompt
3000 ms after the last input (monotonic clock; each input restarts the count)
  -> REOBSERVE: a write is refused TARGET_STALE (reobserve_required) until a fresh browser_snapshot
  -> after the snapshot, writes planned on it go on (REPLAN -> RUNNING)
```

- **Every page of the session is held.** The operating system says that input reached the window, not which tab. The safe side is to hold all of the session's pages. Other sessions are not held: a person in session A's window never pauses session B.
- **Exactly 3000 ms.** The quiet period is B1's `QUIET_MS` and ends when `now - last_input >= 3000`, on the gate's monotonic clock (`SystemClock`, an `Instant`). The source dates each input when it happened (the OS reports its age), not when orceld noticed it, so a late reading never stretches the pause. The tests check 2999 ms (held) and 3000 ms (released).
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

- **When.** `GetLastInputInfo` gives the tick of the session's last keyboard or mouse input; `GetTickCount` turns it into an age. No key, character, position or window is in it.
- **Where.** `GetForegroundWindow`, then `GetWindowThreadProcessId`. The window counts as the session's when its process is the session's browser host or a descendant of it. The descent is checked with a process snapshot (`CreateToolhelp32Snapshot`). Each parent must have been created no later than its child, so a reused pid never makes a stranger a parent. The chain must end at the host's own pid and creation time, the same identity `LiveBrowser` already writes into every intent. The verdict is cached per window and process.
- **The rule.** A reading counts as a person's input when the last-input tick changed since the previous reading and the session's window is in front. The first reading is a baseline, so input from before the session watched never counts.
- **When it is read.** A thread reads it every 25 ms (`POLL_MS`). The gate reads it again right before every decision: read, write, dispatch, the end of a write, a page opening and a status read. A decision therefore never misses input the OS already recorded while the window is in front.
- **Fail closed.** If `GetLastInputInfo` fails, the reading counts as a person's input now, so the agent waits. A Visible session for which no source can be started is not launched (`PROVIDER_UNAVAILABLE`); the worker is shut down.
- **Orcel's own approval prompt.** The click or key that answers an Orcel prompt can reach the browser window once the prompt closes. `LiveBrowser` tells the gate when a prompt opens and closes (`request_token`). Input within 500 ms before or 1000 ms after the prompt closed is not counted. Input during the prompt with the browser in front still counts, so a person who takes the page over while the prompt is up stops the send.
- **Orcel's own input is not a person's.** The agent's page input is CDP `Input.dispatch*Event` over the engine's debugging pipe. Chromium delivers it to the renderer directly, never through the OS input queue, so it does not move the last-input tick. This is how Chromium's input domain works. It was not measured on this PC, because that needs a headed window on the developer's desktop (section 6). If it ever did not hold, the agent would pause itself for three seconds after its own input. That costs time; it never lets the agent act under a person's hand.
- **Nothing on the desktop changes.** `tests/ob04_shadow_scan.rs` now also scans `human_input.rs` for foreground, activation, input-injection, cursor and clipboard calls. orceld's `windows-sys` gains read-only features (`Win32_UI_Input_KeyboardAndMouse`, `Win32_UI_WindowsAndMessaging`, `Win32_System_SystemInformation`, `Win32_System_Diagnostics_ToolHelp`). The host crate still cannot compile those calls.
- **Shadow sessions** have no window, so no source is started and no person's input can reach them (`takeover_input: "none"` in the status). Only an explicit control could hold one (section 4).
- **Other operating systems** have no source yet (`for_host` answers `None`). The live browser is Windows-only today, so no Visible session runs there. macOS needs its own source: the `CGEventSourceSecondsSinceLastEventType` idle time and the frontmost application's pid are the analogue, in a later packet.

## 3. Contract

- **New failure code `HUMAN_TAKEOVER`** (HTTP 409), appended to `FailureCode` as `HUMAN_VERIFICATION_REQUIRED` was in #810. The schemas are regenerated, the wire spelling and index are frozen in `crates/orcel-contracts/tests/contracts.rs`, and orceld's legacy code-name maps are updated. B1's `HumanOverride` and `Quiet` refusals now map to it; their message still starts `browser session paused:`. `Paused` (an explicit pause), the stale reasons and `Cancelled` keep `TARGET_STALE`.
- **orcel-agent.** `HUMAN_TAKEOVER` joins `AWAIT_PERSON`: the refusal is not final, but the agent owes a fresh observation before any mutation. Its guidance says nothing was done, a person is using the window, wait about three seconds after their last input, then observe again. It never says approve, grant, lease or try again.
- **MCP and docs.** The `browser_task_status` description and `docs/p16/TOOL_CONTRACT.md` (and its generator) describe the takeover. The status reply gains `takeover_input` (`visible_window` or `none`). No tool was added or removed.
- **Receipts.** A refused action's receipt has outcome `refused` and failure code `HUMAN_TAKEOVER`.

## 4. Explicit controls and emergency stop

The grain's scope lists `browser_pause`, `browser_takeover` and `browser_resume`. No MCP tool for them is added here:

- An agent-callable resume could end a person's hold, and an agent-callable takeover is not a person taking over.
- The founder's Take Over, Pause and Return to Shadow are the person's controls in the Orcel UI, which the Design session owns. Approvals stay with Windows dialogs.
- B1's gate already has the operations: `take_over`, `return_control`, `pause`, `resume` and `cancel`, reachable through `TakeoverGate::session_gate`. They wait for that UI's control path. `browser_full.test.ts` still checks that no tool is named after takeover.

Emergency stop is unchanged and does not go through the gate. A moved approval epoch ends every session before any session or gate is touched, and `end_all` shuts every worker down. A held page is closed like any other; the test `ob06_a_held_session_can_still_be_stopped_and_closed` covers cancel and close during a takeover.

## 5. An action in flight when the person acts

- **The last check is immediate.** The gate's last check is right before the frame is sent (`before_dispatch`, after the approval prompt or the lease check). It re-reads the OS first, so a person who acted during the prompt stops the send.
- **A sent frame runs to its end.** A frame already sent to the engine is not recalled: an action cut off halfway is worse than one that finished. Its outcome is recorded as usual.
- **Input during the flight supersedes the action.** The gate reads the OS again when the write ends (`after_write`, before `finish_write`). Input during the flight starts a new intervention, so the write is settled as superseded. The next action is refused with `HUMAN_TAKEOVER`. After the quiet period, nothing planned before the person acted is sent until the page was observed again. A consequential write whose outcome is unknown stays uncertain and is never admitted again until reconciled (B1 idempotency guard, unchanged).
- **Full Access (OB-08).** A takeover refusal of a write ends the session's Full Access lease (the existing OB-08 rule: "a person interrupted this browser session"). In a Visible session, a person's input on the window therefore stops lease-covered actions for that session until the owner issues a new lease. That is OB-08's decision, kept as is.

## 6. Tests

- **B1** (`crates/orcel-browser-session/tests/transitions.rs`): an event reported late counts its quiet from when it happened, exactly 3000 ms; a future instant is taken as now; an unowned resource is ignored.
- **Input source** (`human_input.rs`):
  - The first reading is a baseline. Only a new input with the session's window in front counts, dated by its age, and the latest wins.
  - An unreadable OS counts as input now.
  - The answer to an Orcel prompt is not counted; input during the prompt is.
  - The monitor reads before handing input over.
  - A polling monitor's thread stops on drop.
  - No source exists off Windows.
- **Input source, Windows, read-only:**
  - A child process descends from its parent and not the other way round, and another creation time is another process (a `cmd /C ping` child, no window).
  - The real probe reads the last input and the window in front, and changes nothing.
  - No test moves the mouse, sends input or touches the clipboard.
- **Gate with a scripted OS** (`takeover_gate.rs`, `ob06_tests`):
  - The first input pauses reads and writes; held at 2999 ms, released at 3000 ms into `REOBSERVE`; a write is stale until a fresh observation.
  - Every input restarts the count.
  - A late reading counts from the input's own time.
  - Input in another window, and the agent's own actions, hold nothing.
  - Input during an action in flight supersedes it and holds the next action.
  - A takeover during the prompt stops the send; the click that answers a prompt does not.
  - Two sessions are independent, and Shadow has no source.
  - A held session can still be cancelled and closed.
  - An unreadable OS holds the agent.
  - Input before a page opened holds only the pages that existed.
- **Contracts, agent, MCP:** the frozen spelling, index and HTTP status; `AWAIT_PERSON` and the guidance; the status description.

## 7. Not done, and limits

- **Founder G as written.** The founder-present run (a person edits a Visible session's page, and the agent waits for three quiet seconds, re-observes and keeps the edits) has not run. No test here sends real input. That would need `SendInput` on the developer's PC, which is not allowed. CI has no Visible-session harness.
- **CDP input not measured.** The claim that the agent's CDP input does not move `GetLastInputInfo` rests on how Chromium's input domain works. It is not measured. The founder-present run should record it: a Visible session that only acts, with no one at the PC, must never report `HUMAN_OVERRIDE`.
- **Which tab is not known.** The whole session is held.
- **Very short input missed after a window switch.** Input that reaches the window less than one poll (25 ms) before the person switches away from it can be missed. Input while the window stays in front is never missed, because the source is read again before every decision.
- **The prompt edge.** Input within 500 ms before or 1000 ms after an Orcel prompt closes is not counted, whatever window it reached. Input that goes on past that edge is counted.
- **A press held still.** A mouse button held down without moving produces no new input, so the quiet period can end during such a press. The B1 begin and end brackets for ongoing input have no source here. A key held down auto-repeats and does count.
- **Process chain.** A window counts only when its process descends from the session's host through living processes. If an intermediate process had exited, the window would not count (a missed takeover). The worker runtime between the host and the engine lives as long as the session, and the engine's own child windows (dialogs) count as the session's.
- **Other software.** Input another program injects while the session's window is in front counts as a person's (the safe side).
- **A locked or disconnected desktop** has no window in front, so nothing counts.
- **Shadow take-over.** Taking over a Shadow session needs the UI's Take Over control (which would move the task to a Visible window). It is not built.
- **macOS and Linux:** no source (section 2).
- **Review.** OB-06 is on the grain's list of packets that need a fresh-context security judge. d1-local is advisory only.
