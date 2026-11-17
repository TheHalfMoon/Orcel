# W2-02: Agent S orchestration primitives in the Orcel Agent

Status: **INTEGRATED, TESTED (synthetic)** on branch `w2/agent-s-planner`.
Not qualified against a real desktop: every task ran against a fake orceld
tool layer with a scripted model.

- **Donor:** `simular-ai/Agent-S` at
  `0fff0e634869dab72027435b4586e62300185d41`, read-only clone at
  `D:\Orcel-REA-W2\Agent-S`.
- **Licence (recorded, not judged):** Apache-2.0 at the root. `agent_s4/`
  carries its own Apache-2.0 LICENSE.
  `osworld_setup/s4/agent_harness/prime-agent-runtime/` is MIT (Mario
  Zechner, Prime Intellect) and is not used.
- **Notices:** the repository has no NOTICE file at this commit, so there is
  no NOTICE content to carry.
- **Authorization:** OWNER-ASSERTED AUTHORIZATION, founder 2026-11-17
  (`docs/orcel/grants/2026-11-17-founder-attestation.md`).
- **Records:** `docs/orcel/agent_s_provenance.json` and
  `docs/orcel/notices/agent-s-Apache-2.0.txt`.

## Binding architecture

- orceld is the only authority. The orchestrator is a `Planner`: it proposes
  one tool call or a finish at a time.
- The existing Agent gate (`orcel_agent/agent.py`) checks every proposal:
  - the allowlist and the schema;
  - refusals are final;
  - the step and approval budgets;
  - the resume invariant.
- orceld then authorizes, prompts for approval, executes and audits each
  call.
- There is no second runtime and no direct execution, and the orchestrator
  makes no network call.
- The model is any caller-supplied object with `complete(role, messages)`.
  This packet ships no provider client and no default model, so a paid
  provider can only be used opt-in, with the caller's own key (BYOK).

## Step 1: map

### What the Orcel Agent already had

| Area | Orcel module | Notes |
|---|---|---|
| Loop and gate | `agent.py` | Observe, propose, dispatch through the edge. Allowlist, fail-closed classes, final refusals, approval and step budgets, resume invariant. |
| Planner contract | `planner.py` | `Planner.propose(goal, steps, tools) -> ToolCall or Finish`. A Finish is a claim, never a receipt. |
| Chat-model planner | `chat_planner.py` | M2 LangChain adapter, read-only tools only. |
| Tool calls | `edge.py` | One MCP stdio connection to the Orcel edge. |
| Memory | `todos.py`, `compaction.py`, `checkpoint.py` | Todos, context compaction and a durable checkpoint, all from SG-000129. |
| Recovery | `failures.py`, `journal.py`, `loop_detection.py` | Typed refusal guidance, unknown outcomes and loop caps. |

What was missing:

- task decomposition (a plan as a dependency graph of subtasks);
- a subtask state machine with re-planning after failure;
- per-step reflection;
- recovery from windows that appear unexpectedly;
- a completion rule stronger than "the model said so".

### Agent S inventory and decisions

| Agent S source | What it does | Decision |
|---|---|---|
| `gui_agents/s2/utils/common_utils.py` `Node`, `Dag`, `parse_dag` | Plan graph types and tolerant JSON extraction | **COPY/ADAPT** into `task_graph.py` (dataclasses, bounds, None on failure) |
| `gui_agents/s2/agents/manager.py` `_topological_sort`, `format_subtask_list`, planner messages | Plan, translate to a DAG, sort | **ADAPT** into `task_graph.py` and `orchestrator.py` (refuse cycles, unknown edges and duplicates) |
| `gui_agents/s2/memory/procedural_memory.py` `COMBINED_MANAGER_PROMPT`, `DAG_TRANSLATOR_PROMPT` | Manager and translator prompts | **ADAPT** (renamed for Orcel) |
| `gui_agents/s2/agents/agent_s.py` `AgentS2.predict` | Subtask state machine: FAIL re-plans, DONE records and re-plans | **ADAPT** into `TaskOrchestrator`; the "empty plan means done" exit becomes a completion claim to verify |
| `gui_agents/s3/agents/worker.py` `_generate_reflection`, `flush_messages` | Reflection on each step; bounded trajectory | **ADAPT**; reflection cases are labelled; Case 3 is advisory |
| `gui_agents/s3/memory/procedural_memory.py` `REFLECTION_ON_TRAJECTORY`, `FORMATTING_FEEDBACK_PROMPT` | Reflection and formatting feedback prompts | **ADAPT** (code-agent text dropped) / **COPY** verbatim |
| `gui_agents/s3/utils/common_utils.py` `call_llm_safe`, `call_llm_formatted`, `parse_code_from_string` | Retries and format-checked re-prompting | **ADAPT** (no sleep, no printing, None after three bad replies) |
| `gui_agents/s3/utils/formatters.py` single-action and valid-code checks | Re-prompt on a malformed action | **ADAPT** to one JSON tool call checked against the tool's schema |
| `gui_agents/s3/bbon/comparative_judge.py`, `behavior_narrator.py` | Vision-model judging of best-of-N trajectories | **SKIP** as code. Design reference for `verification.py`. A model judge may later be an opt-in second opinion, never the gate |
| `gui_agents/s3/agents/grounding.py`, `gui_agents/s2/agents/grounding.py` (ACI) | Text-to-coordinate grounding with a grounding model; generates pyautogui code | **SKIP.** Orcel targets UIA elements by typed id and generation. A grounding model is opt-in only and belongs behind orceld's vision path |
| pyautogui code generation and `eval` (`create_pyautogui_code`) | Direct desktop execution | **NEVER.** All actions go through orceld tools and approvals |
| `gui_agents/s3/agents/code_agent.py` | Runs Python and Bash in the environment | **SKIP.** Out of scope; any process action is an orceld tool with its own approval |
| `gui_agents/s2/core/knowledge.py`, narrative and episodic memory | Embeddings, web search, cross-run memory files | **SKIP.** These need network or embeddings and write files outside the run store. Revisit as opt-in, local-only memory |
| `gui_agents/*/core/engine.py`, `mllm.py` | Provider clients (OpenAI, Anthropic, Gemini, and others) | **SKIP.** The agent's source boundary denies provider SDKs. Providers stay BYOK behind the caller-supplied model |
| `gui_agents/*/cli_app.py` | Local CLI with an osascript permission dialog | **SKIP.** orceld owns approvals |
| `agent_s4/` (evolution harness, AWS VMs, tournaments) | Research harness | **SKIP** for the runtime. It is a benchmark reference only (W2-08) |

### What Orcel added (not in Agent S)

1. **An observation after every action.** The orchestrator calls
   `desktop_window_list` after every non-read action. Agent S's WAIT, which
   slept, also becomes a fresh observation.
2. **Unexpected-dialog recovery** (`verification.py`). A dialog-class window
   (`#32770` and similar) counts as unexpected when two things hold: it was
   absent from the first observation, and its title matches no
   `expected_windows` pattern. Recovery then works like this:
   - The orchestrator reads the dialog's own UIA tree.
   - It asks the model, under the `recovery` role, for one dismiss action.
   - It accepts only closing that exact window and generation, or invoking a
     Cancel, Close, No, Not now, Dismiss, Skip or Later element of that
     dialog. OK, Yes, Allow and Install are refused.
   - If no safe action comes back, it falls back to
     `desktop_window_action close`.
   - It allows at most 2 attempts per dialog. After that the run stops with
     `dialog_unrecovered`.
   - Every recovery action is an orceld call with approval, like any other.
3. **Completion verification that refuses unverified claims.**
   - All of these are only claims:
     - a worker's DONE;
     - a plan with nothing left;
     - a reflection's Case 3.
   - A run finishes clean only when every caller-supplied `SuccessCheck`
     passes. A check is a read-only orceld call, dispatched after the last
     action, with a trusted predicate over its real result.
   - A failed check rejects the claim. The orchestrator re-plans from a
     fresh observation, and a second rejection stops the run with
     `unverified_completion`.
   - With no checks at all, a finish always carries
     `completion_unverified`.
4. **Bounds.** Each of these has a limit:
   - re-plans;
   - steps per subtask;
   - rejected claims;
   - dialog attempts;
   - format retries;
   - state transitions per proposal.
5. **An opt-in gate change in `agent.py`.** The new `observation_tools`
   field may only contain `desktop_window_list` and `desktop_window_tree`,
   which are `DESKTOP_OBSERVE_TOOLS`. Their contract approval is `none`, with
   effect `desktop_observe` in `apps/orcel-mcp/src/tool_contract.ts`.
   - When a caller opts in, the agent counts them as read-only.
   - Otherwise they stay fail-closed as mutating.
   - Anything wider stops the run with `observation-tools-too-wide`.
   - `READ_ONLY_TOOLS` and the chat agent's read-only gate are unchanged.

## Step 2: donor unit tests

- `tests/test_providers.py` (the only test under `gui_agents`'s `tests/`):
  **5 run, 5 passed.**
  - Python 3.12.13 venv outside the repository, holding only `openai`,
    `anthropic`, `backoff` and `numpy`: 144 MB, deleted afterwards.
  - No API keys, no network calls and no model download.
  - The run used `-B`, and the donor tree was clean afterwards
    (`git status` empty).
- `osworld_setup/s4/tests/` (34 files): **NOT RUN.** They test the
  `agent_s4` evolution harness (VMs, tournaments, cloud evaluation), which is
  not part of what was transplanted.

## Step 3: what was copied

| Orcel file | From (at the pin) | Decision |
|---|---|---|
| `apps/orcel-agent/orcel_agent/task_graph.py` | s2 `common_utils.py`, `manager.py`, `procedural_memory.py` | ADAPT |
| `apps/orcel-agent/orcel_agent/orchestrator.py` | s2 `agent_s.py`, `manager.py`, `procedural_memory.py`, `common_utils.py`; s3 `worker.py`, `common_utils.py`, `formatters.py`, `procedural_memory.py` | ADAPT |
| `apps/orcel-agent/orcel_agent/verification.py` | none (design reference: s3 `bbon/comparative_judge.py`) | Orcel-original |
| `apps/orcel-agent/orcel_agent/agent.py` | none | Orcel change (opt-in `observation_tools`) |

Renamed to Orcel. Removed:

- telemetry and logging;
- cost and token accounting;
- model names and provider clients;
- sleeps;
- cloud and knowledge-base code.

Every adapted module names its sources and the pin in its header.
`tests/test_orchestrator.py` checks this in both directions.

## Step 4: tests

`apps/orcel-agent/tests/test_orchestrator.py` holds 21 tests. Ten of them are
the deterministic synthetic multi-window tasks. Each one runs the real
`Agent` gate with a `FakeDesktop`, a scripted orceld tool layer that has:

- typed windows with generations;
- UIA-like elements;
- a modal-dialog block;
- hooks.

A `ScriptedModel` drives each task, and each task asserts what orceld was
asked to do:

1. Two windows, success; a cyclic plan graph is fed back and repaired.
2. Copy a value between windows after a read. The worker sees the real
   result, labelled untrusted.
3. An expected Save As dialog is used, not dismissed.
4. An unexpected update dialog: the model dismisses it with Later, and the
   task completes.
5. An unsafe recovery (Allow) is refused; the fallback close is used.
6. A dialog that will not close: the run stops with `dialog_unrecovered`,
   and no work continues behind it.
7. A refused action fails the subtask; the re-plan succeeds.
8. DONE without acting (hallucinated success) is rejected twice; the run
   stops with `unverified_completion` and no mutation was dispatched.
9. A reflection saying "Case 3, completed" does not make it so; the run
   stops with `unverified_completion`.
10. No success checks: the finish carries `completion_unverified`, never a
    clean finish.

The other 11 tests cover:

- the task-graph primitives;
- the action parser;
- formatted retries;
- the recovery safety matrix;
- dialog detection;
- read-only checks;
- trajectory flushing;
- the `observation_tools` gate;
- the provenance record.

Results, Windows 11, Python 3.12.13:

- **Stdlib only:** `test_agent`, `test_chat_planner`, `test_checkpoint`,
  `test_compaction`, `test_dependencies`, `test_failures`,
  `test_loop_detection`, `test_output_budget`, `test_restart`, `test_todos`
  and `test_orchestrator` ran 248 tests: 0 failures, 0 errors, 91 skipped
  (the locked dependency environment).
- **Locked environment** (`ORCEL_AGENT_DEPS=1`, hash-locked wheels, 55 MB
  venv outside the repo, deleted afterwards): 248 run, 0 failures, 0
  errors, 12 skipped. The skips are Unix-only, macOS-only and Linux
  seccomp/netns tests.
- **Store location:** the store's ancestor rule refuses this host's
  `%TEMP%`, which grants another account DELETE. The suites therefore ran
  with `TMP`/`TEMP` set to `C:\Users\Shehr\oatmp`. The same refusal makes
  the existing suites error under the default `%TEMP%` on this host before
  this change, so it is not caused by it.

## Gaps

- **Synthetic only.** Nothing has run against real orceld or real windows.
  The next step is the AgentKit or benchmark harness (W2-08), on a test
  orceld with a Full User lease.
- **No provider adapter in this packet.** A LangChain chat model (M2) can be
  wrapped as a `DecisionModel` in a later slice. Its prompts would then
  carry untrusted window text, so the planner-side injection tests of
  SG-000129 slice 6 should be extended to this path.
- **No resume support.** The orchestrator does not resume mid-task: it
  restarts its own state, while the Agent's journal still prevents
  replaying an unknown or completed mutation. It is not wired into
  `checkpoint.py`.
- **Dialog detection is class-based** (Win32 dialog classes) plus a
  baseline. macOS (AX sheets and dialogs) needs its own rule when the macOS
  desktop tools land.
- **Success checks come from the caller.** There is no general task
  checker; tasks without checks never finish clean, by design.

## Grain amendment needed

Yes, a small one. SG-000129 (or its successor grain for the agent runtime)
should record two decisions:

1. The opt-in `observation_tools` field on `Agent`, admitting only
   `desktop_window_list` and `desktop_window_tree`, the contract
   approval-`none` desktop observation tools, as read-only.
2. The new planner path (`TaskOrchestrator`), which may propose mutating
   desktop tools. Under M1, only `entry.chat_agent` existed, and it is
   read-only.

The agent source-boundary scan needs no change: the new modules import only
admitted standard-library modules.
