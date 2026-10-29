# DeerFlow 2.0 and the Orcel Agent: source audit, transplant matrix and master plan

**Status: PLAN, revision 2 (no capability activated, no code imported).**
This document records the founder-directed investigation of ByteDance
DeerFlow 2.0, made under the directive "DEERFLOW 2.0 FULL COPY-FIRST
RESEARCH, ARCHITECTURE AND ENGINEERING AUTHORIZATION" (2026-10-30; this PR,
#533, is its durable record). It also records the resulting architecture
decision. It grants no authority and changes no SpecGrain state.

- **Donor pin:** `bytedance/deer-flow` at
  `81e1ab8dcc86574cfac0ecdfe3636b775a08c567` (main, 2026-10-30).
- **License:** MIT, "Copyright (c) 2025 Bytedance Ltd. and/or its affiliates;
  Copyright (c) 2025-2026 DeerFlow Authors".
- **Candidate files:** hashed in `deerflow-donor.lock.json`, next to this file.
  The lock pins *representative* entry files per group. Each import milestone
  extends it with that milestone's full copy closure and tests (section B,
  provenance).
- **Orcel base audited:** `main` at `ced44f8b` (refreshed at merge; see
  section H).
- **Independent review:** revision 1 was challenged by an independent
  reviewer (ACCEPT WITH CHANGES, 14 findings). Revision 2 resolves them
  (section I).

## 0. Reconciliation with adopted Orcel decisions

This plan does not replace any adopted decision. It must fit four of them.

1. **`ORCEL_AI_SERVER_ARCHITECTURE.md`** (F7, adopted 2026-10-09).
   - It says: "All Orcel AI model inference, conversations, planning,
     orchestration, routing … run on founder-controlled servers. The local
     app … validates/executes proposals. Core remains usable through
     external supported MCP clients without founder inference. … BYO
     planner … belong[s] only in separately described Core integrations."
   - Proposals must reference device-minted targets and observation
     generations, and a model's "done" is not a receipt.
2. **`AGENT_RUNTIME_INTEGRATION.md`** (adopted 2026-10-18).
   - "Orcel's kernel is not an LLM agent loop. Planners are external MCP
     clients … or the founder-hosted AI service (F7)."
   - Its CR-02 adopts the AgentKit run and step event contract for the
     Control Room.
3. **`ORCEL_COMPUTER_USE_DONOR_MATRIX.md`.**
   - "donor agent loop / model runtime: REJECT_FOR_CORE."
   - Every import names the SpecGrain that authorizes it.
4. **P20** (`ORCEL_P20_UNIVERSAL_AGENT_RUNTIME_PLAN.md`).
   - The "AI / MCP client" layer sits above the edge.
   - SG-000104 plans an optional model loop behind `ComputerActionProposal`.
   - §17: a mutation is not retried after dispatch.

**How the Orcel Agent fits.** The DeerFlow-derived loop is a
*deployment-neutral planner package* that lives outside the kernel. It has
exactly two possible homes:

- **(a) A Core integration.** A local, unprivileged MCP client of the Orcel
  edge, with a local open-weight or scripted model.
  - This is the "separately described Core integration" that F7 allows, and
    this document is its description.
  - It serves the 2026-10-30 directive's local-first, zero-additional-cost
    requirement.
  - It does not change Orcel AI's founder-hosted default.
- **(b) The F7 orchestration service.** The same loop could run on founder
  servers with the founder's models, emitting proposals in the reviewed relay
  vocabulary.
  - Hosting, models and infrastructure remain founder decisions under F7.
  - This plan prepares nothing that requires them.

Either way, the loop is a planner. orceld remains the only authority, and the
kernel stays free of any agent loop.

## A. DeerFlow source audit

### What DeerFlow is

DeerFlow 2.0 is a multi-tenant, server-hosted "super agent" platform, not a
library.

| Part | Contents |
|---|---|
| `backend/packages/harness/deerflow` | The agent runtime: 829 files and about 200,000 lines of Python 3.12 on LangChain 1.3 and LangGraph 1.2 |
| `backend/app` | A FastAPI gateway: auth, CSRF, run manager, SSE, scheduled tasks, durable MCP tasks |
| `backend/app/channels` | Chat bridges: Telegram, Slack, Feishu, WeCom, DingTalk, Discord |
| `frontend` | A Next.js and React workbench: 1,302 files |
| `deploy`, `docker` | Helm and Compose |
| `skills/public` | 23 `SKILL.md` skills |
| Tests | 1,258 backend test files |

### Agent intelligence

- **Assembly.**
  - `agents/factory.py::create_deerflow_agent(model, tools, *, features,
    extra_middleware, checkpointer, ...)` builds a LangGraph agent from
    arguments and reads no config files.
  - `features.sandbox` defaults to **True** (`features.py:30`). Only an
    explicit `False` removes the ThreadData, Uploads and Sandbox middlewares
    and `view_image_tool` (`factory.py:249-259, 366`).
- **Middleware chain (about 60 modules)** around LangChain's `create_agent`:
  - **Loop detection.** A sliding-window hash of tool calls, a warning, then
    a hard stop, with the decision persisted for audit. It special-cases
    DeerFlow tool names (`read_file`, `write_file`, `str_replace`, `bash`,
    `ls`, `glob`, `grep`; `loop_detection_middleware.py:108,182-204`).
  - **Todos.** `todo_middleware.py` *subclasses LangChain's
    `TodoListMiddleware`* (`:26,110`). It adds context-loss reminders and
    premature-exit prevention.
  - **Summarization.** `summarization_middleware.py` *subclasses LangChain's
    `SummarizationMiddleware`* (`:18,122`). It adds pre-compression hooks,
    and `durable_context_middleware.py` projects the summary as data.
  - **Tool-output budget and synopsis.**
  - **Robustness:** tool-error handling, dangling-tool-call repair,
    clarification, finish-reason detectors.
  - **Subagent bounds:** subagent-limit and receipt verification.
- **Subagents.** `subagents/executor.py`, 2,500 lines.
- **Memory.** DeerMem: `agents/memory/**`, about 15,500 lines, with a file
  store, fact extraction and eviction.
- **Skills.** `SKILL.md` frontmatter, parser, validation, install, review,
  and SkillScan (`skills/skillscan/**`).
- **Models.** A LangChain chat-model factory (OpenAI-compatible, vLLM, an
  Ollama extra, hosted providers).

### Execution infrastructure (rejected for Orcel)

- **The local sandbox runs a host shell:** `subprocess.run([shell, "-c",
  ...])`, also PowerShell and cmd (`local_sandbox.py:330`). It has an
  environment scrubber but no OS confinement and no approval broker.
- **Other sandboxes** (AIO, E2B, OpenSandbox, Boxlite, Kubernetes) and
  **bash, file and browser tools**: in Orcel any of these would be a second
  execution path.
- **Multi-tenant concerns:** RBAC, a guardrail veto, the gateway, auth, IM
  channels, the scheduler, Postgres or SQLite persistence and about 65
  config modules all serve a multi-tenant server, not a local single-user
  desktop agent.

### Quality, weaknesses and risks

- **Strengths:**
  - strong tests and written concurrency contracts;
  - offline-reproducible benchmarks;
  - an explicit prompt-trust rule: framework text goes in the system channel,
    untrusted text in a sanitized human or data channel.
- **Dependency mass.** `deerflow-harness` declares as *core* dependencies
  `kubernetes`, `langfuse`, `e2b-code-interpreter`, `tavily-python`,
  `exa-py`, `firecrawl-py`, `duckdb`, `markitdown[all]`, `langgraph-api`,
  `langgraph-cli`, provider SDKs, `sqlalchemy`, `alembic` and more. A
  wholesale install is a large supply-chain and egress surface.
- **Coupling.** Measured by Python `ast` import closure, counting *every*
  import (including function-local and `TYPE_CHECKING`) and excluding
  parent-package `__init__` files.

  | Module | Closure |
  |---|---|
  | `agents/factory.py` | 414 modules, 100,981 lines, reaching Postgres, Redis, SQLAlchemy and Langfuse |
  | Summarization, subagents | about 99,500 lines each |
  | Todo | about 45,000 lines |
  | Memory | about 48,000 lines |
  | Loop detection | 8 modules, 1,525 lines |
  | Dangling-tool-call | 1 module, 525 lines |
  | Clarification | 3 modules, 890 lines |
  | Receipt verification | 4 modules, 836 lines |
  | Tool-output synopsis | 1 module, 651 lines |
  | Skills parser | 5 modules, 585 lines |
  | Skills frontmatter | 1 module, 77 lines |
  | Skills validation | 6 modules, 686 lines |

  The last seven are self-contained, depending on LangChain, LangGraph,
  pydantic and, for skills, `pyyaml`.
- **Risks for Orcel:**
  - the unconfined host-shell sandbox;
  - runtime MCP and skill installation;
  - a private `starlette._utils` import;
  - telemetry clients (Langfuse, Monocle; LangSmith via `langchain-core`);
  - `tiktoken`, which downloads BPE files on first use unless pre-seeded.

## B. Copy-first transplant matrix

Each decision is one of COPY (verbatim, with Orcel tool-name and failure-code
mapping only), ADAPT (copy and decouple or reshape), REUSE (a pinned
dependency), REIMPLEMENT (take the design, not the code), or REJECT.

| # | Capability | DeerFlow source (pin 81e1ab8) | Orcel counterpart today | Decision | Destination | Dependencies | Security notes | Complexity | Testing | Expected benefit |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | Agent loop | `agents/factory.py`, `features.py`, `thread_state.py` | No loop in Orcel; planners are external clients or F7; SG-000104 plans a model loop behind `ComputerActionProposal` | REIMPLEMENT a thin loop on LangChain's `create_agent` with the copied middlewares, rather than decoupling the 101k-line factory | `apps/orcel-agent/orcel_agent/loop/` | `langchain`, `langgraph` (MIT) | Tools come only from the edge; `sandbox` never set | Medium | Fake-model unit tests; BM-02 through the agent | A local planner for Core and BM-02 Tier C3 |
| 2 | Loop detection | `loop_detection_middleware.py` and its closure (8 modules) | None | COPY, then map DeerFlow tool names to Orcel's (`fs_read`, `fs_write`, `fs_edit`, `fs_list`, `fs_find`, `fs_search`, `process_spawn`, UIA tools) | `orcel_agent/middleware/loop_detection.py` | As row 1 | Decisions are logged | Low–Medium | Port `test_loop_detection_middleware.py` (2,492 lines) with Orcel names | Stops runaway loops |
| 3 | Todos | `todo_middleware.py` | Deterministic BM-02 planners | REUSE LangChain `TodoListMiddleware` + COPY DeerFlow's delta (context-loss reminder, premature-exit guard) | `orcel_agent/middleware/todos.py` | As row 1 | None | Low | Ported delta tests | Decomposition that survives compaction |
| 4 | Compaction | `summarization_middleware.py`, `durable_context_middleware.py` | None (orceld's SG-000120 resume summary is task-level, not model context) | REUSE LangChain `SummarizationMiddleware` + ADAPT DeerFlow's hooks and durable projection | `orcel_agent/middleware/compaction.py` | As row 1 | Summaries are untrusted data | Medium | Fake-model token tests | Long tasks on small contexts |
| 5 | Output budget | `tool_output_budget_middleware.py` (ADAPT), `tool_output_synopsis.py` (COPY) | MCP results bounded per tool by orceld | ADAPT: in memory first; externalization only into the agent's private, bounded store (section C, privacy) | `orcel_agent/middleware/output_budget.py` | As row 1 | No writes to user paths | Medium | Oversized-result tests | UIA trees fit context |
| 6 | Error handling and dangling calls | `tool_error_handling_middleware.py`, `dangling_tool_call_middleware.py` (COPY) | orceld typed failures; T-AN-04 resume note | COPY + Orcel failure-code mapping; dangling calls become `outcome_unknown` (section C, resume) | `orcel_agent/middleware/errors.py` | As row 1 | A refusal is final; nothing is ever retried around the broker | Low | Refusal and resume tests | Correct recovery |
| 7 | Clarification | `clarification_middleware.py` (COPY) | Approval prompts are separate | COPY; a question is never consent | `orcel_agent/middleware/clarify.py` | As row 1 | — | Low | Unit | Fewer wrong guesses |
| 8 | Subagents and receipts | `subagents/executor.py` (ADAPT), `receipt_verification.py` (COPY) | None | ADAPT later (M6), single-process | `orcel_agent/subagents/` | As row 1 | Same session, same approvals | High | Bounded-delegation tests | Verified sub-reports |
| 9 | Memory | `agents/memory/**` | None (orceld journals actions, not knowledge) | ADAPT later (M6), off by default, private bounded store | `orcel_agent/memory/` | As row 1 | Untrusted data; retention limits | High | Synthetic offline tests | Durable task memory |
| 10 | Skills | `skills/parser.py`, `frontmatter.py`, `validation.py` (COPY), `skills/skillscan/**` (ADAPT) | None in Orcel | Read-only reviewed catalog; no runtime install | `orcel_agent/skills/` | `pyyaml` | Skills are untrusted instructions | Medium | Parser and scanner tests | Reusable workflows |
| 11 | Planner and model interface | `models/factory.py`, `models/vllm_provider.py` | F7 typed-decision contract | REIMPLEMENT: a provider-neutral `Planner` protocol from M1 (an observation and the tool schemas in; a typed tool-call proposal or finish out), with three adapters: scripted (M1), LangChain chat model (M2), typed-decision (later) | `orcel_agent/planner.py` | stdlib (M1) | Proposals are checked against the edge's schemas before dispatch | Low | Contract tests | Model-independent |
| 12 | Agent run state | LangGraph checkpointers | `orcel-journal`, SG-000120 resume summary | REUSE `langgraph-checkpoint-sqlite` for plan and message state only (M3) | Private agent state dir | `langgraph-checkpoint-sqlite` | orceld's journal is the truth for actions | Low | Kill-and-resume tests | Resumable plans |
| 13 | MCP client | `mcp/`, `langchain-mcp-adapters` | Orcel is the server | M1: a stdlib JSON-RPC client. M2: REUSE `mcp` + `langchain-mcp-adapters` | `orcel_agent/edge.py` | stdlib, then `mcp` | Exactly one server: the Orcel edge | Low | Contract tests | Exact governed tools |
| 14 | Sandboxes | `sandbox/**`, `community/*_sandbox` | orceld providers and hosts | REJECT | — | — | Parallel execution path | — | — | — |
| 15 | Bash, file, browser tools | `tools/builtins`, `community/browser_automation` | orceld `process`, `fs`, browser, UIA | REJECT | — | — | Bypasses the broker | — | — | — |
| 16 | Gateway, auth, channels, scheduler, persistence | `backend/app/**`, `persistence/**` | orceld app API, Control Room, relay | REJECT | — | — | New network surfaces | — | — | — |
| 17 | Frontend | `frontend/**` | Control Room (CR-02 AgentKit events) | REFERENCE only | — | — | No DeerFlow branding | — | — | UX ideas |
| 18 | Telemetry | `tracing/**`; LangSmith | `orcel-audit` | REJECT; LangSmith forced off and tested with egress denied | — | — | Egress | — | — | — |
| 19 | Evaluation conventions | `scripts/benchmark/**` | BM-02 | REIMPLEMENT the conventions in BM-02 | `tests/benchmarks` | — | — | Low | — | Honest evaluation |
| 20 | Run events | `runtime/events` | CR-02 AgentKit event contract (adopted) | The agent emits AgentKit-shaped run and step events, so Control Room needs no second schema | `orcel_agent/events.py` | — | Events never carry approvals | Low | Event-contract tests | One event model |

**Provenance and licensing (every COPY and ADAPT row).**
- Each file keeps a header naming its DeerFlow path and the pin.
- `apps/orcel-agent/third_party/deer-flow/LICENSE` is the verbatim MIT text.
- A per-milestone provenance ledger maps each imported file to its source
  blob and lists the modifications.
- The donor lock gains that milestone's full closure and tests.
- Nothing DeerFlow-branded is user-facing.
- **Dependencies:** a resolved lock with `--require-hashes` and a transitive
  license table in M2. `langchain-core` pulls `langsmith`, and `mcp` pulls an
  HTTP stack. LangSmith tracing is forced off. `tiktoken` is avoided or
  pre-seeded, and tests run with egress denied.
- **Model licenses** are a founder decision (section G).

## C. Target architecture

```text
 Orcel Agent (planner package; unprivileged; DeerFlow-derived middlewares)
   Planner protocol: scripted | LangChain chat model | typed-decision
   loop: observe -> propose tool call -> dispatch through the edge -> record
   middlewares: loop detection, todos, compaction, output budget, errors,
                clarify, [subagents], [memory], [skills]
   state: private agent store (bounded, owner-only, expiring)
   events: AgentKit-shaped run/step events (CR-02)
        |  MCP stdio - the ONLY tool source: the Orcel edge, `core` profile
        v
 Orcel MCP edge -> orceld authority kernel (policy, approval broker,
   leases, journal, audit, protected surfaces, identity) -> providers/hosts
```

- **Authority.**
  - The agent proposes. orceld authorizes, executes and verifies.
  - Approval prompts reach the user through orceld's broker as for any
    client. The agent never sees, mints, caches or relays an approval, a
    lease or a target identity the edge did not give it.
  - A model's "finish" is a claim, never a receipt: completion is judged from
    orceld results and task checkers.
- **Tool surface and leases (fixes the unattended-autonomy risk).**
  - Until a grain qualifies more, the agent connects with the **`core`
    profile only**.
  - It refuses to start when a FullControl, Admin or RemoteFullControl lease
    is active for its session. Under a Full User lease routine operations
    need no fresh approval (P20 §4.2), so an injected instruction could act
    unattended.
  - **A per-run approval-request budget** (default 3). The run stops after
    the first denial. It never re-asks the same operation.
- **Resume invariant (fixes P20 §17 replay risk).**
  - On restart, any tool call the agent proposed whose result it never
    recorded becomes a synthetic `outcome_unknown` result. This is
    DeerFlow's dangling-call role, with Agent-Native's T-AN-04 wording: "do
    not assume they succeeded OR failed".
  - The planner must then *re-observe* through orceld before it can propose
    again. A mutating call is never re-dispatched from agent state.
  - This reconciles with orceld's SG-000120 resume summary, which stays the
    action-side truth.
  - Tested by killing the agent between dispatch and recording.
- **Data trust.** Everything from tools, files, pages, skills, memory and
  summaries is untrusted data in the human or data channel. The system
  prompt is static Orcel text.
- **Privacy of agent state.** The agent store holds model context, which
  includes file and UIA text. It is a new data store, and its review is part
  of the owning grain.
  - It lives in an owner-only directory, with the ACL tested as orceld's
    state is.
  - Size-capped, with a TTL.
  - **Deleted on run completion by default.**
  - No raw screenshots and no secret-like values. orceld already redacts
    passwords.
  - Memory (M6) is opt-in, with its own retention control.
- **Transport.**
  - The agent spawns exactly one child, the edge (`node
    apps/orcel-mcp/dist/index.js` in tests; the installed `orcel mcp stdio`
    after packaging).
  - Later milestones may open one loopback socket to a local model endpoint
    (M4). Nothing else.
  - A source scan enforces both.
- **Cross-platform.** Python 3.12 (Orcel's CI version) on Windows, macOS
  and Linux. Platform differences stay in orceld and the hosts.

## D. Alternatives and trade-offs

1. **Install `deerflow-harness` wholesale.** Rejected.
   - About 200,000 lines.
   - SaaS, server and Kubernetes dependencies.
   - Sandbox, bash and file tools one flag (with a `True` default) away from
     a second execution path.
   - Telemetry.
2. **Transplant the whole platform.** Rejected: it duplicates orceld, Control
   Room and the relay, and adds network surfaces.
3. **Decouple DeerFlow's factory (the plan's revision 1).** Replaced by a
   thin loop on LangChain's `create_agent` plus copied self-contained
   middlewares.
   - The factory closes over 101k lines.
   - The valuable behaviour sits in middlewares, most of them self-contained
     or thin subclasses of LangChain built-ins.
4. **A smaller transplant (loop detection only).** Insufficient: it would not
   give a usable planner. The chosen set is the smallest that does.
5. **Rewrite in Rust or TypeScript.** Rejected for now. Python 3.12 already
   runs in Orcel CI, and the copy-first rule favours proven code.
6. **Put the loop in orceld.** Rejected by `REJECT_FOR_CORE` and the adopted
   runtime model.
7. **Chosen:** a deployment-neutral planner package, Core-integration first,
   with a thin loop, copied self-contained DeerFlow middlewares, LangChain
   built-ins for todos and summarization, a provider-neutral `Planner`
   protocol, and the Orcel edge as its only tool source.

## E. Implementation roadmap

| Milestone | Scope | Gate | Acceptance | Rollback |
|---|---|---|---|---|
| M0 | This plan, the donor lock, an independent review | — | Reviewed and merged | Revert (docs) |
| M1 | `apps/orcel-agent`, standard library only, **no donor code, no new dependencies**: `edge.py` (an MCP stdio client spawning the built edge), `planner.py` (the `Planner` protocol plus a scripted planner), `agent.py` (the loop, a step budget, refusal-is-final, the approval-request budget, `core` profile only, the resume invariant with `outcome_unknown`), `events.py` (AgentKit-shaped events) | None beyond this plan: no import, no authority | (1) the BM-02 Tier A tasks (fs read, list, stat, read_range, find; all exposed by the edge, `fs_mutation.ts:91,101`) are solved through the real edge and a test orceld on Windows, macOS and Linux CI, every call audited. (2) The kill-between-dispatch-and-record test yields `outcome_unknown` and a re-observation. (3) A source scan: one allowlisted spawn (the edge), no shell, no other subprocess or socket, no writes outside the agent's state dir. (4) Not packaged and not referenced by orceld | Remove the app |
| M2 | A pinned dependency set (`langchain`, `langgraph`, `mcp`, `langchain-mcp-adapters`) with a hash-locked resolve, a transitive license table and supply-chain audit; the LangChain planner adapter; COPY loop detection with Orcel tool names | **The owning grain is activated** (section G) | Scripted-model parity with M1; ported loop-detection tests; egress-denied tests; LangSmith off | Revert the dependencies |
| M3 | Todos and compaction (built-ins plus DeerFlow deltas), output budget, errors, clarification, LangGraph SQLite checkpoints | M2 | Ported tests; long-task tests; resume invariant kept | Revert |
| M4 | Local-model evaluation on CI (a pinned open-weight model on a disposable runner, llama.cpp, labelled "autonomous, local model") | M3 plus founder decision 2 (model and license) | The section F report | Drop the job |
| M5 | Ablations and the harder BM-02 tasks (section F) | M4 | Reported with confidence intervals | — |
| M6 | Subagents and receipts; memory and skills, read-only and off by default | M3 | Ported tests; privacy and retention tests | Revert |
| M7 | Packaging and Control Room integration | Grain qualification plus founder decision 1 | Release qualification, SBOM | Do not ship |

**M1 is the first executable slice.** It imports no donor code and adds no
dependency. It is an MCP client of the existing edge, like any external
client, so it needs no grain. Every later milestone that imports donor code
or dependencies (M2 and on) waits for the owning grain.

## F. Benchmark plan

- **Baselines.** BM-02 Tier A (20 read-only tasks) and Tier B (21 mutating
  tasks, scripted SOFT consent, labelled) through orceld, unchanged.
- **Row labels:**
  - `deterministic-scripted`: the agent loop replaying the existing plans.
    Measures harness overhead and regressions only.
  - `autonomous-local-model`;
  - `autonomous-hosted-model`: optional and founder-funded, never default.
- **Approvals.** Scripted SOFT consent stays labelled. Real STRONG presence
  is founder-present only. No row claims a real user approval that did not
  happen.
- **Tasks that exercise the middlewares** (new, synthetic, labelled):
  - loop traps (a tool result that invites repetition);
  - long context (many files, forcing compaction);
  - oversized output (large directory listings and UIA trees);
  - injected instructions inside files (must not change the plan or widen
    calls);
  - forced kill and resume.
- **Ablations** with the same model, prompt and seed: a minimal loop, then
  each middleware added in turn. This isolates each middleware's effect;
  comparing against an oracle does not.
- **Metrics:**
  - success with confidence intervals over task variants;
  - Orcel calls and refusals;
  - approval requests;
  - tokens;
  - p50 and p95 step and task time;
  - the agent's peak RSS;
  - loop and compaction events;
  - resume outcomes.
- **Reproducibility:**
  - pinned weights (SHA-256), prompts and config;
  - temperature 0 and a fixed seed, noting that CPU llama.cpp is not
    bit-deterministic across runners, which is why variants and confidence
    intervals are reported;
  - the report records the Orcel commit, donor pin, model hash and config;
  - no download in the default developer workflow.

## G. Risks and governance

- **Owning grain: "Orcel Agent: Core-integration planner (DeerFlow-derived
  MCP client)".**
  - **Scope:** M2–M6 imports and dependencies, the agent's private data
    store, and the `core`-only, no-lease, approval-budget rules.
  - **Authority delta:** none in orceld, hosts, approvals or leases. New: a
    first-party client, a dependency set and an agent data store.
  - **Activation is a founder decision.** The packet is to be prepared as
    `prep/SG-ORCEL-AGENT.md` with category A/B conditions, on the SG-000115
    pattern.
  - Until it is activated: only M0–M1 proceed. Dependency admission (M2),
    model download and CI inference (M4) are category B.
- **Canonical clarification,** reviewed with the grain. The donor matrix's
  `REJECT_FOR_CORE` stays. A donor-derived planner may run only as an
  unprivileged client above the edge (Core integration) or as F7
  orchestration.
- **Founder decisions** (recorded; M0–M1 proceed meanwhile):
  1. Activate the owning grain (M2+) and later qualify packaging (M7).
  2. The local model for M4, its license, and how users obtain it (Orcel
     never ships or downloads weights silently).
  3. Whether the Core-integration agent ships beside F7's founder-hosted
     Orcel AI, and whether a hosted provider may be an opt-in for it.
  4. Runtime skill installation. The default is no: a read-only, reviewed
     catalog.
- **Dependency risk.** LangChain and LangGraph change often. Pin by hash,
  audit in CI, keep telemetry off, and rely on pure rollback: the agent sits
  above the edge.
- **Model risk.**
  - Small local models may plan poorly. The scripted path always remains,
    and claims follow the data only.
  - This development PC (16 GB RAM, no discrete GPU) has no model installed,
    and this work installs none. Evaluation uses disposable CI runners.
- **Coordination.** SG-000115 (browser host) and SG-000128 (UIA) touch
  `crates/`. The agent lives in `apps/orcel-agent` and `tests/benchmarks`,
  so nothing overlaps.

## H. Execution checkpoint

- `main` is at `be95e31f` (SG-000115 A1–A3 merged; A4 #531 and A5 #532
  open). Refresh at merge.
- The donor is pinned at `81e1ab8`, and `deerflow-donor.lock.json` covers 22
  representative files.
- **Next action:** M1 on a new branch:
  - `apps/orcel-agent/orcel_agent/{edge,planner,agent,events}.py`;
  - unit tests with a fake edge;
  - a CI step running BM-02 Tier A through the agent, the built edge and a
    test orceld;
  - the kill-and-resume test;
  - the source scan.

## I. Independent review (revision 1) and resolution

| # | Finding | Resolution |
|---|---|---|
| 1 | Conflicts with F7 and the adopted runtime model, uncited | Section 0: the agent is a Core integration (as F7 allows), deployment-neutral toward F7; founder decision 3 |
| 2 | Imports without an owning grain; the SG-000115 pattern overstated; inconsistent ranges | Section G: an owning grain gates M2+; only M0–M1 proceed; ranges made consistent |
| 3 | M1 acceptance unrealistic | Partly incorrect: `fs_read_range` and `fs_find` *are* exposed by the edge (`apps/orcel-mcp/src/fs_mutation.ts:91,101`, registered at `server.ts:526`). Accepted: M1 spawns the built edge, not `orcel mcp stdio`; the scan narrowed to one allowlisted spawn; M4's loopback socket noted |
| 4 | Crash resume could replay a mutation | Section C, resume invariant, tested in M1 |
| 5 | Unattended action under Full User | Section C: `core` profile, refuse under leases, approval budget |
| 6 | Agent state escapes privacy bounds | Section C: privacy rules; reviewed with the grain |
| 7 | SG-000104, F7 and AgentKit overlap | Section 0; rows 1 and 20 |
| 8 | A smaller transplant suffices; coupling overstated | Section A table; rows 1–7 and 10 reworked (thin loop, built-ins plus deltas, COPY clean modules); alternative 3 |
| 9 | Model interface not portable | Row 11: a `Planner` protocol from M1 with three adapters |
| 10 | Benchmarks would not show improvement | Section F: harder tasks, ablations, confidence intervals, a determinism caveat |
| 11 | Dependency and licensing incomplete | Section B provenance: hash lock, license table, LangSmith off, tiktoken, egress-denied tests; model licenses are decision 2 |
| 12 | The lock does not pin what is copied | The lock is marked representative; per-milestone closures and tests are added |
| 13 | Loop detection uses DeerFlow tool names | Row 2: mapping and ported tests |
| 14 | Stale snapshot | Section H refreshed; refreshed again at merge |
