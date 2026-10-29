# DeerFlow 2.0 and the Orcel Agent: source audit, transplant matrix and master plan

**Status: PLAN (no capability activated).** This document records the
founder-directed investigation of ByteDance DeerFlow 2.0 (founder directive
"DEERFLOW 2.0 FULL COPY-FIRST RESEARCH, ARCHITECTURE AND ENGINEERING
AUTHORIZATION", 2026-10-30) and the resulting Orcel architecture decision. It
grants no authority and changes no SpecGrain state. Shipping an agent runtime
in an Orcel release is a new product surface, gated by the grain proposed in
section G.

- **Donor pin:** `bytedance/deer-flow` at
  `81e1ab8dcc86574cfac0ecdfe3636b775a08c567` (main, 2026-10-30).
- **License:** MIT, "Copyright (c) 2025 Bytedance Ltd. and/or its affiliates;
  Copyright (c) 2025-2026 DeerFlow Authors".
- **Candidate files:** hashed in `deerflow-donor.lock.json`, next to this
  file.
- **Orcel base audited:** `main` at `ced44f8b2b5ba335dbb98e0d367f95d3e1258e7e`.

## A. DeerFlow source audit

### What DeerFlow is

DeerFlow 2.0 is a multi-tenant, server-hosted "super agent" platform, not a
library.

| Part | Contents |
|---|---|
| `backend/packages/harness/deerflow` | The agent runtime: about 830 files and about 200,000 lines of Python 3.12 on LangChain 1.3 and LangGraph 1.2 |
| `backend/app` | A FastAPI gateway: auth, CSRF, run manager, SSE streaming, scheduled tasks, durable MCP tasks |
| `backend/app/channels` | Chat bridges: Telegram, Slack, Feishu, WeCom, DingTalk, Discord |
| `frontend` | A Next.js and React web workbench: about 1,300 files |
| `deploy`, `docker` | Helm charts and Compose for Kubernetes or container sandboxes |
| `skills/public` | 23 `SKILL.md` skills, mostly content and web generation |
| Tests | 1,258 backend test files and several CI workflows |

Measured by source reading (`ast` import-closure analysis) and by reading the
modules named below.

### Agent intelligence (the valuable part)

- **Assembly.**
  - `agents/factory.py::create_deerflow_agent(model, tools, *, features,
    extra_middleware, checkpointer, ...)` builds a LangGraph agent from plain
    arguments. It reads no config files, so it is the natural seam for
    embedding.
  - `features.sandbox=False` removes DeerFlow's sandbox, thread-data and
    upload middlewares entirely.
- **Middleware chain (about 60 modules).** The lead agent is LangChain's
  `create_agent` loop wrapped in ordered middlewares. The ones worth taking:
  - **Loop detection** (`loop_detection_middleware.py`, 1,000 lines): it hashes
    tool calls in a sliding window, injects a "wrap up" warning, then
    hard-stops, and persists the decision for audit. Its import closure is
    self-contained: 8 modules, 1,525 lines, depending only on LangChain,
    LangGraph and pydantic.
  - **Planning** (`todo_middleware.py`, 452 lines): a `write_todos` plan with
    context-loss reminders after compaction, and premature-exit prevention
    while todos are open.
  - **Context compaction** (`summarization_middleware.py`, 1,302 lines, plus
    `durable_context_middleware.py`): it summarizes old history, keeps the
    active tail, and projects the summary as durable data instead of a
    message.
  - **Tool-output budget** (`tool_output_budget_middleware.py`, 1,281 lines):
    oversized results are externalized to disk and replaced with a typed
    synopsis, with head-and-tail truncation as the fallback.
  - **Robustness:** tool-error handling, dangling-tool-call repair, LLM-error
    fallback, model-length and safety finish-reason detectors, and
    clarification (ask the user).
  - **Subagent bounds:** subagent-limit (per-response and per-run delegation
    caps) and receipt verification (a subagent's report must cite tool
    receipts that really occurred).
- **Subagents.** `subagents/executor.py` (2,500 lines) handles bounded
  delegation, execution ids, timeouts, cancellation and a durable batch
  runtime.
- **Memory.** DeerMem is a pluggable `MemoryManager` with a file store, fact
  extraction and capacity eviction, evaluated offline against LongMemEval.
- **Skills.** `SKILL.md` with `name` and `description` frontmatter (the
  Anthropic agent-skills shape), a parser, validation, install, review, and
  SkillScan static security scanning.
- **Models.** A LangChain chat-model factory with OpenAI-compatible endpoints
  (vLLM, and Ollama through an extra) and several hosted providers. Thinking
  and vision flags, request admission.

### Execution infrastructure (what Orcel must not take)

- **Sandboxes.**
  - The local provider (`sandbox/local/local_sandbox.py`) runs a host shell
    (`subprocess.run([shell, "-c", ...])`) with an environment scrubber. It
    has no OS confinement and no approval broker.
  - The other providers (AIO, E2B, OpenSandbox, Boxlite, Kubernetes) are
    hosted or containerized.
  - In Orcel, any of these would be a second privileged execution path
    beside orceld.
- **Files, bash and browser tools:** sandbox-bound, with no per-action
  approval.
- **Authz and guardrails:**
  - RBAC and principal or tool filters for a multi-user server;
  - a guardrail middleware that can veto tool calls by provider policy.
  - These are advisory to the model loop; Orcel's authority is orceld.

### Quality, weaknesses and risks

- **Strong engineering discipline:** thorough tests, explicit concurrency
  contracts, offline-reproducible benchmarks, and prompt-trust rules (a
  system channel for framework text, sanitized human channel for untrusted
  text).
- **Dependency mass.** `deerflow-harness` declares as *core* dependencies
  `kubernetes`, `langfuse`, `e2b-code-interpreter`, `tavily-python`,
  `exa-py`, `firecrawl-py`, `duckdb`, `markitdown[all]`, `langgraph-api`,
  `langgraph-cli`, several provider SDKs, `sqlalchemy`, `alembic` and others.
  Installing it wholesale imports SaaS clients and a server stack that Orcel
  would never use. That is a large supply-chain and egress surface.
- **Coupling.** The import closure of `agents/factory.py` is 414 modules and
  about 101,000 lines, reaching Postgres, Redis, SQLAlchemy and Langfuse
  through `config/` and `persistence/`. Summarization, subagents, todo,
  memory and skills each close over 45,000–100,000 lines, so a selective copy
  requires decoupling work. Loop detection is the clean exception.
- **Multi-tenant server assumptions:**
  - a web gateway, auth, IM channels, Postgres for multi-instance, and
    scheduled tasks;
  - about 65 config modules.
  - Orcel is a local desktop agent with one user.
- **Security for Orcel's model:**
  - the unconfined local shell sandbox;
  - runtime MCP and skill installation and marketplace;
  - a private `starlette._utils` import pinned at a security boundary (by
    design, but fragile);
  - telemetry clients (Langfuse, Monocle) that must stay off.

## B. Copy-first transplant matrix

Each decision is one of COPY (verbatim, then minimal adaptation), ADAPT (copy
and decouple), REUSE (a pinned dependency), REIMPLEMENT (take the design, not
the code), or REJECT.

| # | Capability | DeerFlow source (pin 81e1ab8) | Orcel counterpart today | Decision | Orcel destination | Dependencies | Security notes | Complexity | Testing | Expected benefit |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | Agent loop and assembly | `agents/factory.py`, `agents/features.py`, `agents/thread_state.py` | None (Orcel has no agent runtime; BM-02 Tier C3 is blocked for want of a planner) | ADAPT: keep the `create_agent` and middleware architecture; strip `config/` and `persistence/` coupling | `apps/orcel-agent/orcel_agent/loop/` | `langchain-core`, `langchain`, `langgraph` (MIT) | Tools come only from the Orcel MCP edge; `sandbox=False` always | High (decoupling) | Fake-model unit tests; BM-02 Tier A through the agent | The missing capability: an Orcel-native multi-step agent |
| 2 | Loop detection | `agents/middlewares/loop_detection_middleware.py` | None | COPY (self-contained) | `orcel_agent/middleware/loop_detection.py` | Same as 1 | Decisions recorded for audit; no authority | Low | Copy DeerFlow's tests; scripted repeat loops | Stops runaway action loops (P0 safety) |
| 3 | Planning (todos) | `agents/middlewares/todo_middleware.py` | Deterministic per-task planners in BM-02 only | ADAPT | `orcel_agent/middleware/todos.py` | Same as 1 | None | Medium | Context-loss and premature-exit tests | Multi-step decomposition with recovery after compaction |
| 4 | Context compaction | `summarization_middleware.py`, `durable_context_middleware.py` | None | ADAPT | `orcel_agent/middleware/compaction.py` | Same as 1 | Summaries are model output, so they are untrusted data and never authority | High | Token-budget tests with a fake model | Long tasks within small local-model contexts |
| 5 | Tool-output budget | `tool_output_budget_middleware.py`, `tool_output_synopsis.py` | MCP results bounded per tool (64 KiB) by orceld | ADAPT (externalize to the agent's private state dir, never the user workspace) | `orcel_agent/middleware/output_budget.py` | Same as 1 | The disk writes are the agent's own state, outside orceld authority. Never write to user paths | Medium | Oversized-result tests | Keeps observations (UIA trees) within context |
| 6 | Tool-error handling and dangling-call repair | `tool_error_handling_middleware.py`, `dangling_tool_call_middleware.py` | orceld's typed failure codes | COPY plus mapping of Orcel failure codes | `orcel_agent/middleware/errors.py` | Same as 1 | A refusal (`CAPABILITY_DENIED`, `APPROVAL_REQUIRED`) is final for that call; never retried around the broker | Low | Refusal-path tests | Correct recovery semantics |
| 7 | Clarification | `clarification_middleware.py` | Approval prompts (orceld broker) | ADAPT (the question goes to the user through the Orcel client, never approves anything) | `orcel_agent/middleware/clarify.py` | Same as 1 | Clarification is not consent | Low | Unit | Fewer wrong guesses |
| 8 | Subagents and receipts | `subagents/executor.py`, `subagent_limit_middleware.py`, `receipt_verification.py` | None | ADAPT later (milestone M5), single-process, without the durable batch runtime | `orcel_agent/subagents/` | Same as 1 | Subagents share the parent's Orcel session and per-action approvals; no new authority | High | Bounded-delegation tests | Parallel observation, verified sub-reports |
| 9 | Long-term memory (DeerMem) | `agents/memory/**` | None (orceld journals actions, not knowledge) | ADAPT later (M6), file store under the agent's state dir, off by default | `orcel_agent/memory/` | Same as 1 | Memory is untrusted data and is never injected into system text | High | Offline synthetic memory tests | Durable task memory across sessions |
| 10 | Skills | `skills/parser.py`, `frontmatter.py`, `validation.py`, SkillScan | Claude-style skills in clients; none in Orcel | ADAPT (read-only local skill catalog; no runtime install or marketplace) | `orcel_agent/skills/` | `pyyaml` | Skills are untrusted instructions, scanned and never authority | Medium | Parser and scanner tests | Reusable workflows |
| 11 | Model abstraction | `models/factory.py`, `models/vllm_provider.py` | None | REIMPLEMENT thinly on LangChain's OpenAI-compatible client, plus a deterministic scripted model | `orcel_agent/models.py` | `langchain-openai` (MIT) | Local endpoint by default; no paid API by default; telemetry off | Low | Fake and scripted models offline; local-model evaluation on CI | Model-independent, local-first |
| 12 | Durable run state | LangGraph checkpointers (`runtime/checkpointer`) | `orcel-journal` (authority-side) | REUSE `langgraph-checkpoint-sqlite` for agent reasoning state only | Agent state dir | `langgraph-checkpoint-sqlite` (MIT) | orceld's journal stays the source of truth for actions; the agent checkpoint holds plans and messages only | Low | Kill-and-resume tests | Resumable agent tasks |
| 13 | MCP client | `mcp/` plus `langchain-mcp-adapters` | Orcel is an MCP server | REUSE `mcp` and `langchain-mcp-adapters` (MIT) as a client of `orcel mcp stdio` only | `orcel_agent/orcel_tools.py` | `mcp`, `langchain-mcp-adapters` | Exactly one server: Orcel's own edge. No third-party MCP servers | Low | Contract tests against the real edge | Exact, governed tool surface |
| 14 | Sandboxes (local, AIO, E2B, Kubernetes, ...) | `sandbox/**`, `community/*_sandbox` | orceld providers and the computer and native hosts | REJECT | none | none | A parallel privileged execution path | n/a | n/a | n/a |
| 15 | Bash, file and browser tools | `tools/builtins`, `community/browser_automation` | orceld `process`, `fs`, browser and UIA providers | REJECT (duplicates; bypass the broker) | none | none | Would bypass orceld | n/a | n/a | n/a |
| 16 | Gateway, auth, IM channels, scheduler, multi-tenant persistence | `backend/app/**`, `persistence/**` | orceld app API, Control Room, relay and tunnel | REJECT | none | none | New network surfaces | n/a | n/a | n/a |
| 17 | Web frontend | `frontend/**` | Control Room (headless client), desktop preview | REFERENCE (UX patterns for the run timeline and plan view only) | none now | none | Branding: no DeerFlow marks | n/a | n/a | Ideas for the Orcel UI |
| 18 | Telemetry (Langfuse, Monocle, LangSmith) | `tracing/**` | `orcel-audit` | REJECT; LangSmith tracing forced off | none | none | Egress | n/a | n/a | n/a |
| 19 | Evaluation discipline | `scripts/benchmark/**` conventions | BM-02 (Tiers A, B, C) | REIMPLEMENT the conventions (pinned datasets, offline graders, fixed seeds) in BM-02 | `tests/benchmarks` | none | none | Low | n/a | Honest, reproducible agent evaluation |

**Licensing and attribution (all COPY and ADAPT rows).**
- Each imported file keeps a header naming its DeerFlow path and the pin.
- DeerFlow's `LICENSE` is copied verbatim to
  `apps/orcel-agent/third_party/deer-flow/LICENSE`.
- A provenance ledger maps every imported file to its source blob and states
  the modifications.
- Nothing DeerFlow-branded is user-facing: no logos and no "DeerFlow" product
  name in the UI.
- Dependencies are MIT (LangChain, LangGraph, the `mcp` SDK,
  `langchain-mcp-adapters`) or Apache-2.0 (models). Each is pinned exactly and
  recorded in an SBOM before release.

## C. Target architecture

```text
 Orcel Agent (new, unprivileged Python process; DeerFlow-derived)
   planner loop (LangGraph) + middlewares: loop detection, todos,
   compaction, output budget, errors, clarify, [subagents], [memory], [skills]
   model: local OpenAI-compatible endpoint | deterministic scripted model
   state: agent state dir (plans, messages, checkpoints) - no authority
        |
        |  MCP (stdio) - the ONLY tool source: `orcel mcp stdio`
        v
 Orcel MCP edge (apps/orcel-mcp) - tool surface profile, schemas
        |
 orceld authority kernel - policy, approval broker (SOFT/STRONG,
   Windows Hello / Touch ID / polkit), leases, journal, audit,
   protected surfaces, identity checks, bounded observation
        |
 providers and private hosts (fs, process, UIA, computer host,
   native host, browser host, ...)
```

- **Authority.** It is unchanged and stays entirely in orceld.
  - The agent decides what to request. orceld decides whether it happens.
  - Approval prompts reach the user through orceld's broker exactly as they
    do for any MCP client. The agent never sees, mints, caches or relays an
    approval, a lease or a target identity it was not given by the edge.
  - This is P20's "AI / MCP client" layer
    (`docs/canonical/ORCEL_P20_UNIVERSAL_AGENT_RUNTIME_PLAN.md`, section 5).
    It is consistent with the donor matrix's `REJECT_FOR_CORE` for donor
    agent loops, because the loop runs above the edge and outside the
    authority layer.
- **Tools.**
  - The agent connects to exactly one MCP server, Orcel's own edge, started
    as `orcel mcp stdio` with a tool-surface profile.
  - It has no shell, file, browser or network tools of its own. DeerFlow's
    sandbox, bash, file and browser tools are not imported.
  - Its only non-Orcel tools are pure reasoning tools: `write_todos`, ask the
    user and, later, memory read/write in its own state.
- **Data.**
  - Everything entering the model is untrusted data on the human/data
    channel: Orcel tool results, files, pages, skills, memory and summaries.
    That follows DeerFlow's own prompt-trust rule.
  - The system prompt is static Orcel text.
- **Persistence.**
  - Agent reasoning state uses LangGraph SQLite checkpoints in a per-user
    private state dir (owner-only, like orceld's).
  - Actions and their outcomes are journaled by orceld, which stays the
    single source of truth. After a crash, the agent resumes its plan and
    re-observes; it never replays an action from its own state.
- **Models.**
  - Default: a local OpenAI-compatible endpoint (llama.cpp server, Ollama,
    vLLM).
  - Tests: a deterministic scripted model that replays a labelled plan.
  - Hosted providers: optional, opt-in, never a default, never required.
- **Cross-platform.** Pure Python 3.12 (Orcel's CI version) on Windows, macOS
  and Linux. Platform differences stay in orceld and the hosts.

## D. Alternatives and trade-offs

1. **Install `deerflow-harness` wholesale as a dependency.** Rejected.
   - It needs about 200,000 lines and dozens of SaaS, server and Kubernetes
     clients.
   - Its sandbox, bash and file tools would sit one flag away from a second
     execution path.
   - Its telemetry and egress surface is large.
   - Upgrades would drag in its multi-tenant server.
2. **Transplant the whole platform (gateway, frontend, persistence).**
   Rejected.
   - It duplicates orceld, Control Room and the relay.
   - It adds Postgres or SQLite servers, auth and IM channels: new network
     surfaces with no Orcel benefit.
3. **Rewrite the agent in Rust or TypeScript.** Rejected for now.
   - It discards proven, tested middleware code (the copy-first rule) for
     language consistency alone.
   - Python 3.12 already runs in Orcel's CI and benchmarks.
4. **Put the agent loop inside orceld.** Rejected.
   - It violates the canonical `REJECT_FOR_CORE` rule.
   - It mixes model-driven decisions with the authority kernel.
5. **Chosen: a curated, decoupled transplant of DeerFlow's agent core into a
   new unprivileged Orcel Agent, connected to Orcel only through its MCP
   edge.**
   - It keeps DeerFlow's best code (the middleware loop and its robustness
     work).
   - It keeps Orcel's authority model exactly.
   - It adds one small Python dependency set (LangChain core, LangGraph, the
     MCP SDK) instead of a platform.

## E. Implementation roadmap

Each milestone is its own reviewed PR or PRs, with exact-head CI and rollback
by revert. M0–M4 are authority-neutral: the agent is an MCP client like any
other, not packaged into a release and not reachable from orceld. Packaging
the agent into a release is M7 and is founder-gated (section G).

| Milestone | Scope | Depends on | Acceptance | Rollback |
|---|---|---|---|---|
| M0 | This plan, the donor lock, an independent review | — | Reviewed and merged; the lock verifies against the pin | Revert (docs only) |
| M1 | `apps/orcel-agent` skeleton with no third-party dependencies: an MCP stdio client of `orcel mcp stdio`, a deterministic scripted planner, a step budget, a refusal-is-final rule. Runs BM-02 Tier A tasks through the real edge on CI | M0 | Tier A tasks are solved through the edge on Windows, macOS and Linux CI, with every call audited by orceld; the agent has no tool except Orcel's; a source scan forbids subprocess, shell, socket and file writes outside its state dir | Remove the app (not packaged) |
| M2 | The LangGraph loop plus copied loop detection, with a pinned dependency lock (LangChain core, LangGraph, `mcp`, `langchain-mcp-adapters`), supply-chain audit and a scripted chat model | M1 | Scripted-model Tier A parity with M1; DeerFlow's loop-detection tests ported and green; supply-chain audit green; LangSmith and telemetry off, verified | Revert the dependency set |
| M3 | Todos, compaction, output budget, error handling, clarification (ADAPT rows 3–7) | M2 | Ported tests green; long-task compaction tests; refusals are never retried around the broker | Revert the middlewares |
| M4 | Local-model evaluation on CI: a pinned open-weight model (license recorded) served by llama.cpp on a disposable runner; BM-02 Tier A and B agent runs labelled "autonomous, local model" | M3 | A report with success, tokens, latency and failure modes against the deterministic baseline; nothing claimed beyond the data | Drop the job (non-required) |
| M5 | Subagents and receipt verification (row 8) | M3 | Bounded delegation; citations verified | Revert |
| M6 | Memory (DeerMem, row 9) and skills (row 10), read-only and off by default | M3 | Offline synthetic memory tests; skill scanner tests | Revert |
| M7 | Packaging the agent into a release with Control Room integration | M3 to M6 and the founder grain (section G) | The founder activates the grain; release qualification; SBOM | Do not ship |

**First executable slice (M1):** create `apps/orcel-agent` (Python 3.12, standard library only):
- `orcel_agent/edge.py`: a minimal MCP JSON-RPC stdio client for `orcel mcp
  stdio` (initialize, `tools/list`, `tools/call`). No other transport.
- `orcel_agent/agent.py`: the loop. Observe → plan step → call an Orcel tool
  → record the result. A scripted planner, a step budget, a refusal-is-final
  rule, an error mapping.
- **Tests:** unit tests with a fake edge, plus a CI job that runs BM-02
  Tier A tasks through the real orceld and edge via the agent.
- **Inert:** not packaged, no entry in the installer, not referenced by
  orceld. A source scan pins that.

## F. Benchmark plan

- **Baseline:** BM-02 Tier A (20 read-only tasks) and Tier B (21 mutating
  tasks, scripted SOFT consent, labelled) through orceld, as today.
- **Agent runs, labelled per row:**
  1. `deterministic-scripted`: the agent's own loop replaying the existing
     planners. Measures harness overhead and regressions.
  2. `autonomous-local-model`: an open-weight model on a CI runner, no
     scripted plan.
  3. `autonomous-hosted-model`: optional and founder-funded only. Not part
     of the default workflow.
- **Approval labelling** is unchanged:
  - Tier B uses scripted SOFT consent in test builds;
  - real STRONG presence is founder-present only (as SG-000128 slice 3b).
  - No run claims real user approval unless a person gave it.
- **Metrics per task:**
  - success;
  - Orcel calls and refusals;
  - model tokens;
  - wall time per step and per task (p50/p95);
  - peak RSS of the agent process;
  - loop-detector and compaction events;
  - recovery after a forced kill (resume from checkpoint, re-observe,
    finish).
- **Reproducibility:**
  - pinned model weights (SHA-256);
  - fixed sampling (temperature 0, seed);
  - pinned prompts;
  - the report records the Orcel commit, the donor pin, the model hash and
    the config.
  - No dataset or model download in the default developer workflow; the CI
    job downloads pinned weights to a disposable runner only.

## G. Risks and governance

- **Proposed grain (founder activation required before M7): "Orcel Agent:
  first-party MCP client runtime (DeerFlow-derived)".**
  - Scope: ship an unprivileged agent process that is a client of the Orcel
    MCP edge only, with the middlewares and model interface above.
  - Authority delta: none in orceld, the hosts, approvals or leases. A new
    product surface (an agent the user runs), a new dependency set, and an
    optional local model download chosen by the user.
- **Before that grain, M0–M6 are authority-neutral**, on the SG-000115
  pattern: unpackaged code, CI-only, not reachable from orceld, a source scan
  forbidding execution primitives in the agent.
- **Canonical clarification needed (recorded with M1, reviewed).** The donor
  matrix's "donor agent loop / model runtime: REJECT_FOR_CORE" stays true for
  the authority layer. The amendment adds that a donor-derived loop may run
  only as an unprivileged MCP client above the edge.
- **Founder decisions** (recorded here; they do not block M0–M6):
  1. Activate the Orcel Agent grain for packaging and release (M7).
  2. The default local model and its license, and whether the user downloads
     it (Orcel never ships weights silently).
  3. Whether any hosted model provider may be offered as an opt-in.
  4. Whether the agent may install skills at runtime. The plan's default is
     no: a read-only, reviewed catalog.
- **Dependency risk.**
  - LangChain and LangGraph release often. Pin exactly, audit supply chain in
    CI, force telemetry off.
  - Rollback is pure: the agent sits above the edge, so removing it never
    affects orceld.
- **Model risk.**
  - Small local models may plan poorly. The deterministic and scripted path
    always remains, and claims follow M4's data only.
  - On this development PC (16 GB RAM, no discrete GPU) no local model is
    installed, and none is installed on the founder's machine by this work.
    Local-model evaluation runs on disposable CI runners.
- **Coordination.**
  - SG-000115 (Unix browser-host slices A1–A6, owned by the same session) and
    SG-000128 (UIA scoped reads) touch `crates/orcel-browser-host` and
    `crates/orcel-provider-uia`.
  - The agent touches neither: it lives under `apps/orcel-agent` and the
    benchmark harness, so no file overlaps.

## H. Execution checkpoint

- Orcel `main` is at `ced44f8b2b5ba335dbb98e0d367f95d3e1258e7e` when this was
  written. SG-000115 A1 (#527) and A2 (#529) are merged; A3 (#530), A4 (#531)
  and A5 (#532) are open.
- The donor is pinned at `81e1ab8dcc86574cfac0ecdfe3636b775a08c567`, and
  `deerflow-donor.lock.json` hashes the 22 candidate files.
- **Immediate next action:** after this plan's independent review, start M1
  on a new branch:
  - `apps/orcel-agent/orcel_agent/{edge.py,agent.py}`;
  - unit tests;
  - a CI step running BM-02 Tier A through the agent and the real
    `orcel mcp stdio`.
