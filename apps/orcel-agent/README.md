# Orcel Agent (M1; SG-000129 M2 in progress)

A planner package that is an **MCP client of the Orcel edge only**. It proposes
calls, and orceld authorizes, executes, audits and verifies them. Design,
decisions and roadmap:
`docs/orcel/implementation-readiness/prep/DEERFLOW_ORCEL_AGENT_MASTER_PLAN.md`.

**M1 status:**
- Python 3.12, standard library only: no donor code and no third-party
  dependency.
- **Not packaged** and not referenced by orceld.
- M2 and M3 run under SpecGrain SG-000129 (`prep/SG-000129.md`). Slice 1
  admits a hash-locked dependency set, which the agent's code does not import
  yet:
  - LangChain 1.3 and LangGraph 1.2, at the DeerFlow pin's versions;
  - wheels only;
  - a license table and an advisory audit;
  - tracing forced off.

## Loop detection (SG-000129 slice 3)

`orcel_agent/loop_detection.py` is adapted from DeerFlow's loop-detection
middleware. The detection core is unchanged in logic and uses Orcel tool
names; the ledger is in `third_party/PROVENANCE.json`.

Loop detection is on by default (`detect_loops=False` turns it off). The
planner then:
- tracks every proposed call;
- appends a warning to the next model call, after the tool messages;
- turns a hard stop into a finish (`stop_reason` "loop_capped", carried into
  `RunResult`), so the looping call is never dispatched;
- emits each decision to the event log.

The thresholds:
- identical calls: a warning at 3 and a stop at 5, within a window of 20
  (DeerFlow's);
- per tool: a warning at 12 calls and a stop at 20, scaled to the 32-step
  budget (DeerFlow's 30 and 50 could never fire within it).

## LangChain planner adapter (SG-000129 slice 2)

`orcel_agent/chat_planner.py` puts a LangChain chat model behind the M1
`Planner` protocol. Its conversation has four parts:
- a static Orcel system prompt;
- the goal;
- the edge's tool schemas, converted here (no MCP library);
- each step, as a tool call and its result as a tool message, which is
  untrusted data.

**What a reply becomes:**
- exactly one tool call becomes a proposal;
- no tool call becomes a finish claim;
- anything else becomes malformed, and the run stops.

**Every proposal still passes the M1 gate:**
- the allowlist;
- the tool's schema, including JSON types and closed properties;
- the approval and step budgets;
- refusal-is-final;
- the resume invariant.

Build agents for a chat model with `orcel_agent.entry.chat_agent`. It refuses
any allowlist wider than the read-only set. The model runs with LangSmith
tracing disabled for each call.

The tests use a scripted in-process chat model (no inference). BM-02 Tier A
runs through the adapter as `orcel_bench agent --planner chat`, labelled
`orcel-agent-langchain-scripted`.

## Dependencies (SG-000129 slice 1)

```bash
python -m venv .venv
.venv/bin/python -m pip install --require-hashes --only-binary :all: --no-deps -r requirements.lock
ORCEL_AGENT_DEPS=1 .venv/bin/python -I -B -m unittest discover -s tests -v
.venv/bin/python -I tools/licenses.py --check
```

- **Lock records.** `requirements-notes.md` records how the lock is made and
  every version move.
- **Licenses.** `THIRD_PARTY_LICENSES.md` is the generated license table.
- **DeerFlow provenance.** `third_party/deer-flow/LICENSE` is DeerFlow's MIT
  notice, and `third_party/PROVENANCE.json` is the ledger for copied code
  (empty until slice 3).
- **Egress test.** It runs a scripted LangGraph graph with an SQLite
  checkpoint while Python's audit hooks refuse connections, name lookups,
  binds and SQLite extension loads.

## Rules the agent enforces (client side; orceld remains the authority)

- **One tool source.** It spawns exactly one child, the edge
  (`node apps/orcel-mcp/dist/index.js`). It runs no shell and opens no socket.
- **Allowlist.** In M1 only the read-only tools (`fs_read`, `fs_read_range`,
  `fs_list`, `fs_stat`, `fs_find`, `fs_search`, `workspace_get`,
  `system_status`) are offered to a planner or dispatched. The edge cannot
  serve the `core` profile to a local client, so this list lives in the
  agent.
- **Fail-closed classes.** Every tool outside the read-only set is treated
  as mutating and approval-bearing.
- **Refusal is final.** A call orceld refused is never dispatched again,
  even after a resume.
- **Approval budget.** orceld never answers "approval required"; its broker
  prompts the person. So approval-bearing calls are counted *before*
  dispatch: at most 3 per run. The run stops at the first denial and never
  re-asks, even after a resume.
- **Step budget.** Counted across a resume.
- **Resume invariant.** A call dispatched but not recorded (a crash, or a
  broken edge mid-call) is surfaced once as `OUTCOME_UNKNOWN`. That exact
  mutation is never dispatched again, and any other mutation needs a fresh
  observation first.
- **Private store.**
  - A per-run directory, size-capped and expiring 24 h after its last write.
  - Deleted when the run ends; a crash keeps it for resume.
  - Owner-only: mode 0700 on Unix. On Windows it inherits its root's ACL;
    the tests check that no broad principal can reach it, and a protected
    DACL of its own is recorded for the owning grain.
  - It holds tool names, argument digests and error codes only, never
    results or file content.

## Precondition: no Full User or Admin lease

Under a Full User lease, routine operations need no fresh approval, so a
planner fed injected content could act unattended. No MCP tool reports lease
state yet. **Until a read-only lease signal exists (under the owning grain),
run the agent only against a test orceld or an orceld in Safe mode.**

## Tests

```bash
cd apps/orcel-agent && python -B -m unittest discover -s tests -v
```

BM-02 Tier A through the agent, the built edge and a test orceld:

```bash
cd tests/benchmarks && python -B -m orcel_bench agent --orceld <orceld> --edge ../../apps/orcel-mcp/dist/index.js --commit <40-hex> --out <report.json>
```

Rows are labelled `deterministic` / `orcel-agent-scripted`. They are the
tasks' scripted plans, not a model. Only the agent's dispatch rules are
exercised there; its planner loop is covered by the unit tests.
