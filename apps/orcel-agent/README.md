# Orcel Agent (M1)

A planner package that is an **MCP client of the Orcel edge only**. It proposes
calls, and orceld authorizes, executes, audits and verifies them. Design,
decisions and roadmap:
`docs/orcel/implementation-readiness/prep/DEERFLOW_ORCEL_AGENT_MASTER_PLAN.md`.

**M1 status:**
- Python 3.12, standard library only: no donor code and no third-party
  dependency.
- **Not packaged** and not referenced by orceld.
- Later milestones import DeerFlow-derived middlewares under an owning grain
  that is not yet activated.

## Rules the agent enforces (client side; orceld remains the authority)

- **One tool source.** It spawns exactly one child, the edge
  (`node apps/orcel-mcp/dist/index.js`). It runs no shell and opens no socket.
- **Allowlist.** In M1 only the read-only tools (`fs_read`, `fs_read_range`,
  `fs_list`, `fs_stat`, `fs_find`, `fs_search`, `workspace_get`,
  `system_status`) are offered to a planner or dispatched. The edge cannot
  serve the `core` profile to a local client, so this list lives in the
  agent.
- **Refusal is final.** A call orceld refused is never proposed again.
- **Approval budget.** At most 3 approval requests per run. The run stops at
  the first denial and never re-asks.
- **Step budget.**
- **Resume invariant.** A call dispatched but not recorded before a crash is
  surfaced once as `OUTCOME_UNKNOWN`. A mutation then needs a fresh
  observation first, and nothing is re-dispatched from agent state.
- **Private store.**
  - A per-run directory: owner-only, size-capped, expiring after 24 h,
    deleted on completion.
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
tasks' scripted plans dispatched through the agent's rules, not a model.
