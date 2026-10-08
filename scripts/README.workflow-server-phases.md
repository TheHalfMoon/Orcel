# Opt-in server-process phase evidence

Tracking: https://github.com/TheHalfMoon/Orcel/issues/25

This is a **source-backed event-handler timing probe**, not an end-to-end
Workflow latency benchmark and not an HTTP receipt or true model-execution
measurement. It reuses the existing public Orcel instrumentation API and is
confined to the `agent-workflow-stress` fixture. No Nitro or Workflow internals
are patched. No provider, paid exporter, or external service is required.

## Runtime opt-in

For a **local** stress fixture execution, explicitly set:

    WORKFLOW_STRESS_SERVER_PHASES=1

Without this variable, the provider emits no rows and retains no timing state.
With it enabled, the fixture's authored provider observes supported lifecycle
callbacks using the **server process's own** `performance.now()` clock and a
random clock-domain ID generated for that module instance. Each log line is
prefixed `WORKFLOW_STRESS_SERVER_PHASE=` and contains _only_ the event name, opaque
session/turn/attempt correlation IDs, a local sequence, a local monotonic
timestamp, and clock-domain provenance. No prompts, model responses, event
input, PHI, tokens, traces or secrets are recorded by this probe. Treat opaque
IDs as operationally sensitive metadata and retain/redact logs under your
normal evidence-handling policy.

Collect the server's stdout/stderr into a local log file with the already
supported Orcel local runner or equivalent authorized logging; do not copy
client timing observations into that log. From the repository root:

    node --test scripts/workflow-server-phase-report.test.mjs

    node scripts/workflow-server-phase-report.mjs \
      --logs path/to/actual-server.log \
      --output .artifacts/workflow-server-phase-report.json

The analyzer intentionally refuses a log with **zero captured server rows**;
it does not substitute synthetic fixture numbers for missing real events.

## Exact evidence semantics

The analyzer reports only two source-backed boundaries:

- `turnStartToFirstModelHandlerMs`: local provider observation of
  `model.call.started` minus local provider observation of `turn.started`.
  This measures callback dispatch timing, **not** when model computation starts.
- `turnStartToTerminalHandlerMs`: local terminal callback minus local
  `turn.started` callback. This is **not** full Workflow durable completion
  or client settlement.

A duration is calculated only if the start and finish were observed once in
the **same clock domain** with monotonic readings and ordered event sequences.
Multiple model calls are normal; the first _observed_ model callback is used,
while the total observed call count is retained. Missing starts/ends,
duplicated starts/terminals, cross-process clocks, worker restarts with a
reused clock domain, backward clock readings, and invalid identities produce
`null` and an explicit reason. The output contains coverage denominators
and never interprets unavailable phases as zero. HTTP receipt, hook readiness,
true model execution start, durable step/hook writes and serialized byte
counts remain explicitly `null` in `unobservedBoundaries`.

The test suite proves event-adapter/collector behavior with **scripted mock
lifecycle events**, including concurrent turns, sessions, retries, duplicate
delivery, restarts, clock resets and refusal of content-bearing records.
Those tests are not evidence that production Workflow worker logs are
correlated or that a real hosted benchmark ran.

## Local qualification and remaining scientific limits

The Windows local deterministic mock-model fixture was executed with the
opt-in enabled at signed implementation SHA
`04021076986783cdb0694b097e6fb8ca9fffbaf7`: both stress evals passed
(2/2, 361/361 assertion gates). The raw log contains 600 actual handler
observations covering 200 turn identities; the report verifies both
source-backed local deltas for all 200 cases within one real clock domain.
See `research/evidence/issue-25-local-server-phase-2026-10-08.md` for
the immutable raw-log/report hashes, exact command scope, and the prior
failed attempt, which is **not** silently erased.

This does not establish that the authored provider executes in all
hosted/worker contexts, nor does it qualify multiple real-process clock
domains. The client eval samples do not attest their turn IDs into paired
capture rows, so this server report must **not** be silently joined to
per-case client timings; such a join needs explicit verified correlation.
Hosted acquisition remains a separate credential, zero-cost and privacy
boundary. Do not derive cross-machine intervals, a speedup, or inferential
significance from these observations.
