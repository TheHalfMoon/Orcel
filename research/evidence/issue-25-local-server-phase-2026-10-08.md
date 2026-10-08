# Issue #25 — Windows local mock server-phase probe evidence (2026-10-08)

Issue: https://github.com/TheHalfMoon/Orcel/issues/25
Development PR: https://github.com/TheHalfMoon/Orcel/pull/26

## Acquisition and results

The founder-authorized Windows host was used with Node 24, the local fixture
`e2e/fixtures/agent-workflow-stress`, the deterministic mock model, and the
opt-in server event observer. No real AI provider, paid service or cloud
benchmark deployment was used. Logs and full per-case JSON evidence are held
locally **outside the Git repository** because they contain opaque session
and turn correlation identifiers.

The initial run with the pre-rename legacy benchmark log spelling completed both
fixture evals: **2/2 passed, 361/361 assertion gates** and emitted 600 raw
instrumentation rows. That spelling was subsequently corrected to
`WORKFLOW_STRESS_SERVER_PHASE=` because the repository's existing external
compatibility check rejects the retired prefix.

A separate repeated mock fixture run after the spelling fix produced the
following source-backed local records:

- **600** actual public-instrumentation lifecycle handler observations
- **200** distinct server turn identities, from **1** local monotonic clock domain
- **200/200** observed `turn.started` to first `model.call.started` handler deltas
- **200/200** observed `turn.started` to turn-terminal handler deltas
- Original raw logfile SHA-256:
  `A581B89D59E68331A7A4AC56CF44F62EB9946BE26CFEF25418C21CF26675E3D6`
- Local derived JSON report SHA-256:
  `93F15EBD58C4C9BB5CC4E0C0F1F8CB1E690F7E8F1B326B6D35A63E78411044AF`

**Qualification limitation:** this repeated fixture run passed **1 of 2 evals**,
with **360/361** assertion gates passing. The concurrent stress eval failed
one gate; the log also reported a missing `retired.json` in a transient
local runtime snapshot that had been manually removed after the first run.
The failure's causal relationship to that runtime warning has **not** been
established. Do not record this repeated run as a full fixture PASS.
The observation rows demonstrate real provider execution and parser
coverage, not overall scenario correctness, performance improvement, or
scientific significance.

The log was produced using Windows PowerShell UTF-16LE native output
redirection. The analysis CLI was extended to support explicitly marked
UTF-16LE logs, and to skip trying to create an existing volume root when
writing its report. Both discoveries are regression-tested.

## Strict interpretive limits

All non-null values are the differences between **server-local
instrumentation-handler observation timestamps** from one monotonic clock
domain. They are **not** HTTP receipt, session/hook readiness, provider-side
model compute start, durable Workflow completion, durable write counts, or
client send-to-ack times. Unsupported boundaries remain null.

These runs happened in a mutable Windows worktree during development,
including the log-prefix correction, and therefore do **not** constitute
independently attested exact-head hosted trials. There is no paired base/head
deployment or A/A statistical calibration claim. The raw evidence remains
local and is not exposed publicly in source control.

## Remaining acceptance before closing Issue #25

Re-run the full real fixture at the exact **final signed commit**, confirm both
evals and all gates pass without transient runtime warnings, retain raw logs,
correlate sessions across worker domains, and document any unsupported
cross-worker event boundaries. Obtain exact-head CI, host review, normal merge,
and post-merge qualification; do not conceal or waive any failed scenario.
