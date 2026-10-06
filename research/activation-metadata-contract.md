---
issue: "None (maintainer-requested in PR #3338)"
status: implemented
last_updated: "2026-10-06"
---

# Activation metadata contract

> **Implementation status (2026-10-06):** Implemented on canonical `main`. Schema-v4 `invoke_agent` spans expose queryable activation metadata, channel/schedule/audience/content-policy attributes are attached before sampling, and tests cover sampler/export consistency.

## Summary

Schema v4 activation roots need a small provider-neutral attribute set for
filtering and grouping without inspecting captured payloads. The contract keeps
structural metadata on `invoke_agent` spans while preserving orcel's existing
trace-content and destination-redaction boundaries.

## Attribute ownership

Every activation carries its run type, agent identity, audience, turn identity,
and directional content-policy results. Root-session activations additionally
carry their initiating channel kind, origin, authored schedule ID when
applicable, and bounded initial title when input capture permits. An actual
channel delivery carries its own channel kind, name, and delivery ID.
Delivery-less subagent activations omit the root-only attributes and use parent
lineage to describe delegation.

The session title is derived once from the initial session input, stored in the
run context, and repeated on each turn activation. It never describes a later
turn. Titles remain input content and can be omitted by the trace decision or
removed by a destination's input-redaction policy.

## Sampling and export invariants

Session metadata is available before the first turn is sampled. A sampler and
the resulting exported activation therefore observe the same channel kind,
schedule provenance, and title.

The `agent.trace.content.input` and `agent.trace.content.output` attributes
describe what the receiving destination can observe. Destination redaction can
narrow either value from `true` to `false`; it cannot widen the session's
resolved trace decision.

## Scope

This contract does not change workflow lifecycle ownership, status semantics,
trace identity, or remote-lineage authorization. It only makes existing
activation metadata queryable across OpenTelemetry destinations.
