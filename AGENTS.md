# Repository Agent Tooling

Existing project governance and canonical evidence remain authoritative.

<!-- graft:start -->
## Graft — repository context layer

Use Graft (https://github.com/trailhq/Graft, `@nanonets/graft`) as the default codebase context/navigation layer for coding agents.

If Graft is unavailable or the local `graft/` graph is absent/stale, run `graft init`, select the active agent(s), then run `graft build`. Before broad source exploration prefer `graft check`, `graft map`, `graft ask "<question>" --source`, `graft skeleton <file>`, `graft callers <symbol>`, and `graft grep "<literal>"`. After material code changes, run `graft build` again.

Treat `graft/` as a local regenerable cache and do not commit it. Keep usage zero-cost: do not introduce paid model/API usage; any model-backed enrichment must use an already-authorized local or free provider.

Graft is context/navigation, not correctness or qualification evidence. Continue all repository-required tests, Jev review/qualification where applicable, Alibaba Open Code Review, CI, and security checks. Never fabricate Graft output, tool execution, CI, reviews, or evidence.
<!-- graft:end -->
