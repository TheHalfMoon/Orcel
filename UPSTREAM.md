# Upstream Lineage

Kaf originated from the Vercel eve codebase and is being transformed into a distinct HalfMoon project.

- Upstream repository: `vercel/eve`
- Initial migration base: `9c36b7c280fda89ae678cabfd8d906f4bde2216f`
- Base date: 2026-09-30
- Migration policy: preserve upstream provenance, Apache-2.0 licensing obligations, and applicable NOTICE attribution while renaming project-owned identity from eve to Kaf and project-owned branding from Vercel to HalfMoon.

Vercel-specific provider names, package dependencies, service identifiers, trademarks, copyright notices, and third-party attribution are not renamed when they refer to the actual upstream provider, dependency, or rights holder.

## Kaf-specific compatibility adaptations

Generic identity migration is followed by narrowly scoped semantic adaptations when an upstream implementation assumes Eve-specific package identity or hosting coordinates:

- Documentation link validation uses a neutral URL origin (`https://kaf.invalid`) only for URL resolution so route checks remain independent of repository hosting paths.
- The Kaf Slack template uses `@vercel/connect` core token retrieval with Kaf channel/auth exports instead of the Eve-specific `@vercel/connect/eve` adapter, which imports the external `eve` runtime package.
- The deterministic parity-repair workflow regenerates the derived web scaffold before linting and qualification so generated setup artifacts stay synchronized with their canonical registry sources.

These adaptations preserve optional Vercel Connect interoperability without introducing a runtime dependency on the Eve package or rewriting legitimate third-party provider identities.
