# Kaf Migration Qualification

## Scope

This record qualifies the full-tree migration from the pinned upstream donor revision:

- Upstream: `vercel/eve@9c36b7c280fda89ae678cabfd8d906f4bde2216f`
- Regenerated Kaf import commit: `b2cf19bdf5fca7020c38ba94d43fd89b7fe02d30`
- Regenerated Kaf import tree: `a92ba1502a5011cf48ac4f9b38a821a19b8d08d0`
- Regeneration workflow run: `36768732850`
- Default-branch qualification workflow registration merge: `ac837752bac4a0c8b1a975e196e4bbb51380785d`

This file is a qualification ledger, not a completion claim.

## Mechanical migration evidence

The regeneration workflow verified:

1. The exact upstream revision was fetched.
2. The complete upstream repository tree was copied into the Kaf migration workspace.
3. Kaf-owned project identity was transformed with token-aware rules.
4. External dependency package coordinates containing `eve` were discovered from upstream manifests and preserved rather than renamed.
5. The upstream Apache-2.0 LICENSE was preserved byte-for-byte.
6. The upstream NOTICE attribution was retained beneath Kaf attribution.

The generated migration report records 5,614 copied files, 5,592 inspected text files, 3,421 transformed text files, and 12 external package coordinates intentionally preserved.

## Residual identity classification

A raw `eve` token count is not a valid stale-branding metric because Kaf interoperates with externally published packages whose package names legitimately contain `eve`.

Known expected categories include:

- pinned upstream provenance in `UPSTREAM.md` and migration-only workflow material;
- published third-party package coordinates such as `@stripe/link-integrations-eve`, `@agent-browser/eve`, `@browserbasehq/eve`, `@github-tools/eve-extension`, `@onkernel/eve-extension`, `@supermemory/eve`, `@upstash/agentkit-eve`, `@vectorize-io/hindsight-eve`, `@blitzreels/eve`, `@jetty/eve`, and `eve-channel-blooio`;
- lockfile and registry references required to resolve those external packages;
- documentation that names those external integrations by their real published package coordinates.

Residuals are accepted only when they are attributable to provenance, an external package coordinate, or documentation/code that must refer to that external coordinate. Any Kaf-owned runtime, package, command, environment variable, path, URL, or user-facing project identity that remains branded as Eve is a migration defect and must be repaired before readiness.

## Required qualification gates

The migration remains **NOT QUALIFIED** until all applicable gates below pass on the exact PR head:

- frozen-lockfile dependency installation;
- lint and dependency consistency;
- fixture and invariant guards;
- documentation validation;
- TypeScript typecheck;
- unit tests;
- integration tests on Ubuntu and Windows;
- scenario tests and workspace build;
- framework fixture tests;
- template compatibility tests;
- TUI smoke tests where required secrets are available, with unavailable external-secret gates recorded honestly rather than fabricated;
- workflow and release-path audit;
- residual identity audit;
- Jev independent review;
- Alibaba Open Code Review qualification.

The default branch now contains a dedicated zero-cost qualification workflow for the non-secret local gates. It deliberately does not invoke paid APIs, deployment credentials, or secret-backed external services.

Cubic, CodeRabbit, Qodo, and similar services are not accepted as qualification evidence for Kaf.
