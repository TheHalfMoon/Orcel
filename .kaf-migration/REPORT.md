# Kaf Full-Import Report

- Upstream: `vercel/eve@9c36b7c280fda89ae678cabfd8d906f4bde2216f`
- Files copied: 5614
- Text files inspected: 5592
- Text files transformed: 3421
- External Eve package coordinates preserved: 12
- Residual project-identity hits outside LICENSE/NOTICE: 131

## Preserved external package coordinates

- `@stripe/link-integrations-eve`
- `@github-tools/eve-extension`
- `@vectorize-io/hindsight-eve`
- `@onkernel/eve-extension`
- `@upstash/agentkit-eve`
- `@agent-browser/eve`
- `@browserbasehq/eve`
- `eve-channel-blooio`
- `eventsource-parser`
- `@supermemory/eve`
- `@blitzreels/eve`
- `@jetty/eve`

## Residual identity hits

- `.github/workflows/bootstrap-eve-to-kaf.yml`: 15
- `.syncpackrc.json`: 1
- `UPSTREAM.md`: 3
- `apps/docs/lib/integrations/data.ts`: 31
- `apps/docs/package.json`: 11
- `apps/docs/registry/channels/blooio.ts`: 1
- `apps/docs/registry/extensions/agent-browser.ts`: 1
- `apps/docs/registry/extensions/blitzreels.ts`: 1
- `apps/docs/registry/extensions/browserbase.ts`: 1
- `apps/docs/registry/extensions/github-tools.ts`: 1
- `apps/docs/registry/extensions/hindsight-hook.ts`: 1
- `apps/docs/registry/extensions/hindsight-instructions.ts`: 1
- `apps/docs/registry/extensions/jetty.ts`: 1
- `apps/docs/registry/extensions/kernel.ts`: 1
- `apps/docs/registry/extensions/link.ts`: 1
- `apps/docs/registry/memory/supermemory.ts`: 1
- `apps/docs/registry/memory/upstash-agentkit.ts`: 1
- `apps/docs/registry.json`: 11
- `apps/docs/scripts/validate-memory-registry.ts`: 4
- `docs/memory/overview.mdx`: 6
- `packages/kaf/CHANGELOG.md`: 1
- `packages/kaf/src/cli/dev/tui/setup-panel.test.ts`: 2
- `pnpm-lock.yaml`: 33
- `pnpm-workspace.yaml`: 1

## Rename policy

Project-owned eve identity is renamed to Kaf. Project-owned GitHub URLs are redirected to TheHalfMoon/kaf.
Actual external package coordinates are discovered from the pinned upstream dependency manifests and preserved automatically.
Actual `@vercel/*` dependencies and Vercel provider/service names remain intact because renaming them would break runtime behavior.
Apache-2.0 LICENSE is copied byte-for-byte from upstream; upstream NOTICE is retained verbatim beneath Kaf attribution.
Third-party package coordinates are preserved when they are not owned by Kaf.
