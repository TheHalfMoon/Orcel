# Kaf Full-Import Report

- Upstream: `vercel/eve@9c36b7c280fda89ae678cabfd8d906f4bde2216f`
- Files copied: 5614
- Text files inspected: 5592
- Text files transformed: 3430
- Residual project-identity hits outside LICENSE/NOTICE: 26

## Residual identity hits

- `.github/workflows/bootstrap-eve-to-kaf.yml`: 15
- `UPSTREAM.md`: 3
- `apps/docs/lib/integrations/data.ts`: 1
- `apps/docs/package.json`: 1
- `apps/docs/registry/extensions/link.ts`: 1
- `apps/docs/registry.json`: 1
- `pnpm-lock.yaml`: 3
- `pnpm-workspace.yaml`: 1

## Rename policy

Project-owned eve identity is renamed to Kaf. Project-owned GitHub URLs are redirected to TheHalfMoon/kaf.
Actual `@vercel/*` dependencies and Vercel provider/service names remain intact because renaming them would break runtime behavior.
Apache-2.0 LICENSE is copied byte-for-byte from upstream; upstream NOTICE is retained verbatim beneath Kaf attribution.
Third-party package coordinates are preserved when they are not owned by Kaf.
