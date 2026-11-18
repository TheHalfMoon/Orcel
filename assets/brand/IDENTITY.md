# Orcel — identity v5, "People first"

Edition: v5, founder-approved design, 18 November 2026. Supersedes the November 2026 Night Window identity (v4), the Orca Eye identity and the October 2026 Signal identity, which remain in Git history.

## Concept
One person. Many agents. Orcel's primary mark is a vermilion human figure beside a lowercase black wordmark: a person, then a name. The figure is the person in control; the agents act on their computer only with their yes. The editorial voice is painterly: brush figures and gouache scenes in the brand colours.

## Source geometry and palette
All editable vector geometry is built by scripts/sync-brand.mjs from the ORCEL constant, the FIGURE path, the WORD path and the ICONS table.

- Figure (master R13), on a 100 grid with the baseline at y = 100: a squircle head (corner squareness 0.64, rhyming with Inter's o) on shoulders with radius 27% that round into flat feet cut on the baseline; stroke 11.5% of the figure height, matching the wordmark's stem weight. A heavier small cut exists for 16-24 px in the design package.
- Wordmark: lowercase "orcel" in Inter Display (opsz 32) weight 600, tracking -3%, outlined in font units (2048/em). Inter is licensed under the SIL Open Font License.
- Horizontal lockup: the figure is exactly as tall as the l, set 0.26 of that height before the word.
- Product icons, 1024 grid: Orcel (vermilion figure on ivory), Orcel Browser (ink figure on an orange disc in an ink ring), Orcel Agent (one person connected to two agents, vermilion on ivory), Orcel MCP (ivory hub on navy), Orcel Cluster (red #C8102E dots joined by ink lines on sky).

| Role | Colour |
| --- | --- |
| Vermilion, the figure and actions | #DB2532 |
| Ink, the wordmark and text | #141414 |
| Deep Navy, dark surfaces | #182437 |
| Cobalt, illustration | #2354D4 |
| Orange, Browser and illustration | #F5724D |
| Sky, Cluster and brush washes | #BFD8F7 |
| Ivory, the page | #F7F3EB |

Red and blue never sit on each other as text or icons. No shadows, gradients or effects on any mark. Keep half the figure height clear on every side. Never retype the wordmark.

Type: Inter for the wordmark (Display 600) and interface, Instrument Serif for editorial headlines, Geist Mono for evidence. The website self-hosts Latin subsets at build time; their SIL Open Font License texts are published in apps/web/public/fonts.

## Logo variants and file mapping
- assets/brand/orcel-mark-red.svg: the vermilion figure (website mark).
- assets/brand/orcel-o-white.svg and orcel-o-black.svg: the figure in white and ink (historical file names retained for consumers).
- assets/brand/orcel-wordmark-white.svg and orcel-wordmark-black.svg: outlined wordmark.
- assets/brand/orcel-lockup-black.svg (primary, on light) and orcel-lockup-white.svg (on dark): horizontal logo.
- assets/brand/orcel-lockup-stacked-black.svg and orcel-lockup-stacked-white.svg: stacked arrangements.
- assets/brand/orcel-readme-lockup.svg: ivory-backed README logo for both GitHub colour themes.
- assets/brand/orcel-app-icon.svg: the Orcel application icon, favicon and distribution tile. orcel-app-icon-light.svg: the reversed icon, white figure on vermilion (historical file name retained).
- assets/brand/orcel-icon-browser.svg, orcel-icon-agent.svg, orcel-icon-mcp.svg, orcel-icon-cluster.svg: product icons. orcel-accent-icon.svg carries the Browser icon.
- assets/brand/orcel-social-dark.svg and orcel-social-light.svg: social previews.
- assets/brand/orcel-monogram-pattern.svg: a field of figures, one in twelve in vermilion. The old orcel-orbit-pattern path is retained only for link compatibility.

These SVGs are synchronized to apps/web/public/brand, apps/web/app/icon.svg, distribution/openai/assets/logo.svg, and distribution/codex/orcel/assets/logo.svg. Screen-reader visible identity is Orcel. Decorative repeated artwork must not be read as extra text.

## Reproduction and release boundaries
From the repository root run in order:
1. node scripts/sync-brand.mjs
2. node scripts/sync-brand.mjs --check
3. npm ci --prefix apps/web --ignore-scripts --no-audit --no-fund
4. node scripts/render-brand.mjs
5. python scripts/export-brand.py
6. npm run web:test
7. npm run web:typecheck
8. npm run web:build

This produces the versioned Orcel-Identity-Kit-v5.zip, raster sizes, favicon and SHA-256 asset manifest on the qualified GitHub Pages workflow. Product tagline remains Your computer, your terms.

The figure is a widely used head-and-shoulders form; its refinements make it Orcel's, but it offers limited exclusivity. No trademark clearance has been performed. Do not change previous Git history, published releases, product runtime, security boundaries or agent capabilities. Prior identities remain as historical Git evidence. Orcel claims no affiliation with external design agencies or competitors.
