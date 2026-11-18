# Provenance of the Orcel design handoff assets

All artwork in this package was drawn for Orcel in the Orcel Design session (November 2026) and approved by the
founder as the People First identity (v5) on 18 November 2026. No stock art, icon library files or third-party
illustrations are included. The package is text only: SVG, JSON, Markdown and plain text.

| Asset | Origin |
|---|---|
| The figure (vermilion person mark) | Original vector, master R13 and small-size cut R13s, drawn on a 100-unit grid. It stays close to the common head-and-shoulders profile form; the squircle head, flat baseline feet and word-matched stroke weight are Orcel's. |
| Lowercase `orcel` wordmark | Outlined from Inter Display (opsz 32) weight 600, tracking -3%, from the font's own outlines (2048 units per em), then fixed as vector paths. Inter is licensed under the SIL Open Font License 1.1 (see OFL-Inter.txt); the OFL permits outlining glyphs for a logo. |
| Social card text | The two lines on `orcel-social-dark.svg` and `orcel-social-light.svg` are outlined from Inter weight 400 (text optical size) at the size, tracking and position of the original live text, so every renderer draws the same card. |
| Brand SVGs in `assets/brand/` | Byte-identical copies of the output of `scripts/sync-brand.mjs` in PR #811 (TheHalfMoon/Orcel), which embeds the figure, wordmark, product icon and social text paths above. |
| Product icons (Orcel, Browser, Agent, MCP, Cluster) | Original vectors on a 1024 grid, founder-approved colours. |
| UI icons in `assets/ui-icons/` | Original 24-grid line icons drawn for Orcel (1.75 stroke, round caps). Drawn to sit beside Lucide, but no Lucide path data is copied. |
| Brush character and gouache illustrations in `assets/illustrations/` | Original vector artwork with SVG filters (turbulence and displacement) for the brush and paint texture. No raster images. Long path data is wrapped at command boundaries; the rendering is unchanged. |
| Platform icons | Not stored in the package. `icons/web/icon.svg` is a copy of `assets/brand/orcel-app-icon.svg`; every PNG, ICO and ICNS role is a generated entry that `scripts/render-design-handoff.mjs` builds in CI from the listed brand SVGs with the recipes `render`, `full-bleed` (the rounded tile replaced by a square of the plate colour) and `centered-on-plate`. Never redrawn per size. |
| Reference screens | Not stored in the package. Reference renders of the design boards live outside the repository (the design canvas and the design session's `renders/final`). Visual baselines come from the real applications. |
| Typefaces named in tokens | Inter, Instrument Serif, Geist Mono: SIL Open Font License 1.1; licences in this folder. Fonts are never committed: the website loads them with next/font at build time; the Control Room keeps system fonts unless a build step fetches pinned, hash-checked files. |

Trademark: no trademark search or clearance has been performed for the name, figure or wordmark.
