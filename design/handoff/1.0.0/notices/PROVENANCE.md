# Provenance of the Orcel design handoff assets

All artwork in this package was drawn for Orcel in the Orcel Design session (November 2026) and approved by the
founder as the People First identity (v5) on 18 November 2026. No stock art, icon library files or third-party
illustrations are included.

| Asset | Origin |
|---|---|
| The figure (vermilion person mark) | Original vector, master R13 and small-size cut R13s, drawn on a 100-unit grid. It stays close to the common head-and-shoulders profile form; the squircle head, flat baseline feet and word-matched stroke weight are Orcel's. |
| Lowercase `orcel` wordmark | Outlined from Inter Display (opsz 32) weight 600, tracking -3%, from the font's own outlines (2048 units per em), then fixed as vector paths. Inter is licensed under the SIL Open Font License 1.1 (see OFL-Inter.txt); the OFL permits outlining glyphs for a logo. No font file ships in this package. |
| Brand SVGs in `assets/brand/` | Byte-identical copies of the output of `scripts/sync-brand.mjs` in PR #811 (TheHalfMoon/Orcel), which embeds the figure, wordmark and product icon paths above. |
| Product icons (Orcel, Browser, Agent, MCP, Cluster) | Original vectors on a 1024 grid, founder-approved colours. |
| UI icons in `assets/ui-icons/` | Original 24-grid line icons drawn for Orcel (1.75 stroke, round caps). Drawn to sit beside Lucide, but no Lucide path data is copied. |
| Brush character and gouache illustrations in `assets/illustrations/` | Original vector artwork with SVG filters (turbulence and displacement) for the brush and paint texture. No raster images. |
| Platform icons in `icons/` | Rendered from `assets/brand/orcel-app-icon.svg` (and `orcel-lockup-black.svg`, `orcel-social-dark.svg`) with sharp and Microsoft Edge; never redrawn per size. Apple touch and MSIX tiles use the same artwork full-bleed on the same ivory. |
| Typefaces named in tokens | Inter, Instrument Serif, Geist Mono: SIL Open Font License 1.1; licences in this folder. Fonts are loaded by the apps (next/font at build time, or bundled locally in Tauri), not shipped here. |

Trademark: no trademark search or clearance has been performed for the name, figure or wordmark.
