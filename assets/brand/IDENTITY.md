# Orcel — Orca Eye identity

Edition: Orca Eye, version 3, founder-selected design, November 2026. Supersedes the October 2026 Signal identity, which remains in Git history.

## Concept
Orcel sounds like orca: black and white, calm, watchful, the guardian nobody messes with. The mark is one circle with the orca's eye patch cut out of it. It is always a single color: white on dark surfaces, black on light or lime surfaces. Signal Lime belongs to actions (buttons, approval badges, highlights) and the accent tile, never inside the mark.

The wordmark is lowercase "orcel" set in Unbounded SemiBold (weight 600) with -40/1000 tracking, converted to outlines. The outlines ship as vector paths; no font file is distributed or required.

## Source geometry and palette
All editable vector geometry is built by scripts/sync-brand.mjs from the ORCA constant and the MARK and WORD paths.

- Mark, on a 256 grid: circle centered at 128,128 with radius 104; the eye patch is two curves from 60,136 to 206,82, rising about 20 degrees, cut with the even-odd fill rule.
- Wordmark: canvas 780x256. Outlines are stored in font units with the baseline at y=0 and placed with translate(24 222) scale(.25).
- Horizontal lockup: canvas 1100x256, mark at x=20, wordmark at x=316.

| Role | Color |
| --- | --- |
| Main background, ink | #080808 |
| Primary mark on dark | #FFFFFF |
| Signal Lime, action only | #D4FF3F |
| Charcoal supporting surface | #17191B |
| Light inverse surface | #F5F6F7 |
| Supporting silver | #D9DDE1 |

No shadows, outlines, gradients, glow, or lime inside the mark. Keep a quarter of the mark's width clear on every side. The smallest size is 16 px, for favicons.

Unbounded is licensed under the SIL Open Font License 1.1. Interface text on the website keeps its existing system sans-serif stack.

## Logo variants and file mapping
- assets/brand/orcel-o-white.svg and orcel-o-black.svg: the Orca Eye mark (historical file name retained for consumers).
- assets/brand/orcel-wordmark-white.svg and orcel-wordmark-black.svg: outlined wordmark.
- assets/brand/orcel-lockup-white.svg and orcel-lockup-black.svg: primary horizontal logo, mark and wordmark.
- assets/brand/orcel-readme-lockup.svg: dark-background README logo for both GitHub color themes.
- assets/brand/orcel-app-icon.svg and orcel-app-icon-light.svg: favicon and distribution tiles.
- assets/brand/orcel-accent-icon.svg: black mark on a Signal Lime tile, for avatars.
- assets/brand/orcel-lockup-stacked-white.svg and orcel-lockup-stacked-black.svg: stacked arrangements.
- assets/brand/orcel-social-dark.svg and orcel-social-light.svg: social previews.
- assets/brand/orcel-monogram-pattern.svg: the eye patch repeated, one in twelve in lime. The old orcel-orbit-pattern path is retained only for link compatibility.

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

This produces the versioned Orcel-Identity-Kit-v3.zip, raster sizes, favicon and SHA-256 asset manifest on the qualified GitHub Pages workflow. Product tagline remains Your computer, your terms.

Do not change previous Git history, published releases, product runtime, security boundaries or agent capabilities. Prior identities remain as historical Git evidence. Source branch and PR alone are not proof of Pages publication. Orcel claims no affiliation with external design agencies or competitors.
