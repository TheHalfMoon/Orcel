# Orcel — Signal identity

Edition: Signal version 2, founder-approved design, October 2026.

## Concept
A custom lowercase Orcel typographic identity with white geometric letterforms on a near-black background. The recognition accent is the orange upper terminal of the final lowercase l. The founder's final approved image has one small deliberate lower-left opening inside the o's circular stroke. The c remains continuous with its normal right-side aperture; preserve the original composition and the orange l terminal. Do not reinterpret the opening as letter spacing.

The standalone square icon is a white C-shaped form with a curved orange arc at its upper-right and a small white teardrop, matching the founder's final visual reference. It is not a previous orbital, OI or nested monogram. The primary full typographic mark is the word itself.

## Source geometry and palette
All original editable vector geometry is built by scripts/sync-brand.mjs from the SIGNAL constant. Wordmark canvas: 860x256. Letter o is a 343-degree open heavy circular stroke with a deliberately slanted lower-left opening; r is a continuous filled stem/shoulder; c is uninterrupted open-sided curved geometry; e uses a structured counter and crossbar; l is a single rounded filled vertical bar with the top section orange. The glyphs contain no typeset text, downloaded fonts or third-party artwork.

| Role | Color |
| --- | --- |
| Main background | #080808 |
| Primary glyphs | #FFFFFF |
| Recognition terminal | #FF813E |
| Charcoal supporting surface | #17191B |
| Light inverse surface | #F5F6F7 |
| Supporting silver | #D9DDE1 |

No blue/purple gradient is used in the approved primary mark. No shadows, 3D effects, glow, font files, or artificially disconnected strokes. Typography for adjacent editorial text is the existing web system sans-serif stack. The actual wordmark is hand-constructed vector artwork.

## Logo variants and file mapping
- assets/brand/orcel-wordmark-white.svg and orcel-wordmark-black.svg — main brand.
- assets/brand/orcel-lockup-white.svg and orcel-lockup-black.svg — primary website horizontal wordmark.
- assets/brand/orcel-readme-lockup.svg — official dark-background README logo, same vector wordmark in both GitHub color themes.
- assets/brand/orcel-o-white.svg and orcel-o-black.svg — new Signal icon, historical URL name retained for consumers.
- assets/brand/orcel-app-icon.svg and orcel-app-icon-light.svg — favicon and distribution tiles.
- assets/brand/orcel-lockup-stacked-white.svg and orcel-lockup-stacked-black.svg — stacked arrangements.
- assets/brand/orcel-social-dark.svg and orcel-social-light.svg — social previews.
- assets/brand/orcel-monogram-pattern.svg — Signal motif; old orcel-orbit-pattern path retained only for link compatibility.

These SVGs are synchronized to apps/web/public/brand, apps/web/app/icon.svg, distribution/openai/assets/logo.svg, and distribution/codex/orcel/assets/logo.svg. Preserve generous clear space around the entire wordmark and use the compact icon for 16-32px surfaces only after a pixel-level inspection. Screen-reader visible identity is Orcel. Decorative repeated artwork must not be read as extra text.

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

This produces the new versioned Orcel-Identity-Kit-v2.zip, raster sizes, favicon and SHA-256 asset manifest on the qualified GitHub Pages workflow. Product tagline remains Your computer, your terms. A clear signal for what's next is an editorial design phrase, not a software availability claim.

Do not change previous Git history, published releases, product runtime, security boundaries or agent capabilities. Prior identity proposals remain as historical Git evidence. Source branch and PR alone are not proof of Pages publication. Orcel claims no affiliation with external design agencies or competitors.
