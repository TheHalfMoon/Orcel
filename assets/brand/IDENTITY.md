# Orcel — identity v4, a Halfmoon product

Edition: v4, founder-selected design, 17 November 2026. Supersedes the November 2026 Orca Eye identity and the October 2026 Signal identity, which remain in Git history.

## Concept
Orcel is a product of Halfmoon. Its mark is the Night Window: a desktop window that holds Halfmoon's half moon. The window is your computer; the half moon is what you choose to let through. The half moon comes from Halfmoon's shape grammar (full, half, crescent, C, horizon), so Orcel belongs to the family without borrowing the parent's crescent.

The crescent belongs to Halfmoon alone. Orcel uses it only in the endorsement line "a Halfmoon product".

The mark doubles as a status light in the tray: an empty window when idle, a dashed lavender moon while a request waits for you, a solid lavender moon during a session you approved, and a red moon after an emergency revoke.

## Source geometry and palette
All editable vector geometry is built by scripts/sync-brand.mjs from the ORCEL constant and the WORD path.

- Night Window, on a 256 grid: frame 200×176 at (28, 40), corner 52, stroke 22; title rule from (66, 82) to (102, 82), stroke 16, round caps; half moon r 50 centred on (128, 146) with its flat edge on the centre axis.
- Moon Tile, the solid form for app icons: rounded tile 208×196 at (24, 30), corner 56, with the title slot and the half moon cut out (even-odd).
- Wordmark: lowercase "orcel" in Bricolage Grotesque SemiBold (the Halfmoon 600 instance), tracking −22/1000 as in the Halfmoon wordmark, outlined. Canvas 620×256, placed with translate(16 223) scale(.28). No per-pair kerning is applied.
- Horizontal lockup: canvas 940×256, mark at x = 0, wordmark at x = 300.

| Role | Colour |
| --- | --- |
| Midnight, ground and app tile | #090C12 |
| White, mark on dark | #FFFFFF |
| Lunar, light surfaces | #F5F4F0 |
| Lavender, the moon and status | #A6ACE6 |
| Lavender deep, the moon on light | #5A61B8 |
| Red, deny and revoke only | #B31B1B |

Proportion follows Halfmoon: about 60% Midnight and white, 30% Lunar and silver, 8% Lavender, 2% Red. No shadows, gradients or extra cuts in the mark. Keep one moon-width clear on every side. Minimum size is 16 px, using the solid tile.

Type follows Halfmoon: Bricolage Grotesque for display, Geist for text, Geist Mono for evidence, and Instrument Serif for one statement per surface. The website self-hosts Latin subsets at build time; their SIL Open Font License texts are published in apps/web/public/fonts.

## Logo variants and file mapping
- assets/brand/orcel-o-white.svg and orcel-o-black.svg: the Night Window mark (historical file name retained for consumers).
- assets/brand/orcel-wordmark-white.svg and orcel-wordmark-black.svg: outlined wordmark.
- assets/brand/orcel-lockup-white.svg and orcel-lockup-black.svg: primary horizontal logo.
- assets/brand/orcel-readme-lockup.svg: dark-background README logo for both GitHub colour themes.
- assets/brand/orcel-app-icon.svg and orcel-app-icon-light.svg: Moon Tile favicon and distribution tiles.
- assets/brand/orcel-accent-icon.svg: midnight mark on a lavender tile, for avatars.
- assets/brand/orcel-lockup-stacked-white.svg and orcel-lockup-stacked-black.svg: stacked arrangements.
- assets/brand/orcel-social-dark.svg and orcel-social-light.svg: social previews with the endorsement line.
- assets/brand/orcel-monogram-pattern.svg: Halfmoon's half moon as a phase field, one in twelve in lavender. The old orcel-orbit-pattern path is retained only for link compatibility.

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

This produces the versioned Orcel-Identity-Kit-v4.zip, raster sizes, favicon and SHA-256 asset manifest on the qualified GitHub Pages workflow. Product tagline remains Your computer, your terms.

Do not change previous Git history, published releases, product runtime, security boundaries or agent capabilities. Prior identities remain as historical Git evidence. Source branch and PR alone are not proof of Pages publication. Orcel claims no affiliation with external design agencies or competitors.
