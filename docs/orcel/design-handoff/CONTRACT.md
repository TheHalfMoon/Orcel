# Design handoff contract (engineering side)

Status: ADOPTED by engineering as the intake contract, 2026-11-18. It adds no capability, changes no visual asset and
grants no authority. The Orcel Design session owns identity, assets, tokens and visual design; engineering owns this
contract, the checker and the wiring into the applications.

Machine-readable parts:

- `docs/orcel/design-handoff/manifest.schema.json`: the manifest schema (JSON Schema 2020-12).
- `scripts/check-design-handoff.mjs`: validates a package against the schema and the rules below. Offline and
  deterministic: it reads only the package folder and, with `--repo`, the repository's Rust sources.
- `scripts/check-design-handoff.test.mjs`: node:test tests over a synthetic package built from
  `scripts/fixtures/design-handoff/source/` (grey squares and neutral greys, clearly marked as not Orcel material).

## 1. Where things stand today

This contract is identity-neutral. It records the current state without changing it.

- **Live identity: v4, the Night Window** (founder-selected 17 November 2026, a Halfmoon product). Every brand SVG is
  generated in code by `scripts/sync-brand.mjs` from the `ORCEL` palette constant and the outlined `WORD` path, and
  written to 34 destinations (`assets/brand/`, `apps/web/public/brand/`, `apps/web/app/icon.svg`,
  `distribution/openai/assets/logo.svg`, `distribution/codex/orcel/assets/logo.svg`). `node scripts/sync-brand.mjs
  --check` fails on any byte of drift; CI and the Pages workflow run it, and `scripts/check-current-identity.mjs`
  runs it too. Guidelines: `assets/brand/IDENTITY.md`. Assertions: `apps/web/tests/brand.test.mjs`,
  `apps/web/tests/site.test.mjs`.
- **Proposed identity: ORCEL CUT, labelled "v3, proposed, awaiting founder approval"** (2026-11-18). It is described
  by the `orcel-brand-master` and `orcel-visual-qa` skills, which live in the founder's local checkout under
  `.claude/skills/` and are **not tracked in Git**. Its full package (`ORCEL_CUT_v3_Master_Package`) is outside the
  repository. Note the numbering: the proposed CUT "v3" is newer than the live "v4". Until an approved handoff
  package says otherwise, v4 stays live and nothing here treats CUT as production.
- No binary brand file (PNG, ICO, ICNS) is committed. `scripts/render-brand.mjs` (Sharp) and `scripts/export-brand.py`
  build PNG exports, `orcel-favicon.ico` and the identity kit at Pages build time.

Surfaces that consume design today:

| Surface | Stack | Styling today | Constraints that matter to Design |
|---|---|---|---|
| Website, `apps/web` | Next.js 16, static export (`output: "export"`), GitHub Pages with an optional base path | `app/globals.css` `:root` custom properties (dark only, `color-scheme: dark`), `app/brand/brand.css` with literal colours, fonts via `next/font` in `app/layout.tsx` (Bricolage Grotesque 600, Geist, Geist Mono, Instrument Serif; downloaded at build and self-hosted, OFL notices in `public/fonts/`) | **No Tailwind** in the repository. Two width breakpoints in CSS (960 px, 560 px) and a `prefers-reduced-motion` block that removes all transitions. Social card PNG is rendered at build from the SVG. |
| Control Room, `apps/orcel-control-room` | Tauri 2 shell (`src-tauri`) plus a TypeScript view compiled from `src/view/*.ts` into `src-tauri/ui/js` | `src-tauri/ui/style.css`, its own palette (light and dark from the system, `forced-colors` respected, logical properties for RTL), system fonts | CSP is `style-src 'self'; font-src 'self'; img-src 'self'`: no inline styles, no remote fonts or images. `bundle.active` is false and there is no `icons/` folder yet. `src/view/a11y.test.ts` asserts 4.5:1 text contrast in both schemes. Read-only window. |
| Desktop preview, `apps/orcel-desktop-preview` | WPF, .NET Framework, `src/Program.cs` | Colours and layout in C# | Windows-native accessibility (UIA, high contrast). Consumes no web tokens today. |
| Orcel Browser | SG-000135; the human browser UI is work packet OB-10 (BrowserOS-based build, packaging, installer), last in the grain | Not built. `apps/orcel-browser-worker` is headless and has no UI. | Comes later; the package should still name browser screens so OB-10 starts from approved references. |

Approval and consent prompts are **not** design surfaces: orceld raises them through the operating system (Windows
message box, Windows Hello). The Design session does not restyle them, and no app UI may imitate them.

## 2. The package

One package per version, delivered as a pull request from a branch named `design/handoff-<version>` that adds exactly
one folder:

```
design/handoff/<version>/          version = semantic version, equal to manifest.version
  manifest.json                    validated by manifest.schema.json
  assets/                          SVG only
  icons/web/  icons/windows/  icons/macos/  icons/tauri/
  tokens/tokens.json               the single DTCG token source
  components/<name>.md             one spec per shared component
  screens/                         reference screens (PNG), never shipped
  notices/                         licences and provenance for fonts, outlines, any third-party material
```

Rules for the folder:

- Every file is listed in the manifest with its SHA-256, and nothing unlisted may be present.
- Paths are relative, forward-slash, inside the folder; no links, URLs, parent segments or absolute paths.
- Packages are immutable once merged. A fix is a new version that `supersedes` the old one.
- Git must not rewrite line endings inside `design/handoff/` (`.gitattributes` marks it `-text`), so hashes hold.

### 2.1 SVG assets

Each entry has `path`, `kind` (`mark`, `wordmark`, `lockup`, `app-tile`, `pattern`, `social`, `illustration`,
`ui-icon`), `sha256`, `background` (`dark`, `light`, `any`) and optionally `destination`, the existing repository file
it replaces (for example `assets/brand/orcel-o-white.svg`), so the 34 sync destinations keep their names.

Every SVG must be static, self-contained vector art:

- root `<svg>` with the SVG namespace and a numeric `viewBox`; an accessible name (`aria-label` or `<title>`);
- no `<script>`, event-handler attributes, `javascript:` URLs, `<foreignObject>`, DOCTYPE or entity declarations;
- no external references: `href` and `url()` may point only at `#fragments`; no `@import`; no embedded raster `<image>`;
- marks, wordmarks, lockups and app tiles are outlined: no live `<text>` (social cards may use text);
- at most 512 KiB.

### 2.2 Icons

Required roles per platform; `check-design-handoff.mjs` decodes every file and checks its real pixel sizes.

| Platform | Role | Format and size |
|---|---|---|
| web | `favicon-svg` | SVG (becomes `apps/web/app/icon.svg`) |
| web | `favicon-ico` | ICO holding 16, 32, 48 |
| web | `apple-touch-icon` | PNG 180×180 |
| web | `icon-192`, `icon-512` | PNG 192×192, 512×512 |
| web | `social-card` | PNG 1200×630 (Open Graph and Twitter card) |
| windows | `app-ico` | ICO holding 16, 24, 32, 48, 64, 256 |
| windows | `msix-square44`, `msix-square44-scale200` | PNG 44×44, 88×88 |
| windows | `msix-square150`, `msix-square150-scale200` | PNG 150×150, 300×300 |
| windows | `msix-wide310` | PNG 310×150 |
| windows | `msix-store`, `msix-store-scale200` | PNG 50×50, 100×100 |
| macos | `app-icns` | ICNS holding PNG images at 16, 32, 64, 128, 256, 512, 1024 |
| tauri | `tauri-32`, `tauri-128`, `tauri-128-2x`, `tauri-icon` | RGBA PNG 32, 128, 256, 512 (Tauri rejects non-RGBA icons) |
| tauri | `tauri-ico`, `tauri-icns` | ICO and ICNS as for Windows and macOS |

Further roles may be added; they are hash-checked and decoded but have no size rule. PNGs are 8-bit. Each icon must
stay legible at 16 px (the identity's minimum size) and be exported from the approved vector, never redrawn per size
unless the spec says so (small-size variants are listed as their own roles).

### 2.3 Design tokens

One file, `tokens/tokens.json`, in the Design Tokens Community Group format: groups of tokens with `$value` and
`$type` (inherited from the group), aliases written as `{group.token}`. Supported types: `color` (`#RRGGBB`,
`#RRGGBBAA` or a DTCG `srgb` object), `dimension` (px or rem), `fontFamily`, `fontWeight`, `duration` (ms or s),
`cubicBezier`, `number`. Names are lowercase kebab-case. Font tokens name families only; font files travel as
assets with their licence in `notices/`.

Required tokens (the checker refuses a package without them):

- `theme.dark.color.*` and `theme.light.color.*`, the same names in both, at least: `background`, `surface`,
  `surface-raised`, `border`, `border-strong`, `text`, `text-muted`, `accent`, `on-accent`, `danger`, `focus`,
  `success`, `warning`;
- `font.family.display`, `font.family.text`, `font.family.mono`;
- `size.radius.base`, `size.content-max`;
- `breakpoint.compact`, `breakpoint.medium`;
- `motion.duration.fast`, `motion.duration.base`, `motion.duration.slow`, `motion.duration.reduced` (must be 0 ms),
  `motion.easing.standard`.

Mapping to the code that exists today (current values in parentheses for orientation only; the package decides):

| Token | Website `apps/web/app/globals.css` | Control Room `src-tauri/ui/style.css` |
|---|---|---|
| `color.background` | `--bg` (#090C12) | `--background` |
| `color.surface` | `--surface` | `--surface` |
| `color.surface-raised` | `--surface-2` | none yet |
| `color.border` | `--line` | `--line` |
| `color.border-strong` | `--line-strong` | none yet |
| `color.text` | `--text` | `--text` |
| `color.text-muted` | `--muted` (also `--muted-2`, `--muted-3` for further steps) | `--muted` |
| `color.accent` | `--accent-a` (also `--accent-b`, `--accent-c`, `--accent-soft`) | none yet |
| `color.on-accent` | `--on-accent` | none yet |
| `color.danger` | `--danger` | `--bad` |
| `color.focus` | focus outlines use `--accent-a` today | `--focus` |
| `color.success` | none yet | `--good` |
| `color.warning` | none yet | `--withheld` |
| `font.family.display` / `text` / `mono` | `--display` / `--sans` / `--mono` (and `--serif`) | system fonts today |
| `size.radius.base` | `--radius` (16px) | literal radii |
| `size.content-max` | `--max` (1240px) | none |
| `breakpoint.compact` / `medium` | `@media (max-width: 560px)` / `(max-width: 960px)` | grids shrink without breakpoints |
| `motion.duration.base` | the 160 ms transitions | none |

Extra colour steps (for example `--muted-2`) are added as extra tokens under `theme.*.color` with any kebab-case name.
The website is dark only today, so it uses `theme.dark` until a light website theme is approved; the Control Room uses
both. **Tailwind:** none of the apps uses Tailwind. If one adopts it later, its theme reads the generated CSS custom
properties (`colors: { background: "var(--orcel-color-background)" }` and so on); tokens are never copied into a
Tailwind config by hand.

### 2.4 Component specifications

One Markdown file per shared component, listed with the states it defines and the surfaces it applies to
(`website`, `control-room`, `desktop`, `browser`, `shared`). Each spec must have these sections (the checker looks for
the headings):

- **States**: default, hover, focus, active, disabled, loading, error (plus selected or empty where they apply), each
  with token references, never raw values. `default` and `focus` are mandatory.
- **Keyboard**: the full keyboard path (Tab order, Enter, Space, Escape, arrow keys where relevant).
- **Accessibility**: role, accessible name, focus indicator, hit area, behaviour at 200% zoom, in forced colours and
  in right-to-left layout.
- **Motion**: which duration and easing tokens apply, and what happens under reduced motion.

Responsive behaviour is stated against `breakpoint.compact` and `breakpoint.medium`, and must work from 320 CSS px
wide (website) and from the Control Room's minimum window (480×320) without horizontal scrolling.

### 2.5 Accessibility requirements (WCAG 2.2 AA)

- Contrast, checked from the tokens in both themes: text 4.5:1 (`text`, `text-muted`, `danger`, `success`, `warning`
  on `background`, `text` and `text-muted` on `surface`, `text` on `surface-raised`, `on-accent` on `accent`); 3:1
  for non-text and focus (`accent` on `background`, `focus` on `background` and `surface`). The manifest's
  `contrastPairs` adds pairs; it cannot remove the built-in ones. Translucent colours are composited first.
- Focus is always visible (2.4.7, 2.4.11): a focus indicator of at least 2 CSS px using `color.focus`, never removed
  without a replacement.
- Every function works by keyboard alone, with no keyboard trap; target size at least 24×24 CSS px (2.5.8).
- Forced colours and high contrast keep every control and state distinguishable; colour is never the only signal.
- Right-to-left and 200% zoom are supported; no text inside raster images except the social card.

### 2.6 Motion

- Durations come from `motion.duration.*`, at most 1000 ms each (the checker enforces it); easing from
  `motion.easing.*`.
- Under `prefers-reduced-motion: reduce`, every transition and animation uses `motion.duration.reduced` (0 ms); no
  meaning may depend on motion. Nothing flashes more than three times a second.
- A once-per-session reveal or loading animation must be listed in a component spec with its reduced-motion form.

### 2.7 Screens

Reference PNGs per surface (`website`, `control-room`, `desktop`, `browser`) and theme, at the widths they were drawn
for. They show intent; engineering never ships them and never uses them directly as visual-regression baselines.
Baselines are always rendered from code (section 3).

## 3. Acceptance checks engineering runs

A package is accepted only when all of these pass on the integration pull request.

| Check | Tool | State |
|---|---|---|
| Manifest schema, version equals folder, approval present when approved | `node scripts/check-design-handoff.mjs design/handoff/<v> --integrate` | in repository |
| Every file listed and hash-matched, no links, nothing unlisted | same | in repository |
| SVG lint: no scripts, handlers, external refs, raster, DOCTYPE; outlined brand art; accessible name | same | in repository |
| Icon completeness: every role, real decoded sizes, ICO/ICNS contents, RGBA for Tauri | same | in repository |
| Tokens: required names, both themes alike, aliases resolve without cycles, valid values, motion limits | same | in repository |
| Token contrast, WCAG 2.2 AA, both themes | same | in repository |
| Component specs have States, Keyboard, Accessibility and Motion | same | in repository |
| Presentation isolation (section 4) | `node scripts/check-design-handoff.mjs --repo .` | in repository |
| Brand destinations byte-identical to the generator | `node scripts/sync-brand.mjs --check` | in repository (CI, Pages) |
| Identity record and generator agree | `node scripts/check-current-identity.mjs` | in repository (CI) |
| Website tests, typecheck, static build | `npm run web:test`, `npm run web:typecheck`, `npm run web:build` | in repository |
| Control Room contrast and view build | `npm --prefix apps/orcel-control-room test` (`a11y.test.ts`, `build.test.ts`) | in repository |
| Visual regression: Playwright screenshots of the built site and the Control Room view at 320, 768 and 1280 px, dark and light, compared with committed baselines rendered from code | planned | **not in repository**: needs the `@playwright/test` dev dependency and a browser download, which need founder approval |
| Automated accessibility: axe-core on the same pages, zero serious or critical violations | planned | **not in repository**: needs `axe-core` (or `@axe-core/playwright`), founder approval |
| Human visual review at actual size | `orcel-visual-qa` skill (local) | process step; passing tests is not proof of good design |

The checker reports problems with stable codes (`SVG_SCRIPT`, `ICON_SIZE`, `TOKEN_CONTRAST`, `NOT_APPROVED`, ...) so
the Design session can fix a package without reading the code. Without `--integrate` a draft or review package is
checked and reported as not eligible; with it, anything but `approved` fails.

## 4. Presentation code never reaches privileged code

- Rust services and security logic (`crates/*`, including orceld, the authority, approval, policy, audit and
  provider crates, and the Tauri shell's Rust in `apps/*/src-tauri/src`) never import, embed (`include_str!`,
  `include_bytes!`) or read SVG, CSS, HTML, images, fonts, token files or anything under `design/handoff/`.
  `check-design-handoff.mjs --repo` enforces this and passes on main today.
- The Tauri shell may serve its own static `ui/` folder through `frontendDist`; that is the presentation layer's only
  entry point, and its CSP stays as strict as it is now.
- Design changes never alter policy, approval, authority, audit, IPC contracts, capabilities or CSP. A pull request
  that mixes a design integration with any of those is split.
- Generated token files are build outputs of the presentation layer only. No security decision may depend on a
  colour, label or asset.

## 5. Approval and versioning

- `status` is `draft`, `review`, `approved` or `withdrawn`. Only `approved` with an `approval` block
  (`approvedBy`: `founder` or `design-session`; `approvedOn`; `record`, a link to where the approval is written down)
  is integrated. A change to the identity itself (mark, wordmark, palette) needs `approvedBy: founder`.
- Engineering never takes assets from a draft board, a canvas, a chat attachment, a screenshot or an unmerged branch.
  A board reference in `source.reference` is provenance only.
- Versions follow semantic versioning: patch for a corrected export with the same design, minor for added assets,
  components or tokens, major for an identity change or removed or renamed tokens.
- `supersedes` names the approved version being replaced, so history stays linear.

## 6. Integration procedure

1. The Design session opens the `design/handoff-<version>` pull request with the package only. Engineering runs the
   checker; failures go back to the Design session with the error codes.
2. Once the package pull request is merged with `status: approved`, engineering opens one integration pull request
   from main that wires the package into the apps (section 8), updates `scripts/sync-brand.mjs` and
   `apps/web/tests/brand.test.mjs` when the identity changes, and records the package version in the commit message.
3. All checks in section 3 pass, then a human visual review. Pull requests are merged one at a time; the `release`
   environment is never approved or bypassed by an agent.

## 7. Rollback

- Every integration is one pull request; rollback is `git revert` of that merge, which restores the previous
  generator output, tokens and icons together. `sync-brand.mjs --check` and the web tests confirm the restored state.
- The previous package folder stays in `design/handoff/`; nothing is deleted when a package is superseded.
- A package found to be wrong after merge is marked `withdrawn` by a new commit to its manifest status only (the one
  permitted edit), and a corrected version follows.
- Released versions and published Pages artifacts are not rewritten; a rollback ships as a new release.

## 8. Integration plan per application (not implemented)

A small generator, `scripts/build-design-tokens.mjs` (to be written with the first approved package), reads
`tokens/tokens.json` and writes plain CSS custom properties named `--orcel-<group>-<name>` (for example
`--orcel-color-background`), one file per consumer, with a `--check` mode like `sync-brand.mjs`. Breakpoints cannot be
CSS variables inside media queries, so the generator writes them as constants into the generated files' comments and
the integration replaces the literal values in the media queries.

**Website (`apps/web`).**

- Tokens: generated `app/tokens.generated.css`, imported first in `app/layout.tsx`; the `:root` block in
  `app/globals.css` becomes aliases (`--bg: var(--orcel-color-background)` and so on, per the table in section 2.3),
  so the rest of the stylesheet is unchanged. `app/brand/brand.css` literals move to the same variables.
- Fonts: `next/font` declarations in `app/layout.tsx` follow `font.family.*`; licences go to `public/fonts/`.
- Brand SVGs: geometry ported into `scripts/sync-brand.mjs` (keeping all 34 destination names), or the generator
  changed to copy approved package files; either way `sync-brand.mjs --check` stays the gate.
- Icons: `app/icon.svg` (`favicon-svg`), `app/favicon.ico`, `app/apple-icon.png`, and the social card as
  `public/brand/orcel-social-dark.png`, which `layout.tsx` metadata and `.github/workflows/pages.yml` already
  reference. Today these PNG and ICO files are built at Pages time; the integration decides whether to keep rendering
  them (`render-brand.mjs`) or to take the approved exports.

**Control Room (`apps/orcel-control-room`).**

- Tokens: generated `src-tauri/ui/tokens.css` (both themes, `prefers-color-scheme`), linked from `ui/index.html` and
  `ui/start.html` before `style.css`; `style.css` keeps its variable names as aliases. `src/view/a11y.test.ts` reads
  the generated values so its contrast assertions follow the package.
- Fonts: system fonts stay unless the package ships font files; then they are copied into `src-tauri/ui/fonts/`
  (CSP `font-src 'self'`) with their notices, and the app-size budget is rechecked.
- Icons: the `tauri` roles go to `src-tauri/icons/` (`32x32.png`, `128x128.png`, `128x128@2x.png`, `icon.png`,
  `icon.ico`, `icon.icns`) with a `bundle.icon` list in `tauri.conf.json` when packaging is turned on; the Windows
  MSIX roles go with the Windows packaging work.

**Desktop preview (`apps/orcel-desktop-preview`).** WPF does not read CSS. If it is kept, the generator also writes a
XAML `ResourceDictionary` (or a C# constants file) from the same tokens, and `Program.cs` uses it instead of literal
colours; the `app-ico` icon becomes its window and executable icon.

**Orcel Browser UI (OB-10, later).** The BrowserOS-based human browser takes the `browser` screens and the shared
component specs, its own generated token file from the same source, and the `tauri`/`windows`/`macos` icon roles for
its installer. Its browser chrome is presentation only and follows section 4: the session broker, leases and policy
code never import it.

## 9. What engineering will not do

- Draw, redraw, recolour or "fix" an asset, token or layout; a problem goes back to the Design session.
- Integrate a draft, a board export, or anything without an approved manifest.
- Weaken a check to make a package pass. A rule change is a pull request to this contract and the checker, reviewed
  on its own.
