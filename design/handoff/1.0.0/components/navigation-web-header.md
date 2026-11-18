# Web header

Top navigation of the website, with the one red download button.

Surfaces: website

## Anatomy

- Bar 72 (60 on phone), color.background, bottom hairline, sticky.
- Lockup.
- Links (type.body-s, weight 500).
- Sign in (ghost) and Download for Windows (primary).

## States

- **default**: Links color.text-muted; current link color.text.
- **hover**: Link color.text.
- **focus**: color.focus ring on links and buttons.
- **active**: Link color.text.
- **disabled**: Does not apply
- **loading**: Does not apply
- **error**: Does not apply
- **selected**: Current page link color.text with aria-current=page.

## Keyboard

Skip link is the first tab stop. Then lockup, links, Sign in, Download. On phone the menu button opens a sheet; focus moves into it; Esc closes.

## Accessibility

- Role: banner containing navigation.
- Accessible name: "Main" for the navigation; the lockup is "Orcel home".
- Focus indicator: 2px outline in color.focus with a 2px offset on :focus-visible (offset -2px inside lists and scroll areas); on color.shadow-bg the ring uses color.shadow-accent.
- Hit area: At least 24×24 CSS px; 32 by default in the Control Room, 40 on the website.
- 200% zoom: Reflows; labels wrap rather than truncate; no horizontal scrolling.
- Forced colours: Keeps a visible border or outline in CanvasText/ButtonText; state is also carried by words or icons, never colour alone.
- Right-to-left: Built with logical properties (padding-inline, margin-inline-start, inset-inline); icons that imply direction mirror.

## Motion

Sheet slides in over motion.duration.base, motion.easing.enter. Under prefers-reduced-motion every transition and animation uses motion.duration.reduced (0 ms); no meaning depends on motion.

## Responsive

Below breakpoint.medium links collapse into the menu sheet; works from 320 with the lockup at its minimum width.

## Implementation

header and nav; Base UI Dialog for the phone sheet.
