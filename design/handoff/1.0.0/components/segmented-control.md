# Segmented control

Switches between 2 to 4 views of the same data.

Surfaces: control-room|desktop|browser

## Anatomy

- Track color.sunken, radius size.radius.base, padding 2.
- Segments 28 high with optional icon.

## States

- **default**: Segments color.text-muted.
- **hover**: color.text.
- **focus**: color.focus ring around the focused segment.
- **active**: color.hover while pressed.
- **disabled**: Segment color.text-subtle with a reason in its tooltip.
- **loading**: Does not apply
- **error**: Does not apply
- **selected**: color.surface with color.text and a small shadow.

## Keyboard

One tab stop; Left and Right move and select (mirrored in right-to-left); Home and End jump.

## Accessibility

- Role: radiogroup (Base UI ToggleGroup, single).
- Accessible name: Group label, e.g. "View".
- Focus indicator: 2px outline in color.focus with a 2px offset on :focus-visible (offset -2px inside lists and scroll areas); on color.shadow-bg the ring uses color.shadow-accent.
- Hit area: At least 24×24 CSS px; 32 by default in the Control Room, 40 on the website.
- 200% zoom: Reflows; labels wrap rather than truncate; no horizontal scrolling.
- Forced colours: Keeps a visible border or outline in CanvasText/ButtonText; state is also carried by words or icons, never colour alone.
- Right-to-left: Built with logical properties (padding-inline, margin-inline-start, inset-inline); icons that imply direction mirror.

## Motion

Thumb moves over motion.duration.base, motion.easing.standard. Under prefers-reduced-motion every transition and animation uses motion.duration.reduced (0 ms); no meaning depends on motion.

## Responsive

Icons only below breakpoint.compact, with aria-label per segment.

## Implementation

Base UI ToggleGroup.
