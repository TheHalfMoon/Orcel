# Keycap

Shows a keyboard shortcut.

Surfaces: shared

## Anatomy

- Box 18 high (24 in docs), radius size.radius.xs, 1px color.border-strong with a heavier bottom edge.
- Key name in Windows terms: Ctrl, Shift, Alt, Enter, Esc.

## States

- **default**: color.surface with color.text-muted.
- **hover**: Does not apply
- **focus**: Does not apply; not focusable.
- **active**: Does not apply
- **disabled**: Does not apply
- **loading**: Does not apply
- **error**: Does not apply
- **selected**: Inside a tooltip: transparent with color.text-inverse at reduced emphasis.

## Keyboard

Not in the tab order.

## Accessibility

- Role: kbd.
- Accessible name: Spelled-out key names when the keycap is the only text, e.g. "Control K".
- Focus indicator: 2px outline in color.focus with a 2px offset on :focus-visible (offset -2px inside lists and scroll areas); on color.shadow-bg the ring uses color.shadow-accent.
- Hit area: Not a target.
- 200% zoom: Reflows; labels wrap rather than truncate; no horizontal scrolling.
- Forced colours: Keeps a visible border or outline in CanvasText/ButtonText; state is also carried by words or icons, never colour alone.
- Right-to-left: Built with logical properties (padding-inline, margin-inline-start, inset-inline); icons that imply direction mirror.

## Motion

None. Under prefers-reduced-motion every transition and animation uses motion.duration.reduced (0 ms); no meaning depends on motion.

## Responsive

Hidden below breakpoint.compact on touch layouts.

## Implementation

Native kbd.
