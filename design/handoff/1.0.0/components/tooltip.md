# Tooltip

Names an icon button and shows its shortcut.

Surfaces: shared

## Anatomy

- Bubble 28 high, radius size.radius.sm, background color.text, label color.text-inverse.
- Optional keycap.

## States

- **default**: color.text with color.text-inverse.
- **hover**: Shown after a delay on hover of the trigger.
- **focus**: Shown when the trigger gets keyboard focus.
- **active**: Does not apply
- **disabled**: Explains why a control with aria-disabled cannot be used.
- **loading**: Does not apply
- **error**: Does not apply

## Keyboard

Appears on focus; Esc hides it without moving focus.

## Accessibility

- Role: tooltip.
- Accessible name: Duplicates the trigger's aria-label; never the only source of information.
- Focus indicator: 2px outline in color.focus with a 2px offset on :focus-visible (offset -2px inside lists and scroll areas); on color.shadow-bg the ring uses color.shadow-accent.
- Hit area: Not a target; the trigger is.
- 200% zoom: Reflows; labels wrap rather than truncate; no horizontal scrolling.
- Forced colours: Keeps a visible border or outline in CanvasText/ButtonText; state is also carried by words or icons, never colour alone.
- Right-to-left: Built with logical properties (padding-inline, margin-inline-start, inset-inline); icons that imply direction mirror.

## Motion

Opacity over motion.duration.fast after a 400 ms delay. Under prefers-reduced-motion every transition and animation uses motion.duration.reduced (0 ms); no meaning depends on motion.

## Responsive

Not used on touch; labels show inline below breakpoint.compact.

## Implementation

Base UI Tooltip.
