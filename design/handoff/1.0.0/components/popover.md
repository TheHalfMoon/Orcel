# Popover

Rich, interactive detail anchored to a trigger.

Surfaces: shared

## Anatomy

- Panel 300 wide, radius size.radius.lg, color.surface-raised, arrow.
- Content: header, text, progress, small actions.

## States

- **default**: color.surface-raised with color.text.
- **hover**: Actions only.
- **focus**: Focus moves into the popover; actions show the color.focus ring.
- **active**: Actions only.
- **disabled**: Does not apply
- **loading**: Skeleton inside.
- **error**: Inline error text in color.danger.

## Keyboard

Click or Enter opens; focus moves inside; Tab cycles its controls; Esc closes and returns focus to the trigger.

## Accessibility

- Role: dialog (non-modal).
- Accessible name: Labelled by its header.
- Focus indicator: 2px outline in color.focus with a 2px offset on :focus-visible (offset -2px inside lists and scroll areas); on color.shadow-bg the ring uses color.shadow-accent.
- Hit area: At least 24×24 CSS px; 32 by default in the Control Room, 40 on the website.
- 200% zoom: Reflows; labels wrap rather than truncate; no horizontal scrolling.
- Forced colours: Keeps a visible border or outline in CanvasText/ButtonText; state is also carried by words or icons, never colour alone.
- Right-to-left: Built with logical properties (padding-inline, margin-inline-start, inset-inline); icons that imply direction mirror.

## Motion

Opacity and scale 0.98 to 1 over motion.duration.fast, motion.easing.enter. Under prefers-reduced-motion every transition and animation uses motion.duration.reduced (0 ms); no meaning depends on motion.

## Responsive

Full-width sheet below breakpoint.compact.

## Implementation

Base UI Popover.
