# Dialog

Modal confirmation, e.g. stopping a task. Never used to imitate an approval prompt.

Surfaces: shared

## Anatomy

- Panel radius size.radius.xl, color.surface-raised, padding size.space.6.
- Title, type.app-heading.
- Body, color.text-muted, says exactly what happens and what stays.
- Actions at the inline end; safe action first.

## States

- **default**: Scrim color.scrim; panel color.surface-raised.
- **hover**: Actions only.
- **focus**: Initial focus on the safe action ("Keep running"); ring color.focus.
- **active**: Actions only.
- **disabled**: Does not apply
- **loading**: Confirming action shows its loading form; dialog stays open until the result.
- **error**: Error text in color.danger above the actions; the dialog stays open.
- **selected**: Stop confirmation copy: "Stop now. Work already done stays; nothing is rolled back." Destructive action is outline danger, never filled.

## Keyboard

Focus is trapped. Tab and Shift+Tab cycle inside. Esc closes and returns focus to the trigger. Enter activates the focused button only.

## Accessibility

- Role: alertdialog (destructive) or dialog.
- Accessible name: The title via aria-labelledby; body via aria-describedby.
- Focus indicator: 2px outline in color.focus with a 2px offset on :focus-visible (offset -2px inside lists and scroll areas); on color.shadow-bg the ring uses color.shadow-accent.
- Hit area: At least 24×24 CSS px; 32 by default in the Control Room, 40 on the website.
- 200% zoom: Reflows; labels wrap rather than truncate; no horizontal scrolling.
- Forced colours: Keeps a visible border or outline in CanvasText/ButtonText; state is also carried by words or icons, never colour alone.
- Right-to-left: Built with logical properties (padding-inline, margin-inline-start, inset-inline); icons that imply direction mirror.

## Motion

Opacity and scale 0.98 to 1 over motion.duration.base, motion.easing.enter; exit motion.duration.fast, motion.easing.exit. Under prefers-reduced-motion every transition and animation uses motion.duration.reduced (0 ms); no meaning depends on motion.

## Responsive

Width min(440, viewport minus size.space.8); below breakpoint.compact actions stack full width. Fits 480×320 with internal scrolling.

## Implementation

Base UI AlertDialog or Dialog.
