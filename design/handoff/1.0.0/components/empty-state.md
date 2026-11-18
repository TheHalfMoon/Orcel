# Empty state

Explains an empty place and offers one next step.

Surfaces: shared

## Anatomy

- Large: one gouache illustration, one serif line (font.family.display), one sentence, one primary action.
- Small (panel, list): icon 20, type.app-heading, type.app-body, one secondary button.

## States

- **default**: Headline color.text, body color.text-muted on color.surface.
- **hover**: Action only.
- **focus**: Action shows the color.focus ring.
- **active**: Action only.
- **disabled**: Does not apply
- **loading**: Does not apply; use skeleton while loading.
- **error**: Does not apply; use the error state of the panel.
- **empty**: This component is the empty form.

## Keyboard

Tab reaches the action.

## Accessibility

- Role: region or plain group.
- Accessible name: The headline.
- Focus indicator: 2px outline in color.focus with a 2px offset on :focus-visible (offset -2px inside lists and scroll areas); on color.shadow-bg the ring uses color.shadow-accent.
- Hit area: At least 24×24 CSS px; 32 by default in the Control Room, 40 on the website.
- 200% zoom: Reflows; labels wrap rather than truncate; no horizontal scrolling.
- Forced colours: Keeps a visible border or outline in CanvasText/ButtonText; state is also carried by words or icons, never colour alone.
- Right-to-left: Built with logical properties (padding-inline, margin-inline-start, inset-inline); icons that imply direction mirror.

## Motion

None. Under prefers-reduced-motion every transition and animation uses motion.duration.reduced (0 ms); no meaning depends on motion.

## Responsive

Illustration hides below breakpoint.compact and at 480×320; text and action remain.

## Implementation

Plain markup.
