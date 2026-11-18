# Card

Groups related content such as an agent or a Shadow session.

Surfaces: shared

## Anatomy

- Surface radius size.radius.lg, color.border hairline, padding size.space.4 or size.space.5.
- Header (avatar, title, meta, chip).
- Body.
- Actions: at most one primary.

## States

- **default**: color.surface, border color.border, no shadow on color.background.
- **hover**: Clickable cards: color.hover.
- **focus**: Clickable cards: color.focus ring around the card.
- **active**: color.selected while pressed.
- **disabled**: Does not apply
- **loading**: Skeleton of the same layout.
- **error**: A banner inside the card; the card frame does not change colour.
- **selected**: Shadow session card: color.shadow-bg, text color.shadow-text, top line color.shadow-accent.

## Keyboard

Cards are not focusable unless the whole card is a link; inner actions follow in Tab order.

## Accessibility

- Role: article or group.
- Accessible name: The card title.
- Focus indicator: 2px outline in color.focus with a 2px offset on :focus-visible (offset -2px inside lists and scroll areas); on color.shadow-bg the ring uses color.shadow-accent.
- Hit area: At least 24×24 CSS px; 32 by default in the Control Room, 40 on the website.
- 200% zoom: Reflows; labels wrap rather than truncate; no horizontal scrolling.
- Forced colours: Keeps a visible border or outline in CanvasText/ButtonText; state is also carried by words or icons, never colour alone.
- Right-to-left: Built with logical properties (padding-inline, margin-inline-start, inset-inline); icons that imply direction mirror.

## Motion

None beyond its contents. Under prefers-reduced-motion every transition and animation uses motion.duration.reduced (0 ms); no meaning depends on motion.

## Responsive

Grids collapse to one column below breakpoint.compact; two below breakpoint.medium.

## Implementation

Plain article with shadcn Card markup.
