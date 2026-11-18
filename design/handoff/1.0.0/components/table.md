# Table

Dense tabular data such as connections.

Surfaces: control-room|desktop|website

## Anatomy

- Header 32 (type.app-label, color.text-muted).
- Rows 36 with hairlines color.border.
- Numbers tabular and aligned to the inline end.
- Optional selection column.

## States

- **default**: Rows color.text on color.surface.
- **hover**: Row color.hover.
- **focus**: Focused cell or row inset color.focus ring.
- **active**: Row color.selected while pressed.
- **disabled**: Row color.text-subtle.
- **loading**: Skeleton rows.
- **error**: Status badge color.danger-soft with color.danger.
- **selected**: Row color.selected.
- **empty**: Small empty state in the body.

## Keyboard

Tab enters the table; arrows move between cells when it is a grid; Space selects a row; Enter opens; sortable headers are buttons.

## Accessibility

- Role: table (grid when cells are interactive).
- Accessible name: Caption or aria-label, e.g. "Connections".
- Focus indicator: 2px outline in color.focus with a 2px offset on :focus-visible (offset -2px inside lists and scroll areas); on color.shadow-bg the ring uses color.shadow-accent.
- Hit area: At least 24×24 CSS px; 32 by default in the Control Room, 40 on the website.
- 200% zoom: Reflows; labels wrap rather than truncate; no horizontal scrolling.
- Forced colours: Keeps a visible border or outline in CanvasText/ButtonText; state is also carried by words or icons, never colour alone.
- Right-to-left: Built with logical properties (padding-inline, margin-inline-start, inset-inline); icons that imply direction mirror.

## Motion

Row background over motion.duration.instant. Under prefers-reduced-motion every transition and animation uses motion.duration.reduced (0 ms); no meaning depends on motion.

## Responsive

Below breakpoint.medium secondary columns hide; below breakpoint.compact rows become stacked cards. No horizontal scrolling at 320 or 480×320.

## Implementation

Semantic table with shadcn Table markup; TanStack Table for sorting.
