# List row

One item in a dense list: agents, files, activity.

Surfaces: shared

## Anatomy

- Row 36 (dense 30), radius size.radius.sm, padding-inline size.space.2-5.
- Leading icon 16 or avatar 24.
- Label, truncates.
- Trailing meta or chip.

## States

- **default**: Label color.text, meta color.text-subtle.
- **hover**: color.hover.
- **focus**: Inset color.focus ring.
- **active**: color.selected while pressed.
- **disabled**: color.text-subtle, still focusable with a reason in meta.
- **loading**: Skeleton rows.
- **error**: Trailing alert icon in color.danger plus text in meta.
- **selected**: color.selected; navigation rows add weight 500.
- **empty**: List shows the small empty state.

## Keyboard

The list is one tab stop (roving tabindex). Up and Down move, Home and End jump, type-ahead jumps, Enter opens, Space selects, Shift+F10 opens the context menu.

## Accessibility

- Role: option in a listbox, or link in a navigation list.
- Accessible name: The label plus state, e.g. "Research agent, running".
- Focus indicator: 2px outline in color.focus with a 2px offset on :focus-visible (offset -2px inside lists and scroll areas); on color.shadow-bg the ring uses color.shadow-accent.
- Hit area: At least 24×24 CSS px; 32 by default in the Control Room, 40 on the website.
- 200% zoom: Reflows; labels wrap rather than truncate; no horizontal scrolling.
- Forced colours: Keeps a visible border or outline in CanvasText/ButtonText; state is also carried by words or icons, never colour alone.
- Right-to-left: Built with logical properties (padding-inline, margin-inline-start, inset-inline); icons that imply direction mirror.

## Motion

Background over motion.duration.instant. Under prefers-reduced-motion every transition and animation uses motion.duration.reduced (0 ms); no meaning depends on motion.

## Responsive

Meta hides below breakpoint.compact; chip stays. At 480×320 rows keep 36.

## Implementation

listbox with a roving-focus hook; links for navigation.
