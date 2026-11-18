# Menu and context menu

Lists actions from a button or a right-click.

Surfaces: shared

## Anatomy

- Popup radius size.radius.lg, color.surface-raised, padding size.space.1.
- Items 32 with icon 16, label, trailing keycap.
- Separators color.border; group headers type.eyebrow.
- Danger items last, after a separator.

## States

- **default**: Items color.text, icons color.text-muted.
- **hover**: color.selected.
- **focus**: Highlighted item color.selected (virtual focus); the trigger keeps its ring when closed.
- **active**: color.selected.
- **disabled**: color.text-subtle, focusable when a tooltip explains why.
- **loading**: Item shows a spinner in place of its icon.
- **error**: Does not apply
- **selected**: Checked items show a check in the icon slot. Danger items (Stop task…) use color.danger.

## Keyboard

Enter, Space or Down on the trigger opens. Arrows move, Home and End jump, type-ahead, Enter or Space activates, Esc closes and returns focus. Shift+F10 or the Menu key opens the context menu on a focused row.

## Accessibility

- Role: menu, menuitem.
- Accessible name: Trigger label; items by their label.
- Focus indicator: 2px outline in color.focus with a 2px offset on :focus-visible (offset -2px inside lists and scroll areas); on color.shadow-bg the ring uses color.shadow-accent.
- Hit area: At least 24×24 CSS px; 32 by default in the Control Room, 40 on the website.
- 200% zoom: Reflows; labels wrap rather than truncate; no horizontal scrolling.
- Forced colours: Keeps a visible border or outline in CanvasText/ButtonText; state is also carried by words or icons, never colour alone.
- Right-to-left: Built with logical properties (padding-inline, margin-inline-start, inset-inline); icons that imply direction mirror.

## Motion

Opacity and y 4 over motion.duration.fast, motion.easing.enter. Under prefers-reduced-motion every transition and animation uses motion.duration.reduced (0 ms); no meaning depends on motion.

## Responsive

Becomes a bottom sheet below breakpoint.compact on the website; in the 480×320 Control Room it flips to fit.

## Implementation

Base UI Menu and ContextMenu.
