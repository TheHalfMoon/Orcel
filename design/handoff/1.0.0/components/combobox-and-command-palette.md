# Combobox and command palette

Search and run anything with Ctrl+K.

Surfaces: control-room|desktop|browser

## Anatomy

- Dialog radius size.radius.xl, color.surface-raised.
- Input row 52 high with search icon and Esc keycap.
- Grouped results, rows 32 with icon, label, shortcut or meta.
- Footer with key hints and result count on color.background.

## States

- **default**: Rows color.text; group headers color.text-subtle.
- **hover**: Row color.hover.
- **focus**: Input has the field focus; the active row shows color.selected and is the aria-activedescendant.
- **active**: Row color.selected while running.
- **disabled**: Unavailable commands in color.text-subtle with a reason in meta.
- **loading**: Spinner in the input row while results load.
- **error**: "Couldn't search sessions. Try again." row in color.danger.
- **empty**: "No results for 'shadx'" with a hint to search docs.

## Keyboard

Ctrl+K opens and focuses the input. Typing filters. Up and Down move (wrap), Home and End jump, Enter runs, Tab cycles result types, Esc closes and restores focus.

## Accessibility

- Role: dialog containing a combobox and listbox.
- Accessible name: "Command palette"; the input is labelled "Search agents, sessions and commands".
- Focus indicator: 2px outline in color.focus with a 2px offset on :focus-visible (offset -2px inside lists and scroll areas); on color.shadow-bg the ring uses color.shadow-accent.
- Hit area: At least 24×24 CSS px; 32 by default in the Control Room, 40 on the website.
- 200% zoom: Reflows; labels wrap rather than truncate; no horizontal scrolling.
- Forced colours: Keeps a visible border or outline in CanvasText/ButtonText; state is also carried by words or icons, never colour alone.
- Right-to-left: Built with logical properties (padding-inline, margin-inline-start, inset-inline); icons that imply direction mirror.

## Motion

Opens with opacity and y 4 over motion.duration.fast, motion.easing.enter. Under prefers-reduced-motion every transition and animation uses motion.duration.reduced (0 ms); no meaning depends on motion.

## Responsive

Full width minus size.space.4 below breakpoint.compact; at 480×320 the list shows at least 5 rows and scrolls.

## Implementation

Base UI Combobox inside Base UI Dialog, or shadcn Command (cmdk).
