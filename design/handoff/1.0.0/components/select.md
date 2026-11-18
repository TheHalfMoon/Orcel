# Select

Picks one option from a short list.

Surfaces: shared

## Anatomy

- Trigger styled as a text input with chevron.
- Popup with the menu surface; items 32 with a check slot.

## States

- **default**: Trigger color.surface, border color.border-strong.
- **hover**: Border color.text-subtle.
- **focus**: Border color.focus with a halo.
- **active**: Open: chevron points up.
- **disabled**: color.sunken with color.text-subtle.
- **loading**: Spinner in place of the chevron while options load.
- **error**: Border color.danger and an error message.
- **selected**: Selected item shows a check; unavailable items color.text-subtle with a badge ("Offline").

## Keyboard

Enter, Space or Down opens; arrows move; type-ahead; Enter selects; Esc closes and keeps the value.

## Accessibility

- Role: combobox with listbox.
- Accessible name: Its visible label, e.g. "Run agents on".
- Focus indicator: 2px outline in color.focus with a 2px offset on :focus-visible (offset -2px inside lists and scroll areas); on color.shadow-bg the ring uses color.shadow-accent.
- Hit area: At least 24×24 CSS px; 32 by default in the Control Room, 40 on the website.
- 200% zoom: Reflows; labels wrap rather than truncate; no horizontal scrolling.
- Forced colours: Keeps a visible border or outline in CanvasText/ButtonText; state is also carried by words or icons, never colour alone.
- Right-to-left: Built with logical properties (padding-inline, margin-inline-start, inset-inline); icons that imply direction mirror.

## Motion

Popup opacity over motion.duration.fast. Under prefers-reduced-motion every transition and animation uses motion.duration.reduced (0 ms); no meaning depends on motion.

## Responsive

Native-sized sheet below breakpoint.compact on touch.

## Implementation

Base UI Select.
