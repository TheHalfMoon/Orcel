# Text input

Single-line text entry with label and help.

Surfaces: shared

## Anatomy

- Label above (type.caption).
- Field 32 (app) or 40 (web), radius size.radius.base.
- Optional leading icon.
- Help or error text below.

## States

- **default**: color.surface, border color.border-strong, placeholder color.text-subtle.
- **hover**: Border color.text-subtle.
- **focus**: Border color.focus with a halo; the halo counts as the indicator.
- **active**: As focus while typing.
- **disabled**: color.sunken, color.text-subtle, border color.border, with a reason in help.
- **loading**: Trailing spinner while validating.
- **error**: Border color.danger; message in color.danger says how to fix it.

## Keyboard

Tab focuses; native editing keys; Enter submits the form when it is the only field.

## Accessibility

- Role: textbox.
- Accessible name: The visible label via Field.Label.
- Focus indicator: 2px outline in color.focus with a 2px offset on :focus-visible (offset -2px inside lists and scroll areas); on color.shadow-bg the ring uses color.shadow-accent.
- Hit area: At least 24×24 CSS px; 32 by default in the Control Room, 40 on the website.
- 200% zoom: Reflows; labels wrap rather than truncate; no horizontal scrolling.
- Forced colours: Keeps a visible border or outline in CanvasText/ButtonText; state is also carried by words or icons, never colour alone.
- Right-to-left: Built with logical properties (padding-inline, margin-inline-start, inset-inline); icons that imply direction mirror.

## Motion

Border colour over motion.duration.instant. Under prefers-reduced-motion every transition and animation uses motion.duration.reduced (0 ms); no meaning depends on motion.

## Responsive

Full width below breakpoint.compact.

## Implementation

Base UI Field and Input.
