# Shadow Mode surface

Marks the area an agent owns while it works in the background: a change of room, not a badge.

Surfaces: control-room|desktop|browser

## Anatomy

- The owned area: background color.shadow-bg, text color.shadow-text.
- 2px top line color.shadow-accent.
- Icons and accents color.shadow-accent; secondary text color.shadow-text-muted; borders color.shadow-border.

## States

- **default**: color.shadow-bg with color.shadow-text and the color.shadow-accent top line.
- **hover**: Controls inside use color.shadow-surface.
- **focus**: Ring color.shadow-accent (color.focus is not visible enough on navy).
- **active**: Controls color.shadow-surface.
- **disabled**: Does not apply
- **loading**: Agent progress inside uses color.shadow-accent on color.shadow-surface.
- **error**: Error text color.danger on color.shadow-surface with an icon.
- **selected**: Watching: a small "Watching" label in color.shadow-accent; Take over is available.

## Keyboard

The surface itself is not focusable. Tab reaches Watch and Take over (T).

## Accessibility

- Role: region labelled "Shadow Mode".
- Accessible name: "Shadow Mode, Research agent working".
- Focus indicator: 2px outline in color.focus with a 2px offset on :focus-visible (offset -2px inside lists and scroll areas); on color.shadow-bg the ring uses color.shadow-accent.
- Hit area: At least 24×24 CSS px; 32 by default in the Control Room, 40 on the website.
- 200% zoom: Reflows; labels wrap rather than truncate; no horizontal scrolling.
- Forced colours: Keeps a visible border or outline in CanvasText/ButtonText; state is also carried by words or icons, never colour alone.
- Right-to-left: Built with logical properties (padding-inline, margin-inline-start, inset-inline); icons that imply direction mirror.

## Motion

Entering: background and colours over motion.duration.slow, motion.easing.enter; top line draws after. Leaving uses motion.duration.fast, motion.easing.exit. Under prefers-reduced-motion every transition and animation uses motion.duration.reduced (0 ms); no meaning depends on motion.

## Responsive

Same treatment at all sizes; at 480×320 the surface takes the main region.

## Implementation

A styled region; Switch for the toggle.
