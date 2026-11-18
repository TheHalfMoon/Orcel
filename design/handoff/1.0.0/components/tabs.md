# Tabs

Switches between panels of one object.

Surfaces: shared

## Anatomy

- Tab 36 high, type.app-dense weight 500.
- Underline 2px color.text for the current tab.
- Optional count pill.

## States

- **default**: color.text-muted.
- **hover**: color.text.
- **focus**: color.focus ring around the tab.
- **active**: color.text.
- **disabled**: color.text-subtle.
- **loading**: Panel shows skeleton.
- **error**: Tab shows an alert icon when its panel has an error.
- **selected**: color.text with the underline (Base UI Tabs.Indicator).

## Keyboard

One tab stop; Left and Right move (mirrored in right-to-left); Home and End jump; Enter activates for heavy panels; Tab moves into the panel.

## Accessibility

- Role: tablist, tab, tabpanel.
- Accessible name: Tab labels.
- Focus indicator: 2px outline in color.focus with a 2px offset on :focus-visible (offset -2px inside lists and scroll areas); on color.shadow-bg the ring uses color.shadow-accent.
- Hit area: At least 24×24 CSS px; 32 by default in the Control Room, 40 on the website.
- 200% zoom: Reflows; labels wrap rather than truncate; no horizontal scrolling.
- Forced colours: Keeps a visible border or outline in CanvasText/ButtonText; state is also carried by words or icons, never colour alone.
- Right-to-left: Built with logical properties (padding-inline, margin-inline-start, inset-inline); icons that imply direction mirror.

## Motion

Indicator moves over motion.duration.base, motion.easing.standard. Under prefers-reduced-motion every transition and animation uses motion.duration.reduced (0 ms); no meaning depends on motion.

## Responsive

Scrolls inside its own strip below breakpoint.compact, never the page.

## Implementation

Base UI Tabs.
