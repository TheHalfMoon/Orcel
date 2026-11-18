# Avatar

Identifies a person (round) or an agent (rounded square), with an optional status dot.

Surfaces: shared

## Anatomy

- Container 20, 24 or 32; people radius size.radius.full, agents size.radius.sm to base.
- Initials (type.app-micro) or agent icon at 60%.
- Optional status dot bottom inline-end with a ring in color.surface.

## States

- **default**: Person: background color.text, initials color.text-inverse. Agent: background color.agent-soft, icon color.agent-text.
- **hover**: Does not apply unless it opens a profile popover, then color.hover ring.
- **focus**: When interactive, color.focus ring following its shape.
- **active**: Does not apply
- **disabled**: Offline agents: status dot color.text-subtle; avatar unchanged.
- **loading**: Image loading falls back to initials immediately.
- **error**: Image error falls back to initials or the agent icon.
- **selected**: Status dot color.agent (running), color.accent (needs you), color.success (done).

## Keyboard

Not focusable unless it opens something; then Tab, Enter or Space, Esc closes.

## Accessibility

- Role: img (decorative when a visible name is next to it).
- Accessible name: Name plus status, e.g. "Research agent, running".
- Focus indicator: 2px outline in color.focus with a 2px offset on :focus-visible (offset -2px inside lists and scroll areas); on color.shadow-bg the ring uses color.shadow-accent.
- Hit area: At least 24×24 CSS px; 32 by default in the Control Room, 40 on the website.
- 200% zoom: Reflows; labels wrap rather than truncate; no horizontal scrolling.
- Forced colours: Keeps a visible border or outline in CanvasText/ButtonText; state is also carried by words or icons, never colour alone.
- Right-to-left: Built with logical properties (padding-inline, margin-inline-start, inset-inline); icons that imply direction mirror.

## Motion

None. Under prefers-reduced-motion every transition and animation uses motion.duration.reduced (0 ms); no meaning depends on motion.

## Responsive

Same sizes everywhere; stacks collapse to +N below breakpoint.compact.

## Implementation

Base UI Avatar (image with fallback).
