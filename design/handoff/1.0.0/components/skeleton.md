# Skeleton

Placeholder shaped like the content that is loading.

Surfaces: shared

## Anatomy

- Blocks in color.sunken, radius size.radius.sm, matching the real layout.

## States

- **default**: color.sunken blocks.
- **hover**: Does not apply
- **focus**: Does not apply
- **active**: Does not apply
- **disabled**: Does not apply
- **loading**: This is the loading form; shimmer is a color.hover overlay fading in and out.
- **error**: Does not apply; replace with the panel's error state.

## Keyboard

Not focusable.

## Accessibility

- Role: none; the container has aria-busy=true.
- Accessible name: The container's label, e.g. "Loading agents".
- Focus indicator: 2px outline in color.focus with a 2px offset on :focus-visible (offset -2px inside lists and scroll areas); on color.shadow-bg the ring uses color.shadow-accent.
- Hit area: Not a target.
- 200% zoom: Reflows; labels wrap rather than truncate; no horizontal scrolling.
- Forced colours: Keeps a visible border or outline in CanvasText/ButtonText; state is also carried by words or icons, never colour alone.
- Right-to-left: Built with logical properties (padding-inline, margin-inline-start, inset-inline); icons that imply direction mirror.

## Motion

Shimmer cycles over motion.duration.slower. Shown only after 300 ms. Under prefers-reduced-motion every transition and animation uses motion.duration.reduced (0 ms); no meaning depends on motion. Blocks stay static.

## Responsive

Mirrors the layout at each breakpoint.

## Implementation

Plain divs; shadcn Skeleton restyled.
