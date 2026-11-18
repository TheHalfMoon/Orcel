# Badge

Labels or counts something; never interactive.

Surfaces: shared

## Anatomy

- Pill height 20, radius size.radius.full, type.app-label at 11.5.
- Optional 12px leading icon.
- Count variant 18 high for things waiting on the person.

## States

- **default**: Neutral: color.sunken with color.text-muted.
- **hover**: Does not apply; badges are not interactive.
- **focus**: Does not apply; never focusable.
- **active**: Does not apply
- **disabled**: Does not apply
- **loading**: Does not apply
- **error**: color.danger-soft with color.danger and an alert icon (e.g. Expired).
- **selected**: New: color.highlight-soft with color.highlight-text. Connected: color.success-soft with color.success. Agent: color.agent-soft with color.agent-text. Count: color.accent with color.on-accent.

## Keyboard

Not in the tab order.

## Accessibility

- Role: none (text); count badges are included in the parent's accessible name.
- Accessible name: Its text; counts read as "2 waiting".
- Focus indicator: 2px outline in color.focus with a 2px offset on :focus-visible (offset -2px inside lists and scroll areas); on color.shadow-bg the ring uses color.shadow-accent.
- Hit area: Not a target.
- 200% zoom: Reflows; labels wrap rather than truncate; no horizontal scrolling.
- Forced colours: Keeps a visible border or outline in CanvasText/ButtonText; state is also carried by words or icons, never colour alone.
- Right-to-left: Built with logical properties (padding-inline, margin-inline-start, inset-inline); icons that imply direction mirror.

## Motion

None. Under prefers-reduced-motion every transition and animation uses motion.duration.reduced (0 ms); no meaning depends on motion.

## Responsive

Unchanged across breakpoints.

## Implementation

Plain span; shadcn Badge restyled.
