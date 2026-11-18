# Progress bar and step list

Shows how far an agent is, in a bar and in words.

Surfaces: shared

## Anatomy

- Bar 4 high, radius size.radius.full, track color.agent-track, fill color.agent.
- Count in words next to the bar.
- Step rows: status slot 20, label, time in font.family.mono.

## States

- **default**: Fill color.agent on color.agent-track; done steps check in color.success.
- **hover**: Does not apply
- **focus**: Does not apply; not focusable.
- **active**: Current step spinner in color.agent, aria-current=step.
- **disabled**: Paused: fill stays where it is; chip says Paused.
- **loading**: Indeterminate: a segment slides along the track.
- **error**: Failed step: alert icon and text in color.danger.
- **selected**: Step waiting on the person: dot color.accent, label color.accent-text, "Confirm the reply to Dana in Windows".

## Keyboard

Not focusable; the step list is reachable by reading order.

## Accessibility

- Role: progressbar; ordered list for steps.
- Accessible name: aria-valuetext in words, e.g. "412 of 700 files".
- Focus indicator: 2px outline in color.focus with a 2px offset on :focus-visible (offset -2px inside lists and scroll areas); on color.shadow-bg the ring uses color.shadow-accent.
- Hit area: Not a target.
- 200% zoom: Reflows; labels wrap rather than truncate; no horizontal scrolling.
- Forced colours: Keeps a visible border or outline in CanvasText/ButtonText; state is also carried by words or icons, never colour alone.
- Right-to-left: Built with logical properties (padding-inline, margin-inline-start, inset-inline); icons that imply direction mirror.

## Motion

Width over motion.duration.slower, motion.easing.standard; indeterminate segment loops. Under prefers-reduced-motion every transition and animation uses motion.duration.reduced (0 ms); no meaning depends on motion. Indeterminate becomes a static partial track plus "Working…".

## Responsive

Full width of its container at every size. In right-to-left the fill starts at the inline-start (right) edge.

## Implementation

Base UI Progress.
