# Agent status chip

Shows what one agent is doing in a word, with a dot that pulses only while it runs.

Surfaces: shared

## Anatomy

- Pill, height 22, radius size.radius.full, padding-inline size.space.2.
- Leading 6px dot (or a 12px check or alert icon for done and failed), aria-hidden.
- Label, type.app-label, always the state in words (Idle, Running, Waiting on you, Paused, Done, Failed) or the current step.

## States

- **default**: Running and idle: background color.agent-soft, label color.agent-text, dot color.agent (idle draws the dot as a hollow ring in color.agent).
- **hover**: Static chips have no hover. Interactive chips (open a popover) add color.hover over color.agent-soft.
- **focus**: Interactive chips only: pill-shaped ring, color.focus.
- **active**: Interactive chips: color.selected layered over the background while pressed.
- **disabled**: Does not apply; a chip reflects state and is never disabled.
- **loading**: Running is the loading form: the dot pulses with motion.duration.slower cycles; label may read the step, e.g. Reassessing after your changes.
- **error**: Failed: background color.danger-soft, label and alert icon color.danger.
- **selected**: Waiting on you: background color.accent-soft, label color.accent-text, dot color.accent. Paused: color.sunken with color.text-muted and a square dot in color.text-subtle. Done: color.success-soft, color.success with a check.

## Keyboard

Not focusable when static. When it opens agent details it is a button: Tab reaches it, Enter or Space opens the popover, Esc closes and returns focus.

## Accessibility

- Role: status (only when it updates live), otherwise plain text; button when interactive.
- Accessible name: The label text; interactive chips add the agent name, e.g. "Research agent, running".
- Focus indicator: 2px outline in color.focus with a 2px offset on :focus-visible (offset -2px inside lists and scroll areas); on color.shadow-bg the ring uses color.shadow-accent.
- Hit area: Visual height 22; when interactive the hit area is padded to at least 24×24.
- 200% zoom: Reflows; labels wrap rather than truncate; no horizontal scrolling.
- Forced colours: Keeps a visible border or outline in CanvasText/ButtonText; state is also carried by words or icons, never colour alone.
- Right-to-left: Built with logical properties (padding-inline, margin-inline-start, inset-inline); icons that imply direction mirror.

## Motion

Dot pulse: opacity 1 to 0.35 and scale 1 to 0.8 over 1.6 s, motion.easing.standard, only while running. State swaps: motion.duration.fast, motion.easing.standard. Under prefers-reduced-motion every transition and animation uses motion.duration.reduced (0 ms); no meaning depends on motion. The dot is static and the word carries the state.

## Responsive

Same size at every breakpoint. Below breakpoint.compact long step labels truncate with an ellipsis and expose the full text in the row's accessible name. Fits the 480×320 Control Room list rows.

## Implementation

Plain span; interactive form is a Base UI Popover trigger. shadcn Badge markup restyled.
