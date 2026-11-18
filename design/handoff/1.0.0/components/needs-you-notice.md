# Needs-you notice

Shows a request that is waiting on the person, with the exact preview, and starts the Windows confirmation. The app never approves.

Surfaces: control-room|desktop|browser

## Anatomy

- Surface card, radius size.radius.lg, padding size.space.5.
- Eyebrow "NEEDS YOU" in color.accent-text with a 6px color.accent dot; agent chip on the inline end.
- Title: a plain-English question ("Send the reply to Dana Whitfield?"), type.app-heading.
- Why line, type.app-dense, color.text-muted: who prepared it and that nothing happens until Windows confirms.
- Preview: the exact thing that will happen (recipient, subject, body; path and change; amount and payee), on color.sunken with a color.border hairline. Never a summary.
- Status line: shield icon and "Windows will ask you to confirm" (strong approval: "Windows will ask you · Windows Hello").
- Actions: one primary, filled vermilion "Review", which asks orceld to bring up the Windows prompt; optional ghost "Stop task" where stopping makes sense.
- Outcome line (after the answer): "Approved in Windows · 09:14", "Denied in Windows · 09:15" or "Expired. Nothing was done."; the actions are removed.

## States

- **default**: Waiting: card color.surface, border color.border, eyebrow color.accent-text, Review in color.accent with color.on-accent.
- **hover**: Review color.accent-hover; Stop task color.hover. The card itself has no hover.
- **focus**: Review or Stop task shows the color.focus ring. The card never receives focus by itself.
- **active**: Review color.accent-pressed while pressed.
- **disabled**: Review is unavailable only while the Windows prompt is already open (see loading). There is no other disabled form.
- **loading**: After Review: the button shows a spinner and "Waiting for Windows"; the status line reads "Windows is asking you now. Answer in the Windows prompt."
- **error**: If the prompt cannot open, the status line reads "Couldn't open the Windows prompt. Try Review again." in color.danger with an alert icon; nothing was done.
- **selected**: Answered: eyebrow becomes ANSWERED in color.text-subtle; outcome line in color.success (approved) or color.text-muted (denied, expired); preview stays readable on color.sunken.
- **empty**: No waiting requests: the list shows "Nothing needs you" (empty-state, small form).

## Keyboard

The notice never takes focus. Tab reaches Review, then Stop task. Enter or Space activates the focused Review only; there is no Enter-to-approve, no E, no Esc-to-deny and no timing guard. Ctrl+Shift+A moves focus to the next waiting notice when the person asks; J and K move between notices in the list.

## Accessibility

- Role: region (inline) labelled by the title, described by the preview; the outcome line is role=status.
- Accessible name: The title, e.g. "Send the reply to Dana Whitfield?"; Review's name is "Review in Windows" when the visible label needs context.
- Focus indicator: 2px outline in color.focus with a 2px offset on :focus-visible (offset -2px inside lists and scroll areas); on color.shadow-bg the ring uses color.shadow-accent.
- Hit area: At least 24×24 CSS px; 32 by default in the Control Room, 40 on the website.
- 200% zoom: Reflows; labels wrap rather than truncate; no horizontal scrolling.
- Forced colours: Keeps a visible border or outline in CanvasText/ButtonText; state is also carried by words or icons, never colour alone.
- Right-to-left: Built with logical properties (padding-inline, margin-inline-start, inset-inline); icons that imply direction mirror.

## Motion

Arrival: y 8 to 0 and opacity, motion.duration.base, motion.easing.enter, no scrim, no focus move. Outcome swaps in place with motion.duration.fast. Under prefers-reduced-motion every transition and animation uses motion.duration.reduced (0 ms); no meaning depends on motion.

## Responsive

Width fills its column to a maximum of 440; at breakpoint.compact and below the actions stack and Review spans the width. In the 480×320 Control Room the preview scrolls inside the card after 6 lines.

## Implementation

A plain section with shadcn Card markup and a native button; no Base UI Dialog or AlertDialog (it is not modal and must not imitate an OS prompt). orceld's raise-approval call opens the Windows prompt.
