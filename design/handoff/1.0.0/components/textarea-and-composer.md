# Textarea and composer

Multi-line entry. The task composer in the Control Room is future work and ships disabled.

Surfaces: control-room|desktop

## Anatomy

- Textarea: same frame as text input, grows to 6 lines then scrolls.
- Composer (future): card radius size.radius.xl, context chips, text, agent picker, send.
- Disabled composer reason under it: "Starting tasks here is coming. For now, start them from your AI app."

## States

- **default**: Textarea as text input. Composer in v1: color.sunken, placeholder color.text-subtle, controls disabled.
- **hover**: Textarea border color.text-subtle.
- **focus**: Border color.focus with halo.
- **active**: As focus.
- **disabled**: Composer: color.sunken, color.text-subtle, send in color.sunken; reason text color.text.
- **loading**: Future composer only: send shows a spinner.
- **error**: Border color.danger with a message.

## Keyboard

Textarea: Tab focuses; Enter adds a line. The disabled composer is skipped in Tab order except for its reason text, which is readable. Future composer: Enter sends, Shift+Enter adds a line.

## Accessibility

- Role: textbox (aria-multiline).
- Accessible name: Visible label, e.g. "Note for the agent".
- Focus indicator: 2px outline in color.focus with a 2px offset on :focus-visible (offset -2px inside lists and scroll areas); on color.shadow-bg the ring uses color.shadow-accent.
- Hit area: At least 24×24 CSS px; 32 by default in the Control Room, 40 on the website.
- 200% zoom: Reflows; labels wrap rather than truncate; no horizontal scrolling.
- Forced colours: Keeps a visible border or outline in CanvasText/ButtonText; state is also carried by words or icons, never colour alone.
- Right-to-left: Built with logical properties (padding-inline, margin-inline-start, inset-inline); icons that imply direction mirror.

## Motion

None beyond focus colour. Under prefers-reduced-motion every transition and animation uses motion.duration.reduced (0 ms); no meaning depends on motion.

## Responsive

Full width at all sizes; at 480×320 the textarea starts at 3 lines.

## Implementation

Native textarea in Base UI Field. The composer waits for a reviewed task-start path in orceld.
