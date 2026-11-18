# Banner

Inline message across the width of its container, including the takeover and Shadow Mode banners.

Surfaces: shared

## Anatomy

- Container min height 44, radius size.radius.base, padding size.space.3 size.space.4.
- Icon 18.
- Text with a bold lead phrase.
- Optional actions at the inline end.

## States

- **default**: Info: color.agent-soft, icon color.agent, text color.text.
- **hover**: Actions only.
- **focus**: Actions show the color.focus ring.
- **active**: Actions only.
- **disabled**: Does not apply
- **loading**: Info banner with a spinner for syncing, e.g. "Cluster is syncing. 2 of 3 machines are up to date."
- **error**: color.danger-soft, icon color.danger, text stays color.text.
- **selected**: Control (takeover): color.accent-soft, hand icon color.accent, "You're in control. The agent is paused." with Hand back. Shadow: color.shadow-bg, text color.shadow-text, icon and top line color.shadow-accent. Warning: color.warning-soft. Success: color.success-soft.

## Keyboard

Not focusable itself; Tab reaches its actions in reading order.

## Accessibility

- Role: status (info, success) or alert (error).
- Accessible name: The banner text.
- Focus indicator: 2px outline in color.focus with a 2px offset on :focus-visible (offset -2px inside lists and scroll areas); on color.shadow-bg the ring uses color.shadow-accent.
- Hit area: At least 24×24 CSS px; 32 by default in the Control Room, 40 on the website.
- 200% zoom: Reflows; labels wrap rather than truncate; no horizontal scrolling.
- Forced colours: Keeps a visible border or outline in CanvasText/ButtonText; state is also carried by words or icons, never colour alone.
- Right-to-left: Built with logical properties (padding-inline, margin-inline-start, inset-inline); icons that imply direction mirror.

## Motion

Appears with opacity over motion.duration.base, motion.easing.enter. Under prefers-reduced-motion every transition and animation uses motion.duration.reduced (0 ms); no meaning depends on motion.

## Responsive

Below breakpoint.compact actions wrap under the text. Works at 320 and 480×320.

## Implementation

Plain div with role; no primitive needed.
