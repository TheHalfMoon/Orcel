# Toast

Brief message about something that happened. Needs-you toasts offer only Review or Open Orcel.

Surfaces: control-room|desktop|browser

## Anatomy

- Card 380 wide, radius size.radius.lg, color.surface-raised.
- Icon 18, title, body.
- Optional actions (28).
- Close button.

## States

- **default**: Info icon color.agent; text color.text and color.text-muted.
- **hover**: Timer pauses.
- **focus**: Actions show the color.focus ring; timer pauses.
- **active**: Actions only.
- **disabled**: Does not apply
- **loading**: Does not apply
- **error**: Icon color.danger; stays until dismissed; says what did not happen.
- **selected**: Needs you: inline-start edge color.accent; actions "Review" (brings up the Windows prompt) and "Open Orcel"; never Approve. Success: icon color.success; no Undo.

## Keyboard

Toasts never take focus. F6 moves to the toast region; Tab cycles actions; Esc dismisses the focused toast.

## Accessibility

- Role: status (info, success) or alert (error).
- Accessible name: Its title and body.
- Focus indicator: 2px outline in color.focus with a 2px offset on :focus-visible (offset -2px inside lists and scroll areas); on color.shadow-bg the ring uses color.shadow-accent.
- Hit area: At least 24×24 CSS px; 32 by default in the Control Room, 40 on the website.
- 200% zoom: Reflows; labels wrap rather than truncate; no horizontal scrolling.
- Forced colours: Keeps a visible border or outline in CanvasText/ButtonText; state is also carried by words or icons, never colour alone.
- Right-to-left: Built with logical properties (padding-inline, margin-inline-start, inset-inline); icons that imply direction mirror.

## Motion

Enter y 8 and opacity over motion.duration.base, motion.easing.enter; exit over motion.duration.fast, motion.easing.exit. Under prefers-reduced-motion every transition and animation uses motion.duration.reduced (0 ms); no meaning depends on motion.

## Responsive

Full width minus size.space.4 at the bottom below breakpoint.compact; at 480×320 one toast is visible at a time.

## Implementation

Base UI Toast.
