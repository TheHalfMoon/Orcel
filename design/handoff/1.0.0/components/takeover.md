# Takeover

The person takes control from an agent and hands it back with an optional note.

Surfaces: control-room|desktop|browser

## Anatomy

- Take over button (hand icon, T).
- Control banner: "You're in control. The agent is paused." with Hand back (H).
- Hand-back popover: optional note, Keep control, Hand back.
- Reassessing: chip "Reassessing after your changes" and a "What changed" summary.

## States

- **default**: Agent working: chip color.agent-soft; agent cursor color.shadow-accent.
- **hover**: Buttons only.
- **focus**: Buttons and note field show the color.focus ring.
- **active**: In control: banner color.accent-soft, the person's cursor color.accent, chip Paused.
- **disabled**: Take over is unavailable while the agent waits on the person; the notice says so.
- **loading**: Reassessing: chip running in color.agent with the summary revealing.
- **error**: If hand-back fails: banner stays, error text in color.danger, control stays with the person.
- **selected**: Payment pages: the agent stops and hands the page to the person; it never pays.

## Keyboard

T takes over when the agent is focused; H hands back; Tab moves through the note and buttons; Esc closes the popover and keeps control.

## Accessibility

- Role: button; banner is status.
- Accessible name: "Take over Research agent", "Hand back to Research agent".
- Focus indicator: 2px outline in color.focus with a 2px offset on :focus-visible (offset -2px inside lists and scroll areas); on color.shadow-bg the ring uses color.shadow-accent.
- Hit area: At least 24×24 CSS px; 32 by default in the Control Room, 40 on the website.
- 200% zoom: Reflows; labels wrap rather than truncate; no horizontal scrolling.
- Forced colours: Keeps a visible border or outline in CanvasText/ButtonText; state is also carried by words or icons, never colour alone.
- Right-to-left: Built with logical properties (padding-inline, margin-inline-start, inset-inline); icons that imply direction mirror.

## Motion

Banner leaves with motion.duration.fast, motion.easing.exit; summary rows reveal over motion.duration.base, motion.easing.enter, 60 ms apart. Under prefers-reduced-motion every transition and animation uses motion.duration.reduced (0 ms); no meaning depends on motion.

## Responsive

Works at 480×320: the banner wraps and Hand back stays visible; on the website it is documentation only.

## Implementation

Buttons, Base UI Popover for the note, a live region for transitions.
