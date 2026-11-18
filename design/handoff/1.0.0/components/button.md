# Button

Performs an action. Filled red always means the person acts; destructive actions are outlined.

Surfaces: shared

## Anatomy

- Container 28, 32, 40 or 48 high; radius size.radius.base (28 uses size.radius.sm).
- Optional leading icon 14 to 18.
- Label, verb first.
- Optional keycap hint, never on Review or any authority action.

## States

- **default**: Primary color.accent with color.on-accent. Secondary color.surface with color.border-strong. Ghost transparent with color.text. Outline danger color.danger border and label. Agent color.agent-soft with color.agent-text.
- **hover**: Primary color.accent-hover; secondary and ghost color.hover; danger color.danger-soft; agent color.agent-soft with color.hover layered.
- **focus**: color.focus outline with an offset (see Accessibility), never red.
- **active**: Primary color.accent-pressed; secondary and ghost color.selected; agent color.agent-track.
- **disabled**: color.sunken with color.text-subtle, no border; ghost and danger keep a transparent fill. Use aria-disabled with a tooltip reason when the person needs to know why.
- **loading**: Spinner replaces the icon, label becomes the participle ("Opening", "Stopping"), width unchanged, aria-busy.
- **error**: Does not apply; errors are reported next to the control, not by the button.

## Keyboard

Tab focuses; Enter and Space activate. Shortcuts shown in keycaps are bound by the surface, never globally, and never approve.

## Accessibility

- Role: button.
- Accessible name: The visible label; icon-only buttons need aria-label and a tooltip.
- Focus indicator: 2px outline in color.focus with a 2px offset on :focus-visible (offset -2px inside lists and scroll areas); on color.shadow-bg the ring uses color.shadow-accent.
- Hit area: At least 24×24 CSS px; 32 by default in the Control Room, 40 on the website.
- 200% zoom: Reflows; labels wrap rather than truncate; no horizontal scrolling.
- Forced colours: Keeps a visible border or outline in CanvasText/ButtonText; state is also carried by words or icons, never colour alone.
- Right-to-left: Built with logical properties (padding-inline, margin-inline-start, inset-inline); icons that imply direction mirror.

## Motion

Colour changes over motion.duration.instant, motion.easing.standard. Under prefers-reduced-motion every transition and animation uses motion.duration.reduced (0 ms); no meaning depends on motion.

## Responsive

48 is website-only; below breakpoint.compact primary web buttons go full width. Control Room uses 28 and 32 down to 480×320.

## Implementation

Native button with cva variants (shadcn Button composition); Base UI Toggle for pressed buttons.
