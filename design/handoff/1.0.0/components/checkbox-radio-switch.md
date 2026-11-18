# Checkbox, radio and switch

Small selection controls. Switches take effect at once; the Shadow Mode switch turns a room navy.

Surfaces: shared

## Anatomy

- Checkbox 16, radius size.radius.xs. Radio 16 circle. Switch 32 × 18 track with 14 thumb.
- Label to the inline end; the whole row is the target.

## States

- **default**: Border color.border-strong on color.surface; off switch track color.border-strong.
- **hover**: Border color.text-subtle.
- **focus**: color.focus ring around the control with offset.
- **active**: Checked: color.text fill with a check in color.surface; radio dot color.text; switch track color.text.
- **disabled**: Muted, with the reason next to the label ("disabled by policy").
- **loading**: Does not apply
- **error**: Field-level error text in color.danger under the group.
- **selected**: Mixed checkbox: color.text with a bar. Shadow Mode switch on: track color.shadow-bg with a color.shadow-accent ring and thumb; the row becomes color.shadow-bg.

## Keyboard

Tab to the control (radio group is one tab stop; arrows move and select). Space toggles a checkbox or switch.

## Accessibility

- Role: checkbox, radiogroup/radio, switch.
- Accessible name: The visible label; Shadow Mode switch is described by "Agents keep working in an isolated session you can watch".
- Focus indicator: 2px outline in color.focus with a 2px offset on :focus-visible (offset -2px inside lists and scroll areas); on color.shadow-bg the ring uses color.shadow-accent.
- Hit area: Row height at least 24 (32 in lists); the label extends the target.
- 200% zoom: Reflows; labels wrap rather than truncate; no horizontal scrolling.
- Forced colours: Keeps a visible border or outline in CanvasText/ButtonText; state is also carried by words or icons, never colour alone.
- Right-to-left: Built with logical properties (padding-inline, margin-inline-start, inset-inline); icons that imply direction mirror.

## Motion

Thumb and check over motion.duration.base, motion.easing.standard. Under prefers-reduced-motion every transition and animation uses motion.duration.reduced (0 ms); no meaning depends on motion.

## Responsive

Unchanged; rows wrap labels at 320.

## Implementation

Base UI Checkbox, RadioGroup and Radio, Switch.
