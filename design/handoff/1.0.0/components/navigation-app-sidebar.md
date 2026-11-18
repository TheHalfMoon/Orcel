# App sidebar

Main navigation of the Control Room.

Surfaces: control-room|desktop

## Anatomy

- Column 248 (56 collapsed), color.background, inline-end hairline.
- Search field with Ctrl K keycap.
- Items 32: icon, label, trailing count.
- Group header "Connect".

## States

- **default**: Items color.text, icons color.text-muted.
- **hover**: color.hover.
- **focus**: Inset color.focus ring.
- **active**: color.selected.
- **disabled**: Does not apply
- **loading**: Counts show a skeleton.
- **error**: Cluster devices item shows an alert icon in color.danger when a device is unreachable.
- **selected**: Current item color.selected, weight 500, aria-current=page. Approvals count uses color.accent because it waits on the person.

## Keyboard

Tab enters the list; Up and Down move; Enter opens; G then a letter jumps (G A Agents, G S Shadow sessions); F6 moves to the main region.

## Accessibility

- Role: navigation with a list of links.
- Accessible name: "Control Room"; collapsed items keep aria-label and a tooltip.
- Focus indicator: 2px outline in color.focus with a 2px offset on :focus-visible (offset -2px inside lists and scroll areas); on color.shadow-bg the ring uses color.shadow-accent.
- Hit area: At least 24×24 CSS px; 32 by default in the Control Room, 40 on the website.
- 200% zoom: Reflows; labels wrap rather than truncate; no horizontal scrolling.
- Forced colours: Keeps a visible border or outline in CanvasText/ButtonText; state is also carried by words or icons, never colour alone.
- Right-to-left: Built with logical properties (padding-inline, margin-inline-start, inset-inline); icons that imply direction mirror.

## Motion

Collapse width over motion.duration.base, motion.easing.standard. Under prefers-reduced-motion every transition and animation uses motion.duration.reduced (0 ms); no meaning depends on motion.

## Responsive

Collapsed to 56 below breakpoint.medium; at 480×320 it stays collapsed and the inspector is hidden.

## Implementation

nav and links with a roving-focus hook; Base UI Tooltip for collapsed labels.
