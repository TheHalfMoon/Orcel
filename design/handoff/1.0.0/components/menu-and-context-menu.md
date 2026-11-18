## Menu and context menu

**Surface**: `bg-raised`, radius 12, `shadow-md`, 4px padding, min width 220. Items 32 high, radius 6, icon 16 `fg-muted`, label 13px, trailing keycap or meta. Highlight `bg-selected`. Separators `border-default` full bleed. Group headers 11/600 uppercase. Danger items `danger-default` text and icon, always last, after a separator. Disabled items `fg-subtle` and still focusable when they need a tooltip reason.
**Primitive**: Base UI `Menu` (trigger button) and `ContextMenu` (right-click and Shift+F10 on rows). Context menu items match the row's More menu.
**Keyboard**: arrows, Home/End, type-ahead, Enter/Space activate, Esc closes, Right/Left for submenus.
**Motion**: snappy spring or 140ms fade + 4px offset from the trigger side.
