## List row

36 default (13px), 30 dense (12.5px); radius 6; padding 0 10; icon 16 `fg-muted` or a 24 avatar; trailing meta 12px `fg-subtle` or a chip.
States: hover `bg-hover`, selected `bg-selected` (500 weight in nav), focus-visible inset ring.
**Keyboard**: roving tabindex (one tab stop, arrows, Home/End, type-ahead), Enter opens, Space selects, Shift+F10 context menu.
**Primitive**: Base UI `Menu`-like roving is not appropriate for navigation; use a `listbox` (selection lists) or a `nav` list of links (sidebar) with a small roving-focus hook.
