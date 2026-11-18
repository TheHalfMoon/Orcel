## Combobox and command palette

**Anatomy**: 600 wide, radius 16, `shadow-lg`; input row 52 high (search icon 18, 15px text, Esc keycap); grouped results with uppercase group headers (11/600, `fg-subtle`); rows 32 with icon, label, trailing shortcut or meta; footer 36 on `bg-canvas` with key hints and result count.
**Primitive**: Base UI `Combobox` (or shadcn `Command` on cmdk) inside Base UI `Dialog`.
**Keyboard**: Ctrl+K opens anywhere; typing filters; Up/Down move (wraps); Enter runs; Tab cycles result types; Esc closes and restores focus.
**ARIA**: `role="combobox"` on the input with `aria-activedescendant`; groups are `role="group"` with `aria-labelledby` on the header; announce "6 results" politely on change.
