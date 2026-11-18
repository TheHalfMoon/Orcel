## Keycap (Kbd)

**Anatomy**: 18px box (24 in docs), 1px `border-strong` with a 1.5px bottom edge, `bg-surface`, 11px/500 `fg-muted`.
Inside a primary button: white at 14% fill, white 32% border, white text. Inside a tooltip: transparent with inverse-tinted border.
Windows names: Ctrl, Shift, Alt, Enter, Esc, Tab. On macOS render Cmd, Option. Sequences ("G then A") put the word "then" between caps.
**Primitive**: `<kbd>`. **ARIA**: none; when the keycap is the only text, add `aria-label="Control K"` on the wrapper.
Tailwind: `inline-flex h-[18px] min-w-[18px] items-center justify-center rounded-xs border border-border-strong border-b-[1.5px] bg-bg-surface px-[5px] text-[11px] font-medium text-fg-muted`.
