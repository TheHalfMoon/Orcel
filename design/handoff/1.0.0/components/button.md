## Button

**Anatomy**: container, optional leading icon, label (verb first), optional keycap hint.
**Primitive**: native `<button>` (shadcn `Button` composition with `cva` variants is fine). Use Base UI `Toggle` only for pressed/unpressed buttons.
**Variants and tokens**

| Variant | Rest | Hover | Pressed | Use |
|---|---|---|---|---|
| primary | `bg-you-default text-fg-on-accent` | `bg-you-hover` | `bg-you-pressed` | The person's yes. One per view. |
| secondary | `bg-bg-surface border-border-strong shadow-xs` | `bg-bg-control-hover` | `bg-bg-control-pressed shadow-none` | Neutral actions (Edit). |
| ghost | transparent | `bg-bg-hover` | `bg-bg-selected` | Toolbars, Deny, low emphasis. |
| outline-danger | `border-danger-default text-danger-default` | `bg-danger-soft` | `bg-danger-soft` + 1.5px border | Revoke, Delete, Cancel task. Never filled. |
| agent | `bg-agent-soft text-agent-fg` | `bg-agent-soft-hover` | `bg-agent-track` | Hands work to an agent (Run in Shadow Mode). |

**States**: default, hover, pressed, focus-visible (ring), disabled (`bg-bg-sunken text-fg-subtle`, no border or shadow; ghost and danger keep a transparent fill), loading (spinner 14px replaces the leading icon, label becomes the present participle: "Sending", width does not change, `aria-busy="true"`, click ignored).
**Sizes**: 28 (px 10, 12px, radius 6, icon 14) dense toolbars; 32 (px 12, 13px, icon 16) app default; 40 (px 16, 14px, icon 18) dialogs and web forms; 48 (px 22, 15px/600, radius 10, icon 18) web hero only.
**Icon button**: square at the same heights, ghost by default; requires `aria-label` and a Tooltip that shows the shortcut.
**Keyboard**: Enter and Space activate. A keycap inside the button is a hint only; the shortcut is bound at the surface (e.g. the approval card), never globally.
**ARIA**: `aria-busy` while loading; `aria-disabled="true"` instead of `disabled` when the button must stay focusable to explain why (with a Tooltip).

```tsx
const button = cva(
  "focus-ring inline-flex items-center justify-center gap-1.5 whitespace-nowrap rounded-md border border-transparent font-medium transition-colors duration-[var(--o-duration-fast)] ease-standard disabled:bg-bg-sunken disabled:text-fg-subtle disabled:shadow-none",
  { variants: {
      variant: {
        primary: "bg-you-default text-fg-on-accent hover:bg-you-hover active:bg-you-pressed",
        secondary: "bg-bg-surface border-border-strong shadow-xs hover:bg-bg-control-hover active:bg-bg-control-pressed active:shadow-none",
        ghost: "hover:bg-bg-hover active:bg-bg-selected",
        danger: "border-danger-default text-danger-default hover:bg-danger-soft",
        agent: "bg-agent-soft text-agent-fg hover:bg-agent-soft-hover active:bg-agent-track",
      },
      size: { 28: "h-7 px-2.5 text-[12px] rounded-sm [&_svg]:size-3.5", 32: "h-8 px-3 text-[13px] [&_svg]:size-4",
              40: "h-10 px-4 text-[14px] gap-2 [&_svg]:size-[18px]", 48: "h-12 px-[22px] text-[15px] font-semibold rounded-[10px] gap-2 [&_svg]:size-[18px]" },
  }, defaultVariants: { variant: "secondary", size: 32 } });
```
