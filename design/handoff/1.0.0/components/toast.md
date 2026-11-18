## Toast

380 wide, radius 12, `bg-raised`, `shadow-lg`, padding 14/14/14/16; icon 18 (success `success-default`, info `agent-default`, error `danger-default`, needs you `you-default`); title 13/600, body 13 `fg-muted`; optional actions (28 buttons); close 20 target, 24 hit.
Needs-you toast adds a 3px inset vermilion left edge and never approves from the toast: its primary opens the approval.
**Behaviour**: bottom right, 16 from edges, newest on top, 3 visible. Success and info 6s (paused on hover/focus); error and needs-you persist.
**Primitive**: Base UI `Toast`. **ARIA**: success/info `role="status"`; error `role="alert"`. F6 reaches the toast region.
