## Dialog

Radius 16, `bg-raised`, `shadow-lg`, width 440, padding 22/24/20; title 17/600; body 13.5/1.5 `fg-muted`; actions right-aligned, 40 high.
Scrim `rgba(20,20,20,.32)`. Destructive dialogs: safe action is secondary and receives initial focus ("Keep session"); destructive action is outline-danger with an icon ("Delete session"). The body says exactly what is lost and what stays.
**Primitive**: Base UI `Dialog` (or `AlertDialog` for destructive confirmation). Focus trapped; Esc closes; focus returns to the trigger.
