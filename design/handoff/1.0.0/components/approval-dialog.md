## Approval dialog: "Needs you" (shared convention)

The same card in Control Room, Orcel Browser and notifications. Do not vary it per surface.
**Anatomy** (width 440 desktop, 400 in panels): surface card, radius 12, `shadow-md`, padding 18/20/16.
1. Eyebrow "NEEDS YOU": 11/600, tracking .14em, `you-fg`, preceded by a 6px `you-default` dot. Agent chip on the right (agent identity, blue).
2. Title: plain-English question, 16/600 ("Send the reply to Dana Whitfield?").
3. Why: 13px `fg-muted`, says who drafted it and that nothing happens until you approve.
4. Preview: the exact thing that will happen (recipient, subject, body; file path and diff; amount and payee) on `bg-sunken`, radius 8, hairline. Never a summary.
5. Actions: filled vermilion **"Approve and <verb>"** with Enter keycap; secondary **Edit** (E); ghost **Deny** (Esc).
**Keyboard**: Enter approves, E edits, Esc denies, only while focus is inside the card. When the card appears without the person asking, focus does not move; it is announced politely and reachable with Ctrl+Shift+A.
**ARIA**: `role="alertdialog"` when modal, `role="region"` with `aria-labelledby` (title) when inline; preview is `aria-describedby`.
**Primitive**: Base UI `AlertDialog` (modal) or a plain section (inline).
