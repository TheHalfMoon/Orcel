## Textarea and composer

**Textarea**: same tokens as input, min 72px, grows to 6 lines then scrolls (`field-sizing: content; max-height`).
**Composer** (where a person hands work to an agent): radius 16 card, `border-strong`, `shadow-sm`; focus uses the input halo.
Anatomy: context chips row (files and folders the agent will see, mono 12px on `bg-sunken`, each removable), text area (14/1.5), toolbar: attach (icon 28), dictate (icon 28), agent picker (ghost 28 with chevron), Shadow Mode toggle (ghost 28), hint "Enter to send", send (primary icon button 32, arrow-up).
**Keyboard**: Enter sends, Shift+Enter new line, Ctrl+Enter sends from anywhere in the composer, Esc clears focus. Up arrow in an empty composer edits the last task.
**Primitive**: native `<textarea>` inside Base UI `Field`; agent picker is `Select`; chips are buttons with `aria-label="Remove northwind-order-form.pdf from context"`.
**ARIA**: the context row is a `list` labelled "What the agent can see".
