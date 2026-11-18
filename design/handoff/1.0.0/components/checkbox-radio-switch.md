## Checkbox, radio, switch

- **Checkbox** 16px, radius 4, 1.5px `border-strong`; on: `bg-fg-default` with a 12px check in `bg-surface`; mixed: a 8px bar. Label is the hit target (row at least 24 high). Base UI `Checkbox` (+ `CheckboxGroup`).
- **Radio** 16px circle; on: 1.5px ink border with 8px ink dot. Base UI `RadioGroup` + `Radio`; arrows move and select; one tab stop.
- **Switch** 32 x 18 track, 14px thumb; off `border-strong`, on `fg-default`. Takes effect immediately, never needs Save. Base UI `Switch`; Space toggles; `role="switch"` with `aria-checked`.
- **Shadow Mode switch**: on state uses `bg-shadow-bg` with a 1px inset `shadow-accent` ring and a sky thumb. In its row, the whole row becomes a Shadow surface (navy, sky icon, "On · 2 agents"). Label: "Shadow Mode"; `aria-describedby` "Agents keep working in an isolated session you can watch".
- **Disabled** for all three: 45% opacity plus a reason next to the label ("disabled by policy").
Focus: ring with 2px offset around the control, not the label.
