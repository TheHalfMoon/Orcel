## Select

**Anatomy**: trigger styled as an input with chevron-down (chevron-up when open); popup is the Menu surface (`bg-raised`, radius 12, `shadow-md`, 4px padding); items 32 high with a 16px check slot; disabled items `fg-subtle` with a badge explaining why ("Admin only").
**Primitive**: Base UI `Select` (alignItemToTrigger on). **Keyboard**: Space/Enter/Arrow opens; arrows move; type-ahead; Enter selects; Esc closes and returns focus.
**ARIA**: provided by Base UI (`combobox` + `listbox`).
