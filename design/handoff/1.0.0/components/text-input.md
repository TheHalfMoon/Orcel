## Text input

**Anatomy**: label (12.5/500, above), field (32 app, 40 web; radius 8; `border-strong`; `shadow-xs`), optional leading icon 16 `fg-subtle`, placeholder `fg-subtle`, help text 12px `fg-muted` below, error text `danger-default` with alert icon.
**States**: default; hover (`border-fg-subtle`); focus (`border-border-focus` plus a 3px halo `color-mix(border-focus 22%)`; this replaces the outline ring); filled; error (`border-danger-default`, message says how to fix: "That name is taken"); disabled (`bg-bg-sunken text-fg-subtle`, `border-default`, no shadow, help explains why: "Managed by Cluster").
**Primitive**: Base UI `Field` + `Input` (Field.Label, Field.Description, Field.Error wire the ARIA).
**Keyboard**: native. **ARIA**: `aria-invalid` on error, `aria-describedby` to help and error (Field does this).
Tailwind: `h-8 rounded-md border border-border-strong bg-bg-surface px-2.5 text-[13px] shadow-xs placeholder:text-fg-subtle hover:border-fg-subtle focus:border-border-focus focus:outline-none focus:shadow-[0_0_0_3px_color-mix(in_srgb,var(--o-border-focus)_22%,transparent)] aria-invalid:border-danger-default`.
