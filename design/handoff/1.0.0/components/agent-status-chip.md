## Agent status chip (shared convention)

22px pill, padding 0 8 0 7, gap 6, background `agent-soft`, 6px `agent-default` dot, label 12/500 `agent-fg`.

| State | Background | Dot / icon | Label |
|---|---|---|---|
| idle | agent-soft | hollow ring 1.5px cobalt | Idle |
| running | agent-soft | cobalt dot, pulses 1.6s | Running (or the step: "Reassessing after your changes") |
| waiting on you | you-soft | vermilion dot | Waiting on you / Needs you |
| paused | bg-sunken, fg-muted | 6px square, fg-subtle | Paused |
| done | success-soft, success-default | 12px check | Done |
| failed | danger-soft, danger-default | 12px alert | Failed |

**ARIA**: `role="status"` only when it changes live; the dot is `aria-hidden`; the label always carries the state.
Tailwind: `inline-flex h-[22px] items-center gap-1.5 rounded-full bg-agent-soft pl-[7px] pr-2 text-[12px] font-medium text-agent-fg`.
