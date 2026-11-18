## Progress bar and step list

Bar: 4 high, track `agent-track`, fill `agent-default`, radius full. Indeterminate: 32% segment slides (1.4s). Always paired with words and a count ("412 of 700").
Steps: rows with a 20px status slot (done check `success-default`; now spinner `agent-default`; needs-you 8px vermilion dot with `you-fg` 500 text; todo hollow 8px ring), label 13px, time in mono 12px `fg-subtle`.
**Primitive**: Base UI `Progress` (`aria-valuenow`, `aria-valuetext`). Steps are an ordered list; the current step has `aria-current="step"`.
