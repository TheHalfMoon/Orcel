---
name: kaf
description: Build durable backend AI agents with the kaf framework. Use when creating, editing, or debugging an kaf project — agent instructions, skills, tools, connections, channels, sandboxes, subagents, schedules, or evals.
---

# kaf

kaf is a filesystem-first framework for durable backend AI agents. An agent is
a directory on disk — instructions, skills, tools, connections, channels,
subagents, and schedules are all files — and kaf compiles and runs it.

## Source of truth

The complete documentation ships inside the `kaf` package. Do not rely on this
skill for guidance — always read the bundled docs, which match the installed
version exactly:

```
node_modules/kaf/docs/
```

Start with `node_modules/kaf/docs/README.md`. It contains the full
index and recommended reading order. Before writing any kaf code, read the
relevant guide there first.

If `kaf` is not installed yet, install it (`npm install kaf`) or scaffold a new
agent with `npx kaf init <agent-name>`, then read the bundled docs.
