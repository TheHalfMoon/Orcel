---
name: orcel
description: Build durable backend AI agents with the orcel framework. Use when creating, editing, or debugging an orcel project — agent instructions, skills, tools, connections, channels, sandboxes, subagents, schedules, or evals.
---

# orcel

orcel is a filesystem-first framework for durable backend AI agents. An agent is
a directory on disk — instructions, skills, tools, connections, channels,
subagents, and schedules are all files — and orcel compiles and runs it.

## Source of truth

The complete documentation ships inside the `orcel` package. Do not rely on this
skill for guidance — always read the bundled docs, which match the installed
version exactly:

```
node_modules/@orcel/orcel/docs/
```

Start with `node_modules/@orcel/orcel/docs/README.md`. It contains the full
index and recommended reading order. Before writing any orcel code, read the
relevant guide there first.

If `orcel` is not installed yet, install it (`npm install @orcel/orcel`) or scaffold a new
agent with `npx @orcel/orcel init <agent-name>`, then read the bundled docs.
