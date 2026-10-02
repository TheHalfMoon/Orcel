# agent-tools

> [!NOTE]
> This app is internal test infrastructure, not a template or example.
> For a representative example agent, see
> [`apps/fixtures/weather-agent`](../../../apps/fixtures/weather-agent).

Fixture app for deterministic `orcel eval` tool coverage. It owns ordinary
model-driven tool-use smokes, including dynamic tools, multi-step loops, tool
result narrowing, and tool failure recovery.

## Run locally

```sh
pnpm exec orcel eval --strict
```
