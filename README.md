<div align="center">
  <a href="https://github.com/TheHalfMoon/orcel/">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset=".github/assets/orcel.svg">
      <img alt="orcel logo" src=".github/assets/orcel.svg" height="128">
    </picture>
  </a>
  <h1>orcel</h1>

<a href="https://github.com/TheHalfMoon"><img alt="Built by TheHalfMoon" src="https://img.shields.io/badge/BUILT%20BY-TheHalfMoon-000000.svg?style=for-the-badge&logo=github&labelColor=000000"></a>
<a href="https://www.npmjs.com/package/@orcel/orcel"><img alt="NPM version" src="https://img.shields.io/npm/v/@orcel/orcel.svg?style=for-the-badge&labelColor=000000"></a>
<a href="https://github.com/TheHalfMoon/orcel/blob/main/LICENSE"><img alt="License" src="https://img.shields.io/npm/l/@orcel/orcel.svg?style=for-the-badge&labelColor=000000"></a>
<a href="https://github.com/TheHalfMoon/orcel/discussions"><img alt="Join the community on GitHub" src="https://img.shields.io/badge/Join%20the%20community-blueviolet.svg?style=for-the-badge&logo=Github&labelColor=000000&logoWidth=20"></a>

</div>

[orcel](https://github.com/TheHalfMoon/orcel/) is a filesystem-first framework for durable AI agents. Core agent capabilities live in
conventional locations, so projects are easier to inspect, extend, and operate.

## The filesystem is the authoring interface

A typical orcel agent has this structure:

```text
my-agent/
└── agent/
    ├── agent.ts            # Optional: model and runtime config
    ├── instructions.md     # Required: the always-on system prompt
    ├── tools/              # Optional: typed functions the model can call
    │   └── get_weather.ts
    ├── skills/             # Optional: procedures loaded on demand
    │   └── plan_a_trip.md
    ├── channels/           # Optional: message channels (HTTP, Slack, Discord)
    │   └── slack.ts
    └── schedules/          # Optional: recurring cron jobs
        └── weekly_recap.ts
```

Read the [documentation](https://github.com/TheHalfMoon/orcel/docs) for the full project layout and guides.

## Quick start

```bash
npx @orcel/orcel@latest init my-agent
```

This creates a new `my-agent` directory, installs its dependencies, initializes Git, and starts
the interactive terminal UI. The generated agent uses `openai/gpt-6-luna-fast` with high reasoning.

To start with another AI Gateway model, pass its model ID:

```bash
npx @orcel/orcel@latest init my-agent --model openai/gpt-5.6-terra
```

Passing `--model` without `--reasoning` uses the provider's default reasoning. Pass `--reasoning` to set it explicitly.

To add orcel to an existing project, pass a path:

```bash
cd myapp
npx @orcel/orcel@latest init .
```

> [!NOTE]
> The `orcel` package includes its full documentation, so coding agents can read it locally from
> `node_modules/@orcel/orcel/docs`.

### A minimal example

The generated project includes an `agent` directory. Replace `agent/instructions.md` with:

```md
You are a concise weather demo assistant. Tell users that the weather data is mocked.
```

Add a mock weather tool at `agent/tools/get_weather.ts`:

```ts
import { defineTool } from "@orcel/orcel/tools";
import { z } from "zod";

export default defineTool({
  description: "Return mock weather data for a city.",
  inputSchema: z.object({ city: z.string().min(1) }),
  async execute({ city }) {
    return { city, condition: "Sunny", temperatureF: 72 };
  },
});
```

Choose the model in `agent/agent.ts`:

```ts
import { defineAgent } from "@orcel/orcel";

export default defineAgent({
  model: "openai/gpt-6-luna-fast",
  reasoning: "high",
});
```

For a new scaffold, start the agent again:

```bash
npm run dev
```

That's a working agent. Add human-in-the-loop prompts, subagents, and schedules as needed.
Follow the [first-agent tutorial](https://github.com/TheHalfMoon/orcel/docs/tutorial/first-agent) for a complete
walkthrough.

## Community

The orcel community lives on [GitHub Discussions](https://github.com/TheHalfMoon/orcel/discussions),
where you can ask questions, share ideas, and show what you've built.

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) to get the repo
running locally and land a change, and use
[issues](https://github.com/TheHalfMoon/orcel/issues) and
[discussions](https://github.com/TheHalfMoon/orcel/discussions) to collaborate. By
participating, you agree to our [Code of Conduct](CODE_OF_CONDUCT.md).

## Security

Please do not open public issues for security vulnerabilities. Follow
[SECURITY.md](SECURITY.md) and use GitHub private vulnerability reporting for this repository when available.

## Development status

Orcel is under active development. APIs, documentation, and behavior may change before the first stable release.
