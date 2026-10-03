# Next.js multi-agent orcel demo

This app demonstrates `withEve()` discovering three independent orcel agents
from the project-level `agents/` workspace and mounting them into one Next.js app:

- `support` at `/orcel/agents/support/orcel/v1/*`
- `billing` at `/orcel/agents/billing/orcel/v1/*`
- `research` at `/orcel/agents/research/orcel/v1/*`

Run it locally with:

```sh
pnpm --filter framework-next-multi-agent dev
```

The page calls each agent with `useOrcelAgent({ agent: "<name>" })`.
