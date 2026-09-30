# Next.js multi-agent kaf demo

This app demonstrates `withEve()` discovering three independent kaf agents
from the project-level `agents/` workspace and mounting them into one Next.js app:

- `support` at `/kaf/agents/support/kaf/v1/*`
- `billing` at `/kaf/agents/billing/kaf/v1/*`
- `research` at `/kaf/agents/research/kaf/v1/*`

Run it locally with:

```sh
pnpm --filter framework-next-multi-agent dev
```

The page calls each agent with `useKafAgent({ agent: "<name>" })`.
