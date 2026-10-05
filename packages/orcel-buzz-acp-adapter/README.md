# @orcel/buzz-acp-adapter

Experimental Buzz ACP compatibility adapter for [`orcel`](https://github.com/TheHalfMoon/orcel) agents.

```text
buzz-acp -> orcel-buzz-acp-adapter -> orcel acp -> orcel runtime
                  |
                  +-> local buzz CLI -> Buzz reply
```

## Install

```sh
npm install --global @orcel/buzz-acp-adapter
orcel-buzz-acp-adapter install
```

The global installation is intentional. The installer writes its absolute executable path into Buzz's persistent custom harness definition so Buzz can launch the adapter later without relying on the shell's `PATH`. Do not run the installer through `npx`: that would record a path inside npm's disposable `_npx` cache, and clearing or replacing the cache would leave Buzz unable to start the harness. Reinstall the global package and rerun `install` when moving or replacing the Node installation that owns the recorded path.

The interactive installer asks whether the orcel application is local or deployed, validates the selected target, discovers its authored model, locates Buzz Desktop, and confirms before writing the custom harness. For a protected Vercel deployment, it reuses orcel's Vercel login and Trusted Sources flow; the harness stores no Vercel credential.

The installed harness requires **Who can talk to this agent** to remain on its default owner-only selection. Buzz verifies inbound Nostr events and applies that author gate before sending a prompt to the adapter. In Buzz, owner-only includes the agent's owner and cryptographically verified sibling agents belonging to that owner. The adapter fails before starting orcel if Buzz reports another mode or does not expose the mode.

A positional target may be a working directory or URL. Deployed hostnames without a protocol default to HTTPS:

```sh
orcel-buzz-acp-adapter install ./path/to/orcel-app
orcel-buzz-acp-adapter install agent.example.com
```

For scripts and CI, use explicit target flags and confirmation:

```sh
orcel-buzz-acp-adapter install --local ./path/to/orcel-app --yes
orcel-buzz-acp-adapter install --url https://agent.example.com --yes
```

A service agent intentionally shared with multiple people can opt into Buzz's **Allowlist** or **Anyone** modes during installation:

```sh
orcel-buzz-acp-adapter install --url https://agent.example.com --allow-shared-principal --yes
```

This is an authorization decision, not a compatibility flag. It records `ORCEL_BUZZ_ALLOW_SHARED_PRINCIPAL=1` in Buzz's machine-wide custom harness definition for orcel. Every Buzz agent using that harness can then use a broader author gate, and every sender accepted by Buzz uses the same orcel authentication, connections, tools, and session state. Reinstall without the flag to restore the owner-only requirement.

Reopen Buzz, create or edit an agent, and select **orcel** as its harness. Buzz currently requires a model value but does not prefill one for custom harnesses. Enter the authored model printed by the installer or `doctor`; the harness pins that model independently. For a local application, set **Parallelism** to `1` and add any credentials it does not already load from an env file, such as `AI_GATEWAY_API_KEY`, under Buzz's advanced settings. Leave **Who can talk to this agent** on its default owner-only selection, save the agent, and start it. The connector launches `orcel acp`; do not start a separate ACP process.

To inspect the selected target before installation:

```sh
orcel-buzz-acp-adapter doctor ./path/to/orcel-app
```

## Develop locally

From the orcel repository:

```sh
pnpm --filter @orcel/orcel build
pnpm --filter @orcel/buzz-acp-adapter build
node packages/orcel-buzz-acp-adapter/dist/cli.js install apps/fixtures/weather-agent
```

Without a target, the installer defaults the local-directory prompt to the current directory.

## Troubleshooting

### Buzz shows typing but never replies

Open the Buzz agent log and look for the error returned by orcel. If it says `AI Gateway received no credentials`, add `AI_GATEWAY_API_KEY` to the agent's advanced environment variables or configure the local orcel application to load credentials from an env file. Buzz Desktop does not necessarily inherit variables exported in a terminal.

For a local orcel application, keep **Parallelism** at `1`. Higher values make Buzz launch multiple ACP processes for the same application, but a local orcel dev server has a single owner. Messages still run through the surviving process, while the others repeatedly report `A dev server is already running for this orcel agent`.

### The model list only offers Custom model

Buzz's model-discovery subprocess does not currently identify itself as an inert request, so the adapter's author-gate check safely rejects it before starting orcel. Select **Custom model** and enter the authored model printed by `install` or `doctor`. The adapter pins the installed model independently and does not let the Buzz field switch it.

## Direct use

```sh
orcel-buzz-acp-adapter                         # local application in the current directory
orcel-buzz-acp-adapter https://agent.example.com
```

Buzz Desktop sets `BUZZ_ACP_RESPOND_TO` when it launches its harness. A custom launcher must set that variable to `owner-only` or `nobody`. For an intentional shared-principal deployment, pass `--allow-shared-principal` or set `ORCEL_BUZZ_ALLOW_SHARED_PRINCIPAL=1` in the adapter process. Do not set the opt-in in the orcel application runtime itself; it is connector policy and the adapter removes it before launching `orcel acp`.

This package is an experimental compatibility adapter for ordinary conversational replies. It is pinned to Buzz's current prompt framing and uses Buzz's triggering event ID for idempotency while preserving an optional thread reply anchor. It coordinates idempotent reply publication across local connector processes, including top-level DMs. If Buzz does not confirm whether a send was accepted, the adapter records an unknown delivery state and refuses automatic retries to avoid duplicate replies. It does not provide arbitrary Buzz actions, remote MCP, or interactive form elicitation.

## Security and sender identity

Buzz and orcel authenticate different actors at different boundaries:

- Buzz verifies the signed inbound event and decides whether its author may trigger the agent.
- The adapter trusts Buzz's local ACP process boundary, but ACP supplies the event and its `From:` line as prompt text rather than authenticated sender metadata.
- `orcel acp` authenticates the local or deployed orcel target using the credentials configured for the harness. It does not turn the Buzz sender into `ctx.session.auth.current`.

The adapter therefore never treats `From:`, an event ID, ACP metadata, or any other prompt text as an orcel principal. Parsing that text into authentication would let prose control an authorization boundary and would violate orcel's ACP security model. Buzz's verified sender identity stops at the author gate.

### Owner-only default

Owner-only limits use of the shared orcel capability to the Buzz agent's ownership domain. The owner and same-owner sibling agents can trigger turns; other channel members cannot trigger a turn even though their messages may appear in channel or conversation context. This is containment, not per-sender delegation: accepted triggers still run with the same orcel identity and authored capabilities.

The adapter checks `BUZZ_ACP_RESPOND_TO` before spawning orcel. It accepts `owner-only` and the inert `nobody` mode. It rejects `allowlist`, `anyone`, malformed values, and a missing value unless shared-principal mode was explicitly enabled. This check supplements Buzz's author gate; it does not reverify Nostr signatures.

### Shared-principal opt-in

With `--allow-shared-principal`, the adapter permits any author gate Buzz accepts. Use it only for an agent deliberately designed as a shared service:

- provision dedicated, least-privilege app credentials instead of personal credentials;
- assume every allowlisted or eligible channel participant can exercise every capability exposed to the agent;
- keep approval policies and destructive-operation controls appropriate for the least-trusted accepted sender;
- remember that Buzz uses one ACP session per channel, so conversation state is shared at the channel boundary;
- use separate orcel targets and separately installed Buzz harnesses when groups require different credentials or trust boundaries.

User-scoped orcel connections cannot map to a Buzz sender through this adapter. If target authentication establishes the connector operator as an orcel user, every accepted Buzz sender acts as that same orcel user and can reach that user's connections. If the target establishes only a service, runtime, or anonymous principal, user-scoped connections fail authorization; app-scoped connections remain shared. Do not interpret a name or Nostr public key visible to the model as proof that orcel authenticated that person.

True per-sender authentication requires two protocol changes: Buzz must expose the signature-verified sender as structured authenticated data, and orcel ACP must provide an explicit trusted per-turn principal handoff. Until both exist, the adapter intentionally offers only owner-domain containment or an explicit shared-service model.

## Why this adapter exists

Buzz currently expects an ACP agent to publish its own reply, while generic ACP agents stream assistant text back to the client. This adapter closes that gap by collecting orcel's final assistant text and publishing it through the local Buzz CLI. It also projects orcel's authored model as a fixed model because Buzz custom harnesses currently require client-managed model selection.

The adapter becomes unnecessary when Buzz:

1. Publishes streamed ACP assistant text through its existing signing and threading infrastructure.
2. Supports agent-managed models for custom ACP harnesses.
3. Provides conversation and reply context structurally instead of relying on prompt framing.

At that point, Buzz can launch `orcel acp` directly. Buzz credentials, reply publication, and conversation routing can remain entirely inside Buzz.
