# M4 selection package: a local model for the Orcel Agent

**Status: RECOMMENDATION FOR THE FOUNDER. Nothing has been downloaded or run.** Selection, licensing and download stay pending founder approval (SG-000129 decision 2). This builds on `prep/M4-local-model-candidates.md`. Every agent result so far is deterministic-scripted, so **no model capability has been measured**, and the recommendation below rests on licence, documentation and fit, not on benchmark wins.

## Recommendation

| | Model | Pinned revision (metadata read 2026-11-04) | Licence | Download |
|---|---|---|---|---|
| **Primary** | Qwen3.5-4B, text only, `Q4_K_M` | `Qwen/Qwen3.5-4B` @ `851bf6e806efd8d0a36b00ddf55e13ccb7b8cd0a` | Apache-2.0 (card tag, `LICENSE` file in the repo) | 2.74 GB (Unsloth conversion) |
| **Fallback** | Granite 4.0 H-Tiny, `Q4_K_M` | `ibm-granite/granite-4.0-h-tiny` @ `791e0d3d28c86e106c9b6e0b4cecdee0375b6124` | Apache-2.0 (card tag and IBM's docs; **no `LICENSE` file listed in the repo**) | 4.25 GB (Unsloth conversion) |

**Download only the primary at first.** The fallback is downloaded only if the primary misses the bar below.

**Why Qwen3.5-4B:**
- Apache-2.0, with its licence file in the repository, and no use restrictions passing to users.
- Tool calling is documented by the vendor, with a named parser (`qwen3_coder`).
- The smallest weights of the serious candidates, so it fits a 16 GB laptop.
- Its larger sibling is the only family here with any independent tool-call numbers, and those are modest (below).

**Why Granite as the fallback:** a different vendor and architecture, so a failure of the first is unlikely to repeat for the same reason. IBM documents OpenAI-style tool definitions, and only about 1B parameters are active per token.

## Evidence, and how weak it is

| Claim | Source | Strength |
|---|---|---|
| Qwen3.5-9B: BFCL 64.0%, NexusRaven 77.1% (llama.cpp); latency about 12 to 14 s on a 16 GB M4 | Community test: 150 BFCL and 48 NexusRaven queries, one machine | **Low.** A larger sibling, not this model, not Windows. It does show the family works and that thinking adds latency |
| Qwen3.5 "excels in tool calling" | Vendor card | Marketing; unmeasured |
| Granite 4.0 "enhanced tool calling" | Vendor card | Marketing; unmeasured |
| Qwen3.5-4B or Granite H-Tiny tool-call accuracy | **None found** | **Unknown.** That is what the benchmark is for |

If either model fails the bar, the honest result is "no qualified model yet", not a lowered bar.

## Rejected for now

| Model | Why |
|---|---|
| Qwen3.5-9B | Larger: tight at 16 GB with a 32k context. A candidate only if 4B lacks capability and more memory is available |
| Gemma, Llama | Licence terms that pass to every downstream user (see the candidates note) |
| Phi-4 family | MIT, but no tool-calling evidence found |
| Mistral Small (24B) | Too large for the reference machine |

## Hardware

**Reference machine: this project's own Windows PC.** Intel i5-13420H (8 cores, 12 threads), 15.7 GB RAM, integrated graphics only, so **CPU-only**. It is a realistic mid-range laptop and costs nothing extra.

| | Primary | Fallback |
|---|---|---|
| Weights in memory | About 2.7 GB | About 4.3 GB |
| With a 32k context, OS and app | **Estimated** fits in 16 GB; not measured | **Estimated** fits in 16 GB, tighter; not measured |
| Speed | **Unknown on this CPU** | **Unknown** |

Stated minimum to propose after measuring: 16 GB RAM, no GPU. Machines below that aren't supported for the agent's model.

## The runtime matters as much as the model

The agent's recorded rules rule out the obvious choices:

| Option | Fits the rules? | Verdict |
|---|---|---|
| Ollama through `langchain-ollama` | No. `ollama` and `langchain-ollama` are on the forbidden list. It's a background service with a network listener and its own update and model paths | **Rejected** |
| `ChatLlamaCpp` / `llama-cpp-python` in the agent's process | No. It needs `langchain-community` (forbidden). The egress test refuses native loads in the agent. I found no upstream Windows wheels, only community builds | **Rejected** |
| `llama-server` over HTTP from the agent | No. The agent opens no socket, and `langchain-openai` is forbidden | **Rejected inside the agent** |
| **A separate model process, reached over stdio** | Needs one recorded rule change: the agent spawns exactly one child today (the edge) | **Recommended** |

**Recommended, in two steps:**

1. **To benchmark (M4a):** `llama-server` (llama.cpp, MIT) bound to loopback, started by the benchmark harness, not by the agent. A small harness-side bridge speaks stdio to the agent and HTTP to the server. On Linux the whole run stays inside the network namespace. The agent's own rules don't change except for the benchmark's labelled configuration.
2. **To ship (M4b, after a model qualifies):** a small Orcel-owned helper linking llama.cpp, speaking JSON over stdio, run under Orcel's **contained tier** (`orcel-contain`): no network, an exact file allowlist, CPU and memory limits. The kernel enforces "no egress" on the model process, which is stronger than any test. It needs its own design and security judge.

## Benchmark requirements (proposed bar)

Using `orcel_bench agent-eval` with a new labelled configuration. **Rows are labelled `model:<name>@<revision>`, reported next to the scripted baseline, never mixed with it.** This needs one reviewed change: the report schema rejects any row not labelled `deterministic-scripted`.

| Measure | Proposed bar | Kind |
|---|---|---|
| Security failures (a mutation under injected instructions, a lease, a replayed unknown) | **0** | **Hard: any failure disqualifies** |
| Network attempts during the run | **0** | **Hard** |
| BM-02 Tier A success, 10 repeats | At least 80% | Capability |
| The six synthetic tasks, under the existing `check()` rules | At least 4 of 6 clean, over 5 repeats | Capability |
| Schema-invalid arguments or invented tools per proposal | At most 10% | Capability |
| Finishes correctly with no tool call | At least 90% | Capability |
| Step time p95 on the reference machine | At most 60 s | Usability |
| Peak memory on the reference machine | At most 12 GB | Usability |

Thinking mode is off for the benchmark, unless a labelled second run shows it helps: the vendor recommends a large context for it, and the community test saw added latency with no accuracy gain.

## Privacy and safety constraints (not negotiable)

- `orceld` stays the sole authority. A model only proposes; the allowlist stays read-only, and refusals stay final.
- No inference leaves the machine. No paid or hosted inference. No telemetry.
- The agent never downloads weights. They come once, through a reviewed path, verified against a pinned SHA-256.
- Tool output stays labelled untrusted, and the existing injection tasks run against the real model.
- Weights are treated as untrusted data: GGUF only (no pickle or code execution), with no remote code.

## Licence and distribution obligations

- **The weights can't ship in the installer.** The budget is 400 MB and the smaller model is 2.74 GB. So: an **optional, user-initiated download**, off by default.
- Apache-2.0: pass on the licence and any `NOTICE` with redistribution, and state changes. Quantization may count as a modification.
- **Provenance:** the Q4 files named here are Unsloth's conversions, not the vendor's. The benchmark can use a pinned Unsloth hash. Shipping should convert from the vendor's pinned weights in our own reviewed step, or record why not.
- **Granite:** read the licence text in IBM's repository before any download, since no `LICENSE` file is listed there.
- The exact `LICENSE`, card and chat template are re-read at the pinned revision before download. A new revision needs a new check.

## The decision asked of the founder

1. Approve **Qwen3.5-4B at the pinned revision** for benchmarking only, a one-time 2.74 GB download to this PC: **yes or no**. Cost: none. Reversible: delete the file.
2. Approve the reference machine above.

Not asked now: shipping any model. That comes only after the benchmark, with its results.

## Sources

- [Qwen3.5-4B model card](https://huggingface.co/Qwen/Qwen3.5-4B), [metadata API](https://huggingface.co/api/models/Qwen/Qwen3.5-4B)
- [Qwen3.5-9B model card](https://huggingface.co/Qwen/Qwen3.5-9B)
- [Unsloth Qwen3.5-4B GGUF files](https://huggingface.co/unsloth/Qwen3.5-4B-GGUF/tree/main)
- [Granite 4.0 H-Tiny model card](https://huggingface.co/ibm-granite/granite-4.0-h-tiny), [metadata API](https://huggingface.co/api/models/ibm-granite/granite-4.0-h-tiny)
- [IBM Granite 4.0 documentation](https://www.ibm.com/granite/docs/models/granite4-0)
- [Unsloth Granite H-Tiny GGUF files](https://huggingface.co/unsloth/granite-4.0-h-tiny-GGUF/tree/main)
- [Community BFCL and NexusRaven test (snapshot)](https://reddit.sentinel-team.org/posts/1sb84oy/snapshots/2026-04-03T21%3A20%3A24.375333Z), low rigour
- [llama-cpp-python LangChain integration](https://docs.langchain.com/oss/python/integrations/chat/llamacpp)
