# M4 preparation: local model candidates (research only)

**Status: research only. This note selects no model and approves no model. It downloads nothing and runs nothing.**

M4 needs **founder decision 2**: which model, under which license, and how users obtain it (SG-000129 spec, `m4`). Until that decision is made, and the separate selection and licensing gate is passed, no model is downloaded or executed. This note prepares that decision.

## What the agent needs from a model

These requirements follow from SG-000129 M1–M3:
- **Tool calling.** The agent is a LangChain `ChatModelPlanner`. The model must emit tool calls against the edge's JSON schemas through its chat template, and must reliably answer with no tool call when it is done.
- **Local and offline.** No network egress during inference, and no telemetry. Weights are fetched once, through a reviewed path with a pinned hash, never by the agent at run time.
- **Consumer hardware.** CPU-only must work, even if slowly. Apple Silicon or a single consumer GPU should give acceptable step times.
- **A context window of at least 32k tokens.** M3 compaction keeps the conversation bounded: the peak was 98,941 characters (about 25k tokens) in the long-context evaluation.
- **A license compatible with Orcel's distribution model.**
  - Use restrictions that pass to every downstream user, or remote kill rights, are a significant burden.
  - Attribution or naming requirements must be reviewed.
  - A permissive license (Apache-2.0 or MIT) is the simplest path.

## Candidates

Every license entry below was stated from the cited sources and from background knowledge as of 2026-11. **Each one must be checked against the model's own `LICENSE` file and model card at the exact version and revision chosen.** Licenses change between versions.

| Family | Typical small sizes | License (to verify) | Tool calling | Notes |
|---|---|---|---|---|
| Qwen3 / Qwen3.5 (Alibaba) | about 4B–32B | Apache-2.0 for most sizes | Native, via its chat template | Strong reported agentic and tool-use scores (vendor-reported, unverified). The license must be checked per size, because some larger releases have used other terms. |
| Mistral Small (Mistral AI) | 24B | Apache-2.0 | Native function calling | Mistral's other models are under other terms (for example Codestral's non-production license), so the exact model is what matters. |
| IBM Granite | about 2B–8B | Apache-2.0 | Marketed for enterprise function calling | Small sizes suit CPU-only use. |
| Microsoft Phi-4 family | about 4B–14B | MIT | Weaker than its reasoning focus | MIT is the simplest license; tool-calling quality must be measured. |
| Google Gemma 3 / Gemma 4 | about 1B–27B | Gemma Terms of Use with a Prohibited Use Policy that passes to every downstream user, plus a Google right to restrict usage (Gemma 3); a separate license for Gemma 4 | Weaker native tool calling (Gemma 3) | The flow-down terms and the restriction right are a burden for a distributed desktop agent. Read Gemma 4's own license; secondary claims about it conflict. |
| Meta Llama 3.x / 4 | about 8B (3.x); larger MoE (4) | Llama Community License | Mature ecosystem | Not an open-source license: a 700M-monthly-active-user threshold, a "Built with Llama" display requirement, naming limits, and an EU restriction on Llama 4's multimodal capabilities. |

## Hardware: a rough planning rule (not measured)

With 4-bit quantization, the weights take about 0.55–0.65 GB per billion parameters, plus the KV cache for the context.

| Model size | Weights at 4-bit | Plus about 32k context |
|---|---|---|
| ~4B | about 2.5 GB | fits 8 GB of RAM |
| ~8B | about 5 GB | fits 16 GB |
| ~14B | about 9 GB | needs 16–24 GB |
| ~24–32B | about 15–20 GB | needs 32 GB, or a 24 GB GPU |

CPU-only speed falls with model size. The benchmark below must measure it on reference machines before a size is chosen.

## Benchmark plan, for after the gate

Reuse the slice 6 harness (`orcel_bench agent-eval`) unchanged, adding a **real-model configuration**. Its rows are labelled `model:<name>@<revision>`, never `deterministic-scripted`, and are reported next to the scripted baseline, never mixed with it.

1. **BM-02 Tier A through the model.** Measure success, Orcel calls, refusals, malformed proposals and step time.
2. **The six synthetic tasks**, scored by the same `check()` rules:
   - a `stop_reason` run is never clean;
   - no mutation under injected instructions;
   - no lease;
   - kill and resume surfaces the cut-off call as unknown.
   A model may fail tasks; it may never cause a security failure.
3. **Tool-calling robustness:**
   - schema-invalid arguments;
   - invented tools;
   - finishing correctly with no tool call;
   - behaviour after a refusal.
4. **Resources:** peak RSS, tokens per second and step p50/p95 on the reference machines (CPU-only, Apple Silicon, one consumer GPU).
5. **Egress:** run inside the slice 1 network-denying harness; any connection attempt fails the run.

## What the founder decides

1. Which model family, size and exact revision.
2. Whether its license is acceptable for Orcel's distribution model.
3. How users obtain the weights, for example a separate download with a pinned hash, or a bundled copy. Each option has its own review and cost implications; none is decided here.
4. The reference machines for the benchmark.

## Sources

- [Gemma Terms of Use](https://ai.google.dev/gemma/terms)
- [Gemma Prohibited Use Policy](https://ai.google.dev/gemma/prohibited_use_policy)
- [Llama 3.3 Community License Agreement (text mirror)](https://open.windriver.com/info/uni-license-list/licenses/llama-3.3-license-2024.html)
- [Llama Community License: the 700M MAU threshold (summary)](https://conductatlas.com/platform/meta/llama-community-license-agreement/provision/CA-P-060923/700-million-mau-commercial-license-threshold/)
- [Open-weight LLM comparison 2026](https://wavect.io/blog/open-weight-llm-comparison-2026.md)
- [Open source LLMs in 2026: the definitive comparison](https://letsdatascience.com/blog/open-source-llms-in-2026-the-definitive-comparison)

Secondary roundups disagree in places. The model's own license and card govern.
