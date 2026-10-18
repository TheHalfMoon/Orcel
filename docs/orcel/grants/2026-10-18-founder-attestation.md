# Founder attestation and plan adoption (2026-10-18)

Status: **ADOPTED founder decision**. This is the durable internal record that donor admission and the cross-platform plan cite. It holds nothing confidential.

## What the founder confirmed

On 2026-10-18 the founder stated in writing to the engineering agent:
- they hold full legal authorization covering the applicable donor-owned source code, including Cua, Firecrawl, Skyvern, Browser Use, Agent-Native, Perplexity SPACE and every other authorized source recorded in Orcel;
- the permissions include copying, modification, integration, commercial use, commercial distribution, redistribution and relicensing, within the scope of the applicable grants;
- the underlying agreements are confidential and will not be shared, uploaded or published;
- this statement is the formal founder attestation for internal engineering authorization;
- FD-04 and FD-06 of `docs/orcel/implementation-readiness/backlog/tasks.json` are founder-confirmed for the covered donor-owned code;
- engineering proceeds with the plan in `docs/orcel/implementation-readiness/`, including XP-02 and the remaining cross-platform backlog.

## How this record is read

- **FD-04 (Cua FSL components):** Cua-owned FSL-1.1-MIT components may be copied and distributed inside Orcel. A component is still used only when the architecture admits it.
- **FD-06 (AGPL donors):** the distribution scope of Firecrawl- and Skyvern-owned code includes redistribution and commercial distribution inside Apache-2.0 Orcel. This closes the open paragraph in `2026-10-13-founder-source-authorization.md`.
- **FD-01 (adopt the revision):** read as adopted from "PROCEED WITH THE APPROVED PLAN".
- **FD-02 (parallel track):** read as approved from "Continue XP-02 and the remaining cross-platform backlog". This reading is the record's own; the founder can correct it.
- **Still open:** FD-03 (Tauri direction), FD-05 (Mac runner and Apple Developer ID; no purchase without an explicit decision), FD-07 and FD-08.

## What it does not contain or change

- The agreements were **not** reviewed by the engineering agent and are not quoted, summarized or described here.
- A grant reaches only code its grantor owns. Third-party files inside a donor keep their own licenses. So do dependencies, model weights, datasets and trademarks: for example Cua's AGPL-3.0-only OmniParser model, and crawl4ai's attribution clause.
- Notices, attribution, provenance with object SHAs, dependency admission, and every security, review and release gate are unchanged.
