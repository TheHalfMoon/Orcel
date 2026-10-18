# Source permissions

Status: **ADOPTED founder decision (2026-10-12)**. This record changes which donor source may be copied. It grants no runtime authority: every import still needs its own exact-head qualified change, with its provenance record, notices, tests and review gates.

## Founder attestation

On 2026-10-12 the founder stated: "i have official permission to copy and use the source codes from all sources. apply this on the project."

The founder therefore attests that official permission is held to **copy, use, adapt and rename source code** from the donors. This record applies the statement to every donor repository recorded in `SOURCE_REUSE_MATRIX.md`; that limit is this record's choice, made so that each donor stays pinned, licence-checked and listed, and a donor added to the matrix later is covered on the same terms. A permission reaches only **code its grantor owns**: files a donor itself carries under another party's license (third-party files, vendored packages, datasets with their own attribution) keep that license, whatever the permission says. The permission covers the copyleft donors that were previously reference-only for want of a written grant:

| Donor | Public license | Previous rule | Rule from 2026-10-12 |
|---|---|---|---|
| [Firecrawl](https://github.com/firecrawl/firecrawl/tree/f84845c864b6e2af22791c18fcf89ac2a21f1434) `f84845c` | AGPL-3.0 (engine) | Behavioral reference only; native rebuild (founder decision 2026-10-11) | Grantor-owned code may be copied and adapted under this permission; the gate below is satisfied by the founder authorization of 2026-10-13. |
| [Skyvern-AI/skyvern](https://github.com/Skyvern-AI/skyvern/tree/f5f3f28a9ce0021a1db24286928a7bff6582a1eb) `f5f3f28` | AGPL-3.0 | Behavioral reference only | Grantor-owned code may be copied and adapted under this permission; the gate below is satisfied by the founder authorization of 2026-10-13. |

For permissive donors (MIT, Apache-2.0, BSD) nothing changes. Their licenses already allow copying and renaming, provided the copyright and permission notices travel with the copied code.

## Update 2026-10-18

The founder confirmed in writing that the authorization covers copying, modification, integration, commercial use, commercial distribution, redistribution and relicensing of the covered donor-owned code, including Cua (FSL components included), Firecrawl, Skyvern, Browser Use, Agent-Native and Perplexity SPACE. Record: `docs/orcel/grants/2026-10-18-founder-attestation.md`. The agreements remain confidential and were not reviewed by the engineering agent. Everything in the next section still applies.

## What the attestation does not change

- **Notices and provenance.** Every copied or adapted file keeps an attribution header (donor, path, commit). Every import keeps a provenance record with blob SHAs and a modification summary, plus the donor's notice under `docs/orcel/notices/`. For the AGPL donors the notice records the upstream license **and** this permission.
- **Architecture and authority.** The SG-000074..SG-000108 invariants still apply to copied code, whatever its license. In particular, no code path may evaluate caller-, model- or page-supplied script, and no second channel into the browser is allowed. Donor code that breaks an invariant is not copied, however permissive its terms.
- **Dependencies.** A donor's third-party dependencies (crates, npm packages) are separate works. Each is admitted on its own license, with integrity, SBOM and supply-chain audit, as for playwright-core.
- **Models.** This record covers source code only. The written-grant requirement for redistributing or rebranding models (`ORCEL_AI_SERVER_ARCHITECTURE.md`, `MODEL_INTEGRATION_CONTRACTS.md`) is unchanged.

## The permission documents, and the gate they open

**Updated by the founder decision of 2026-10-13** (`docs/orcel/grants/2026-10-13-founder-source-authorization.md`). The founder confirmed that the necessary official permissions are held to copy, modify, integrate and rebrand grantor-owned Firecrawl and Skyvern source code and the WebMCP donor sources. The founder also confirmed that the documents are confidential and need not be committed. That record is now the durable direct-permission evidence for the gate below. An import of grantor-owned code merges once its own change is qualified and names the record in its provenance. Notices, provenance, dependency admission, security review and every test and review gate are unchanged. The distribution scope is read as that record explains. The text below is kept as the history of the gate and no longer applies; it is **superseded on 2026-10-13**.

*(Superseded 2026-10-13.)* The permission documents themselves are **not in the repository yet**. Orcel is distributed under Apache-2.0. AGPL-3.0 code may be distributed under other terms only if the copyright holders' permission allows it, so each document must state that scope: copy, modification, combination, redistribution and commercial distribution under Orcel's license.

The existing gate stays as written. `docs/canonical/ORCEL_P20_DONOR_LEDGER.md` (Firecrawl, "Permission gate") requires the owning grain to reference durable evidence that the permission covers the intended use before any Firecrawl-owned source is copied into a distributable artifact, and `apps/orcel-mcp/src/p20-architecture.test.ts` asserts that gate. This record applies the same gate to Skyvern:
- *(Superseded 2026-10-13.)* **Until the document is filed,** AGPL donor code may be studied, and an import may be prepared and reviewed on a branch. It is **not merged** into `main`, which feeds every release.
- *(Superseded 2026-10-13: the documents stay confidential and are not filed.)* **Filing:** put a copy of each document, or its durable reference, in `docs/orcel/grants/` (one file per donor: grantor, date, scope, contact), and have counsel confirm the scope (`ORCEL_MASTER_PLAN.md`, the open item "Written rights grants").
- *(Superseded 2026-10-13: the importing change names the founder authorization record instead.)* **After filing,** the importing change names that file and this record in its provenance, and the merge may proceed.
