# Founder source authorization (2026-10-13)

Status: **ADOPTED founder decision**. This is the durable internal record that the donor permission gate refers to:
- `docs/aladdin/SOURCE_PERMISSIONS.md`;
- the Firecrawl "Permission gate" in `docs/canonical/DESKAL_P20_DONOR_LEDGER.md`.

It is deliberately minimal and holds nothing confidential.

## What the founder confirmed

On 2026-10-13 the founder confirmed in writing to the engineering agent that the necessary official permissions have been obtained to **copy, modify, integrate and rebrand** source code from:
- **Firecrawl:** `firecrawl/firecrawl`, the code its grantor owns;
- **Skyvern:** `Skyvern-AI/skyvern`, the code its grantor owns;
- **the WebMCP donors** already admitted in `docs/aladdin/SOURCE_REUSE_MATRIX.md`.

The founder also stated that:
- the permission documents are confidential;
- they need not be disclosed or committed to the repository;
- this explicit authorization is sufficient internal approval to proceed.

This builds on the founder's attestation of 2026-10-12 recorded in `docs/aladdin/SOURCE_PERMISSIONS.md`.

## Distribution: how this record reads the scope

The gates ask for evidence covering copy, modification, combination, redistribution and commercial distribution under Aladdin's license (Apache-2.0). The founder's words were "copy, modify, integrate, and rebrand", and did not enumerate redistribution or commercial distribution separately.

This record reads two things together as covering distribution of the integrated code as part of Aladdin:
- the permission to **integrate** the code into Aladdin, a product distributed under Apache-2.0;
- the founder's instruction that this authorization is **sufficient internal approval** and must not block authorized implementation.

That reading is the record's own, not a further statement by the founder. **Confirmed by the founder on 2026-10-18** (redistribution and commercial distribution included): `docs/orcel/grants/2026-10-18-founder-attestation.md`. The founder holds the documents and is the party who would correct it. A one-line founder confirmation of the distribution scope would replace this paragraph.

## What this record does not contain

- **No details beyond what was given.** It does not name licensors or signatories, and it does not cite document numbers or terms, because none were provided. None may be added unless the founder provides them.
- **No copies or excerpts of the confidential documents.**

## What it satisfies, and what it does not change

- **What it satisfies:** it is the durable direct-permission evidence for the gates named above. An import of grantor-owned Firecrawl or Skyvern code may merge once its own change is qualified, and it names this file in its provenance.
- **Provenance and notices are unchanged.** Exact donor commit SHAs, per-file attribution headers, provenance records with blob SHAs, and the donor's notice under `docs/aladdin/notices/` are still required. For the AGPL donors, the notice records the upstream license and this authorization.
- **Third-party licenses are unchanged.** Files a donor carries under another party's license, and every dependency (crates, npm packages), keep their own licenses and their own admission: integrity, SBOM and supply-chain audit.
- **Security and architecture are unchanged.** The SG-000074..SG-000108 invariants, browser confinement, the host's policy authority, and every review and test gate apply to copied code exactly as to Aladdin's own.
- **Models are out of scope.** Rights for models are not covered.
