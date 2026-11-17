# Founder attestation: unified-platform donors (2026-11-17)

Status: **RECORDED founder attestation**, relayed to the engineering agent by the coordinating agent in the Claude Code
session on 2026-11-17 as part of the founder's answers to FD-UP-1 to FD-UP-13
(`docs/orcel/implementation-readiness/prep/UNIFIED_INTEGRATION_SPEC.md`, section 11). The wording below is the
recording agent's summary of the relayed answer, not the founder's verbatim text; the founder can correct it.

## What the founder confirmed

- The founder holds full legal permission to copy and adapt authorized donor code, naming Firecrawl and Browser Use
  and including other authorized donors and authorized private repositories.
- Firecrawl is to reach full feature parity with a copy-first approach.
- Orcel's core stays independently licensed where necessary. Code under AGPL that cannot enter the core runs as an
  isolated, locally operated component (a separate process and package behind an interface), with its licence
  obligations preserved, including the source offer.

## How this record is read

- This is a founder attestation. It is recorded separately from, and does not replace, the documented upstream
  licence terms in `docs/orcel/implementation-readiness/prep/DONOR_INVENTORY.md`.
- It extends the 2026-10-13 and 2026-10-18 records. No copyright-holder-signed grant is in the repository, and the
  underlying agreements were not reviewed by the engineering agent.
- A grant reaches only code its grantor owns. Third-party files inside a donor, dependencies, fonts, models and
  trademarks keep their own licences.
- Engineering reading (the record's own, correctable by the founder): new bulk copies of AGPL-licensed Firecrawl code
  go into the isolated component `apps/orcel-firecrawl` under AGPL-3.0 with notices and source; the Apache-2.0 core
  keeps only its own code and the already-recorded FD-06 files.
- Which donors are "authorized" is the set the founder has named in these records. Donors listed only in the
  inventory (for example Obscura, Crawlee, Scrapling, agent-browser, phone-harness, Mika, Fleet, agent-desktop) are
  used under their documented upstream licences unless the founder names them in a later record.

## What it does not change

Notices, attribution, provenance with SHAs, licence gates, dependency admission, and every security, review and
release gate are unchanged.

## Master directive (2026-11-17)

Status: **OWNER-ASSERTED AUTHORIZATION, labelled summary.** Recorded by the engineering agent on 2026-11-17 from the
founder's master directive as relayed by the coordinating agent, together with the founder's own statements in the
REA plan files `D:\Orcel-REA-W2\REA_ROUND2_PLAN.md` and `D:\Orcel-REA-W3\REA_WAVE3_COPY_FIRST_PLAN.md` (outside this
repository). The wording is the recording agent's summary, not the founder's verbatim text, except the two quotations
below, which are copied from those plan files. The founder can correct it. **This is not independent legal
verification.**

Founder statements quoted in the plan files:

- Wave 2 plan: "all these sources i have full legal permission to copy the source and re name it to orcel."
- Wave 3 plan: "all of them i have the full legal permission to copy their source code and re name it to orcel"

What the founder asserts:

- Full legal permission to copy, adapt and rename into Orcel the source of every one of the 50 sources named in the
  master directive (groups A to H). The resolved repositories and pinned SHAs are the `records` of
  `docs/orcel/implementation-readiness/prep/TRANSPLANT_LEDGER.json`. This names Obscura, Crawlee, Scrapling, Fleet and
  agent-desktop, so the previous section's "used under their documented upstream licences" reading no longer applies
  to them; the upstream licences are still recorded beside this assertion.
- Copy-first transplant is the intended method: acquire, pin, copy and adapt, integrate, test, qualify.

How this record is read:

- It is kept separate from the public licence terms. Each ledger record carries both fields, and neither replaces the
  other.
- No copyright-holder-signed grant is in the repository. For a source whose public licence does not permit publishing
  copied code in this public repository (no licence, commercial, proprietary, FSL non-compete), the ledger marks
  `PUBLIC_REDISTRIBUTION_NEEDS_GRANT_EVIDENCE` and names the evidence needed: a written grant from the copyright holder
  covering redistribution under Orcel's terms. This assertion does not count as that evidence. It does not block
  private or local engineering.
- AGPL and GPL code is published only under its own licence as a separate component (FD-UP-1), whatever this record
  says.
- The assertion reaches only code its grantors own. Third-party files, vendored code, dependencies, model weights,
  datasets, binaries, fonts and trademarks keep their own terms. Required copyright and attribution notices stay even
  where product names are changed.
- It gives no access to private source. Private repositories still need authorized credentials and exact names.
