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

How this record is read: see the founder decision below, which replaces the earlier reading of this section.

## Founder decision: licences no longer block (2026-11-17)

Status: **OWNER-ASSERTED AUTHORIZATION.** Typed by the founder on 2026-11-17 and relayed verbatim to the engineering
agent by the coordinating agent. The founder's sentence, verbatim:

> all sources i have sent to you and all sources in the repo are legally and i have permission to copy all of them and re name them to orcel. so not worry about the licness anymore

How Orcel records it:

- Licence type no longer blocks copying, renaming or publishing any source the founder has sent or any source in the
  repository. This replaces the `PUBLIC_REDISTRIBUTION_NEEDS_GRANT_EVIDENCE` designation and the "AGPL/GPL only as a
  separate component" designation in the transplant ledger and in the readings of the earlier sections of this file
  and of the 2026-10-13 and 2026-10-18 records where they conflict.
- Each record in `docs/orcel/implementation-readiness/prep/TRANSPLANT_LEDGER.json` keeps the upstream licence facts as an
  informational `public_licence` field beside `authorization: OWNER-ASSERTED (founder, 2026-11-17)`.
- **This authorization is owner-asserted. It has not been independently verified**, no copyright-holder-signed grant is
  in the repository, and the engineering agent did not review the underlying agreements.
- Copies keep the upstream copyright, licence and NOTICE texts, and a provenance record (repository, SHA, paths).
  Required attribution stays even where product names are changed.
- Things that are not sources in the repository are not covered by this sentence and keep their own terms: model
  weights downloaded from model hubs (read each model card before download), hosted services and their terms of
  service, and trademarks.
- It gives no access to private source. Private repositories still need authorized credentials and exact names.
- Architecture choices made for other reasons (for example the separate `apps/orcel-firecrawl` process in
  UNIFIED_INTEGRATION_SPEC.md) stay until changed by their own decision; they are no longer required by licence.
- WP1-01 gates: every donor in `docs/orcel/notices/donor-provenance.json` cites the authorization reference
  **OWNER-ASSERTED AUTHORIZATION, founder 2026-11-17** (defined there and in `docs/orcel/notices/licence-policy.json`,
  both pointing at this record). No gate refuses AGPL, GPL, LGPL, MPL, SSPL, BUSL, FSL, commercial or unlicensed code or
  dependencies; the gates require provenance and preserved notices, and dependency licences are reported, not judged.

## Vercel source expansion (2026-11-17)

Status: **OWNER-ASSERTED AUTHORIZATION — 2026-11-17, labelled summary.** Recorded by the engineering agent on 2026-11-17 from the
founder's Vercel source expansion as relayed by the coordinating agent. The wording is the recording agent's summary, not the
founder's verbatim text. The founder can correct it. **This is not independent legal verification.**

What the founder decided and asserts:

- The open "Vercel agent-use" question is resolved as **both** `vercel-labs/agent-desktop` and `browser-use/desktop`. They are
  separate donors. `browser-use/desktop` is owned by the browser-use organisation, not by Vercel.
- All useful repositories of the `vercel` and `vercel-labs` GitHub organisations are in scope, including the 25 the founder named.
- The founder states rights beyond the public licences for these sources. Under the founder decision above, licences do not block
  copying. The original licence of each source is kept as information, provenance and notices.

How Orcel records it:

- Each record carries `authorization: OWNER-ASSERTED AUTHORIZATION — 2026-11-17` beside the informational `public_licence`. The
  records are group I (founder-named) and group J (found by a discovery sweep) of
  `docs/orcel/implementation-readiness/prep/TRANSPLANT_LEDGER.json`, with `vercel_expansion` in the same file and section 8.7 of
  `DONOR_INVENTORY.md`.
- **Owner-asserted, not independently verified.** No copyright-holder-signed grant is in the repository, and the engineering agent
  did not review any underlying agreement.
- Copies keep upstream copyright, licence and NOTICE texts and a provenance record (repository, SHA, paths). Third-party files inside
  a donor keep their own notices, for example axe-core (MPL-2.0) in agent-browser, the GPL test fixtures in just-bash and Mbed TLS
  (Apache-2.0 OR GPL-2.0-or-later) in quickjs-wasi.
- Not covered: hosted services and their terms (Vercel Sandbox, AI Gateway, Workflow on Vercel, Vercel Connect), model weights and
  trademarks. The Vercel Sandbox microVM backend is not public and is not made available by this record.
- Security, review, dependency-admission and release gates are unchanged.
