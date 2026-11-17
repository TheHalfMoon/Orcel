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
release gate are unchanged. (The licence gates are changed by the later decision below.)

## Later the same day: owner-asserted authorization for every source

Status: **RECORDED founder decision**, typed by the founder and relayed to the engineering agent by the coordinating
agent on 2026-11-17. Verbatim:

> all sources i have sent to you and all sources in the repo are legally and i have permission to copy all of them and re name them to orcel. so not worry about the licness anymore

How it is recorded and applied:

- The authorization reference is **OWNER-ASSERTED AUTHORIZATION, founder 2026-11-17**. It is owner-asserted: no
  copyright-holder-signed grant is in the repository, and the engineering agent has not reviewed the underlying
  permissions. It covers every source the founder has sent and every source in the repository, including renaming to
  Orcel.
- A licence type no longer blocks any change: the WP1-01 gates no longer refuse AGPL, GPL, LGPL, MPL, SSPL, BUSL, FSL,
  commercial or unlicensed code or dependencies, and they no longer enforce the isolated-component reading above.
- What stays: every copied donor file keeps its provenance (source repository, pinned commit, source path, the
  original licence recorded as it is, the original copyright or attribution notice preserved, and this authorization
  reference) in `docs/orcel/notices/donor-provenance.json`, checked by `scripts/check-donor-provenance.mjs`.
  `docs/orcel/notices/licence-policy.json` records the same decision. Dependency licences are reported, not judged.
