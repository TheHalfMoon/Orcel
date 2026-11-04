# F4 slice 7: live browser in release builds, proposal

**Status: PROPOSAL, NOT ACTIVE.** Nothing is enabled. Release builds carry no live browser, and release qualification asserts it. The spec makes this "a separately governed change with its own security judge and an amendment to the canonical record". Until then the browser journey is qualified in development builds only, and the F4 closeout must say so.

## Where it stands

| Fact | Source |
|---|---|
| The live path exists only with the non-default `live-browser-dev` feature, which pins the SHA-256 of `node.exe` and the worker's runtime tree at build time | `docs/security/SG-000108_PRODUCT_CALLER.md`, decision 7 |
| Release builds report the browser as typed unavailable, and qualification checks the tools are absent | decision 7; `release_qualification.rs` |
| Decision 7 says a future "SG-000106" replaces the pin with a signed, pinned Node runtime and worker in the payload. **No SG-000106 spec exists yet** | decision 7; `.specgrain/specs/` |
| A pinned launch refuses a `node.exe` in a folder the current user can change, because Windows loads a DLL planted beside an executable first | decision 7 |
| Orcel installs **per user**, under `%LOCALAPPDATA%\Orcel`, which the user can write | `crates/orcel-lifecycle` |

**So the two rules collide.** A runtime shipped in Orcel's per-user payload sits in a user-writable folder, which the pinned launch refuses. Any release path must resolve this.

## Options

| Option | Unlocks | Cost | Security effect | Reversible |
|---|---|---|---|---|
| **A. Stay development-only for F4 (recommended now)** | The F4 closeout records engineering qualification only, with the browser and signing as open gates. F4 is not recorded as exited while signing stays open (spec) | None | None | Yes |
| **B. Per-machine runtime**: `node.exe` from the official signed Node.js installer in Program Files; worker and playwright-core in the payload | Release browser with no change to the folder rule | None in money; **needs a machine-wide Node install, which needs admin**. An exact-hash pin refuses any other Node build, so a Node update disables the browser until Orcel is updated | Keeps the folder rule, hash pin, directory holds and resolve guard. **Needs recorded changes**: see below | Yes |
| **C. Per-user runtime with an amended folder rule**: ship the official Node binary in the payload | No prerequisite for the user | None | **Weakens a recorded rule.** The argument for it: a same-user attacker who can plant a DLL there can already rewrite `orceld` itself in a per-user install. That argument applies to B's worker tree too, and it needs a judge, not an assertion | Yes |
| **D. Wait for signed, per-machine packaging** | The strongest form | Paid signing (FD-05 and a Windows certificate) | Strongest | Yes |

**Recommendation.** A for F4. If the founder wants a browser in the first distributed build, **B next**: it costs no money, and it keeps the folder rule and the way the worker is already pinned. C only with its own judge.

**What B still changes in the recorded design:**

- Paths are compiled in today. A per-user worker path can't be known at build time, so it must be derived at run time from the install, which touches decision 7's "never from a user-writable runtime setting". It needs a stated rule: derived from orceld's own verified install, never configured.
- Decision 7 says release stays unavailable until SG-000106 ships Node in the payload. B replaces that sentence, so it needs a canonical amendment.
- Decision 7's "what the pin is not" is written for development builds: the host and `orceld` are user-writable. In a per-user release that stays true, so the pin doesn't defend against a same-user attacker there either.

## What a release path must decide (whichever option)

1. **Where the pin comes from.** Today it is compiled in at build time. A release can do the same, from the packaging step, so the digest is in the binary and in `manifest.json`.
2. **Engine.** The worker drives an installed Edge or Chrome, verified by discovery. Release needs a stated policy for engines newer than those in `QUALIFIED_WORKER_ENGINES` (`crates/orcel-browser-host/src/discovery.rs`): refuse, or warn.
3. **Exposure.** The six live tools (`browser_page_open`, `browser_navigate`, `browser_observe`, `browser_click`, `browser_download_preview`, `browser_download`) stay in `browser_structured`. Whether release serves that profile by default, or only after an opt-in, is part of this decision. **Recommended: opt-in per workspace.**
4. **Size.** The installed release is about 25 MB against a 400 MB budget. The worker and playwright-core add little; a shipped Node binary adds roughly 80 to 100 MB (measure before relying on this). All options fit.
5. **Licenses.** Node.js (MIT with bundled notices) and playwright-core (Apache-2.0) are already admitted for development; shipping them needs their notices in `THIRD_PARTY_NOTICES` and the SBOM.

## Security review needed before any release path

| Risk | Status |
|---|---|
| Engine sandbox and confinement (resolver pinning, no-route proxy, service-worker block) | Qualified by SG-000108 on Windows, in development builds |
| Windows only | macOS and Linux need SG-000115, **not activated**, with its residuals not accepted. A release browser is Windows-only until then |
| #438 | One mechanism fixed (#606). The 0-request timeouts are unexplained; they fail closed and typed |
| Download and activation under approval | Qualified by SG-000108's journey, in development builds |
| Reversal | Removing the feature from the release build removes the path entirely |

## Unqualified

No release-build run of the browser exists. Every option above other than A needs a release-qualification journey, a fresh-context security judge and the canonical amendment before it could ship.
