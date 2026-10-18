# Opus handoff: build cross-platform Orcel

Status: ADOPTED planning handoff (founder, 2026-10-18; `docs/orcel/grants/2026-10-18-founder-attestation.md`), authored by Fable. This is the one entry document for implementation. It grants no authority: each task becomes a SpecGrain and goes through normal governance. Where this file disagrees with merged code or a closed grain's record, the merged state wins and this file is corrected.

## 1. Exact frontier (verified 2026-10-18)

- Repository `TheHalfMoon/Orcel` (the former Aladdin repository; local folders named `Orcel-*` dated before 2026-10-09 belong to an older, unrelated repository: check `git log` before using any).
- `main` = `40fc9f0a17b158188d20084126e2742b1632002c` "Merge PR #343: founder-approved Orcel Signal identity"; CI and Pages green on that SHA.
- Active grains (`.specgrain/specs`): **SG-000096** shell and process sessions (GRAIN; issues #260, #264-#267, #271), **SG-000108** live browser engine (GRAIN; #289/#290). All other 97 specs CLOSED.
- Open PRs: **#336** SG-000108 slice 3b-i runtime pin (your active work; head `de5f88cb`, all checks green, **mergeable: CONFLICTING** with main), **#328** Hala research (CONFLICTING), **#342** website copy (MERGEABLE).
- CI: Rust and Node on ubuntu-latest + windows-latest; no macOS leg. Required checks per the main ruleset (ten contexts).
- Planning branch: `plan/fable-opus-readiness-20261018` (this package). The macOS research workspace named in the directive is not on this machine; donors were re-cloned at the pins in `donor_registry.json`.

## 2. Adopted and proposed architecture in one picture

```text
MCP clients ─┐                          ┌─ Control Room (Tauri 2, proposed; WPF kept until parity)
founder AI ──┼─► apps/orcel-mcp (Node) ─┤      └─ AgentKit client over app API (read-only first)
             │                          │
             └──────────────► orceld (sole authority: policy, approvals, leases, journal, dispatch)
                                 │
     ┌───────────────┬───────────┼──────────────────┬──────────────────────┬──────────────────┐
 orcel-platform   providers   computer host /2       browser host + worker   orcel-sandbox (opt.)
 (paths, ids,     fs git proc  Win: Go host (kept)    one engine, one pipe,   cua-vmm Runtime,
  peer creds,     clipboard    mac/Linux:             playwright-core 1.63.0  gVisor/QEMU/Lume/
  secrets,        network      orcel-native-host      + its tools/backend     Firecracker
  presence)                    (Rust + vendored Cua)
```

Decision register with statuses: ARCHITECTURE_DECISIONS.md. Founder-directed: three first-class OSes; copy first. Kept: single authority, tool names, browser engine choice, relay. Adopted: AD-04..AD-12, AD-14, AD-16, AD-17, AD-20. Proposed: AD-13 (Tauri Control Room, waiting on FD-03).

## 3. Remaining founder decisions (do not guess)

Resolved 2026-10-18 (`docs/orcel/grants/2026-10-18-founder-attestation.md`): FD-01 adopted · FD-02 parallel track approved · FD-04 FSL reuse confirmed · FD-06 AGPL distribution confirmed. Open: FD-03 Tauri Control Room direction · FD-05 self-hosted Mac runner and Apple Developer ID · FD-07 Windows host consolidation after data · FD-08 WebMCP engine flag. Details and defaults: IMPLEMENTATION_BACKLOG.md "Founder decisions".

FD-01 is resolved, so XP-05 onward is no longer blocked on adoption; each task still needs its own grain activation and gates.

## 4. Source reuse priorities and pins

1. Cua `a802eaf26ca97616a6bf0de6a29729a9346fbb1f`: `libs/cua-driver/rust/crates/{platform-macos, platform-linux, cua-driver-core, cua-driver-contract, cursor-overlay, pip-preview}`, `libs/cua-driver/tests/fixtures`, `libs/cua/crates/cua-vmm`.
2. Playwright tag v1.63.0 = `1b025d7e20a026371cd5f98ba0cdce48892737c8`: `packages/playwright-core/src/tools/backend/{snapshot,form,keyboard,mouse,files,tabs,dialogs,wait,verify,tab}.ts`.
3. Agent-Native `9c277b79cb87eb27da538e572dd710986e2fa06d`: `packages/agentkit/src/{protocol,client,conformance}`, `packages/core/src/agent/tool-call-journal.ts`.
4. Firecrawl `f84845c864b6e2af22791c18fcf89ac2a21f1434`: `apps/api/native/src/{crawler,pdf,document}.rs`, `apps/api/src/lib/{crawl-regex,canonical-url,map-cosine,change-tracking-diff}.ts`.
5. SPACE `09e922efd23b3c0d109ab64de7e567a901bcc61e`: `crates/libs/node/runtime/core/src/{fc_api,snapshot_files.rs}`, `crates/libs/spaced/guest/server/src/{process,idempotency,filesystem}.rs`.
6. browser-use `c75e8476e26d18b7617643bc2ae082fae8eae431`: `browser_use/dom/serializer/{clickable_elements,paint_order}.py`.
7. crawl4ai `94b67888ca8b335ff2121423a50e06dd27661922`: `crawl4ai/content_filter_strategy.py` (attribution clause).
8. Stagehand `f261c38b4dc50c39485f924e8599c1d3c6e37dc7`: `packages/extension/understudy/a11y/snapshot`, `understudy/page.ts`.

Every row with git object SHAs: SOURCE_TRANSPLANT_MATRIX.md. Verify before copying: `python -I docs/orcel/implementation-readiness/tools/readiness_check.py --donors <dir-with-owner_repo-checkouts> --verbose`.

## 5. Next 20 tasks in order

| # | Task | Why now | Depends on |
|---:|---|---|---|
| 1 | **XP-01** secure per-OS state directories | security fix, smallest, unblocks every non-Windows build | - |
| 1b | XP-01B policy stores off the temp fallback | same bug in authority-bearing stores (found in #345 review) | XP-01 |
| 2 | XP-02 macOS CI leg | catches regressions from here on | - |
| 3 | BM-01 report schema | every later task reports numbers in it | - |
| 4 | XP-04 host protocol /2 | contract for all native hosts | XP-02 |
| 5 | XP-03 identity primitives | pid generation, session, peer creds | XP-01, XP-02 |
| 6 | CR-01 app API transport (read-only) | F0 next slice, cross-platform from day one | XP-01, XP-03 |
| 7 | XP-05 vendor Cua, host workspace | first donor import | XP-02, FD-01 |
| 8 | XP-06 macOS/Linux observation | first user-visible cross-platform capability | XP-03, XP-04, XP-05 |
| 9 | XP-08 conformance fixtures and runners | evidence for everything after | XP-06 |
| 10 | XP-07 window capture | completes read-only parity | XP-06 |
| 11 | CR-02 AgentKit client | event contract for the Control Room | CR-01 |
| 12 | XP-15 clipboard | small, independent | XP-02 |
| 13 | XP-09 macOS approvals | gate for any macOS mutation | XP-01, XP-02 |
| 14 | XP-10 Linux approvals | gate for any Linux mutation | XP-01 |
| 15 | CR-03 Tauri Control Room (read-only) | after FD-03 | CR-02, FD-03 |
| 16 | XP-11 semantic actions macOS/Linux | first mutations off Windows | XP-06, XP-08, XP-09, XP-10 |
| 17 | RJ-01 kernel journal extraction | after SG-000108 closes | SG-000108-CLOSE |
| 18 | XP-12 raw input macOS/Linux | completes desktop parity | XP-11 |
| 19 | BR-01 stale-ref recovery | after SG-000108 closes | SG-000108-CLOSE |
| 20 | BR-02 typed browser actions | biggest browser capability gap | BR-01 |

Then RJ-02, RJ-03, XP-13, XP-14, WI-01..06, XP-16..19, XP-20, CR-04, SX-*. Full cards: IMPLEMENTATION_BACKLOG.md.

### First task, ready to start: XP-01

1. Branch from current `main`. Create `crates/orcel-platform` (add to the workspace members in `Cargo.toml`), with `paths::state_root()` and `paths::ensure_private_dir()` as specified in the XP-01 card.
2. In `crates/orcel-approval/src/lib.rs`, `default_approval_history_path()` currently returns `LOCALAPPDATA\Orcel\approval-history.jsonl` or `std::env::temp_dir()/orcel/approval-history.jsonl`. Make it return `Result<PathBuf, _>` from `state_root()`; keep `ORCEL_APPROVAL_HISTORY_PATH`. Propagate the error so `LocalApprovalBroker::new()` reports ProviderUnavailable rather than writing elsewhere (adjust its constructor signature or add a fallible constructor and keep the infallible one for Windows-only callers; pick the smaller diff and record why).
3. Same for `crates/orcel-audit/src/lib.rs` `default_audit_path()` (lines 72-84) with `ORCEL_AUDIT_PATH` kept.
4. Tests listed in the card; run `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --all -- --check`, `node scripts/check-current-identity.mjs`.
5. Windows behavior must be byte-identical: same path, same file format.

## 6. Must not be rewritten

- `orceld` authority, `orcel-policy` profiles and leases, `orcel-approval` ledger semantics (#286), `orcel-provider-uia` registry and bindings, `orcel-browser-host` policy modules, SG-000108 worker protocol shape, the Node MCP edge and its 40-tool contract, OAuth, pairing, relay, lifecycle on Windows, the Go Windows host (until XP-20 decides with data).
- Merged donor ports (browser-use extraction, MCP-B WebMCP pieces).

## 7. Must not be changed without the governed process

Tool names, scopes, failure-code vocabulary, `orcel-relay/1` frames, `ORCEL_*` env names, storage paths on Windows, SG-000074 argv allowlist, approval classes of existing tools, the no-evaluate and single-channel browser rules, required CI checks.

## 8. Review and testing for every task

Common gates (IMPLEMENTATION_BACKLOG.md top): exact-head CI on every touched OS, Jev exact-diff, Alibaba OCR delegation plus manual review of excluded files, a fresh-context judge, Graft for donor code, provenance + notices for imports, zero unresolved threads, normal merge. d1-local is advisory only and never counts as review. Fable's source inspection is not integration qualification: every capability needs its own Orcel tests on real OS sessions.

## 9. Definition of done for the cross-platform program

All rows of the CROSS_PLATFORM_ARCHITECTURE.md capability matrix marked "T" have Orcel evidence (run ids or attached reports) on their OS; the five roadmap journeys pass on Windows, macOS and Linux; installers pass clean-install tests on each OS within the 400 MB budget; the security acceptance tests in SECURITY_INTEGRATION.md section 5 pass; every import has provenance that `readiness_check.py --donors` verifies; and the canonical frontier records each closed grain.
