# SG-000135: Orcel Browser Session Broker, browser-full profile and Full Access browser leases

Status: activated grain (state GRAIN), 2026-11-17, base `main` `48ae7a1247d5d793775c5b753d325dcff051b5e6`.
The spec is [`.specgrain/specs/SG-000135.json`](../../../../.specgrain/specs/SG-000135.json). This page is a short
guide to it. Nothing here is implemented, and the activation adds no code, tool, listener or authority.

## Founder inputs

The founder's two documents of 2026-11-17 are kept outside the repository: the Orcel Browser architecture decision
and the Shadow Mode and collaboration requirements. Both are marked as not implemented. The grain quotes them in
its `decisions`. In short:

- Orcel Browser is a real headed Chromium browser that people can use with no agent. Agent sessions run on it.
- Shadow Mode runs in an isolated profile and context. It never uses the OS mouse, keyboard, clipboard or focus.
  Visible Mode is allowed. Shadow changes where the work runs, not what it may do.
- There is one Session Broker and one authorization system for every engine. BrowserOS is the chassis.
  browser-harness and browser-use, agent-browser, Stagehand and Obscura are engines or adapters.
- Profiles are persistent and managed by Orcel. Orcel never attaches to a user's default personal profile.
  Import needs consent. Passwords go only through the vault or the browser's autofill, never to the model or logs.
- Full Access is a lease. The owner enables it, can revoke it, and bounds it by scope and time. Routine actions
  inside the lease run with no repeated prompt, because orceld really caches the lease. An action outside the lease
  asks once for the missing scope. High-impact actions need an explicit, narrow standing policy. MFA, passkeys and
  CAPTCHAs are never bypassed: the person gets a Needs-you handoff, and the task resumes on its own afterwards.
- When a person acts on an agent-owned page, that resource pauses at once. A 3000 ms quiet timer restarts on each
  human event. Then the agent re-observes, and the human's edits win. An uncertain submit is never repeated
  automatically.
- ChatGPT gets a remote `browser-full` profile through the Secure MCP Tunnel. Local stdio comes first. ChatGPT is
  never claimed to work without an end-to-end test, and Orcel cannot turn on tools the product does not allow.
- Agent tasks can run at the same time, each with its own budget, and every action has a verifiable receipt.

The founder's own words from the chat directive of 2026-11-17, quoted in the grain:

- "All five must operate through one Orcel Browser Session Broker and one Orcel authorization system."
- "Full Access grants eliminate repeated approvals for routine actions already authorized by the owner."
- "The current Orcel remote MCP profile does not expose browser actions. Implement an explicitly authorized remote
  browser capability profile. Do not merely copy BrowserOS's MCP server and claim that ChatGPT can already control
  it. Prove an actual end-to-end browser task over local MCP, then validate the ChatGPT tunnel integration where the
  client supports it."

## Where the code is today

The read-only code map was taken on `48ae7a12`, with PR #794 and PR #797 read but not merged. Main has one
governed browser:

- It has one lifetime and one page, runs headless, and gets a throwaway profile for each launch.
- It admits one origin per lifetime.
- It is local only (`browser_structured`) and exists only in Windows `live-browser-dev` builds.
- Each consequential action needs its own SOFT approval.

The single browser slot is `crates/orceld/src/live_dispatch.rs:95-98`. The approval calls are in
`live_browser.rs:1295,1431`. Main has no broker, tabs, screenshot, persistent profile, lease covering browser
actions, remote browser path, takeover or challenge detection.

## Work packets, in order

| Packet | Content | Main acceptance |
|---|---|---|
| OB-00 | This activation | A0 |
| OB-01 | Broker, persistent Orcel-managed profiles, budgets, concurrent sessions | C, F, H, Shadow 8 |
| OB-02 | Local `browser_full` profile on existing shapes | C |
| OB-03 | Screenshot frame and tabs | C |
| OB-04 | Shadow and Visible modes (headed argv) | E, F, Shadow 1 and 2 |
| OB-05 | Evidence receipts on the audit chain | H, J |
| OB-06 | Takeover state machine, 3000 ms quiet timer | G |
| OB-07 | Challenge handoff, autofill through the browser vault | I |
| OB-08 | Full Access lease caching (interim store, then the SG-000132 service) | E, Shadow 5, Full Access 4 and 6 |
| OB-09 | Remote `browser_full` mapping for ChatGPT | D |
| OB-10 | BrowserOS human browser, packaging, consented import (later, on a Chromium-sized build volume) | A, B, K, Shadow 7 |

Dependencies:

- PR #794 (contracts) must merge before OB-01 and OB-08.
- WP1-03 (the audit chain) must merge before OB-05.
- PR #797 should merge before `browser_extract`, so that there is one extract path.

## Rule changes recorded before implementation

- **SG-000108 (closed).** It allowed one page, ran headless, gave each launch a throwaway profile and admitted one
  origin per launch. For `browser_full` only, this grain allows several sessions and tabs, a headed Visible mode,
  persistent profiles and a set of admitted origins per session. The rest is unchanged: pipe-only attachment, no
  page script, host-verified engines and the navigation layers.
- **SG-000122 (closed).** For `browser_full`, this grain adds tabs, free typing with named keys, and clicks on any
  actionable node (not only links). Secret fields are still refused for filling and typing. Credentials go only
  through the browser's autofill vault or the person.
- **SG-000079 (closed).** Its "no remote mapping" rule is lifted for `browser_full` only, by OB-09.
- **SG-000132 (active).** This grain adds an amendment entry. The Browser executor is enabled under its dispatcher,
  with a browser lease scope of profiles, origins, sessions, action families and expiry. Browser leases start on the
  existing Hello-gated full-control store and move into the authority service when WP1-10 lands. An interim lease
  ends at the move; it is never converted. Pending founder confirmation, the interim store never covers a remote
  caller; the alternative is
  remote coverage on the interim store, gated by the existing SG-000055 STRONG remote-session lease.
- **Spec section 4.15.** It says a standing approval never covers remote callers. The founder lifted this for the
  remote `browser_full` profile only, and only for the identified client named in the lease.
- **Engines (B0 inventory).**
  - Every engine attaches with `--remote-debugging-pipe`; no adapter may use `--remote-debugging-port`.
  - A donor process such as claw-server runs only behind orceld, with a per-launch token that orceld holds, on a pipe
    or loopback. It never runs as an unauthenticated listener or as a second MCP endpoint.
  - These are excluded: `solve_captcha`, and for now `credentials`, `payment_cards`, `evaluate_in_page` and `run`.
  - BrowserOS pins Chromium 155.0.8059.26. Orcel qualifies engines by major version, and Chromium 155 is qualified.

## Open choices, fail closed until each packet records them

1. The multi-origin model. The default is to relaunch for each set of admitted origins; the other option is to
   widen the resolver rules by lease.
2. Where human events come from in Visible mode, given that page script stays forbidden.
3. The headed argv set.
4. The signals that mark an action as high-impact. A submit's effect cannot be known in advance; this is recorded
   as a limit, as SG-000122 did.

## Review

Every packet needs exact-head CI and Review Gates. The packets that touch authority, isolation or remote access
(OB-01, OB-04, OB-06, OB-07, OB-08, OB-09 and OB-10) each also need a fresh-context security judge. d1-local is
advisory only and never clears a gate.
