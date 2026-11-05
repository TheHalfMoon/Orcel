# Founder decision packet: the next product milestones

**Prepared 2026-11-04.** Only decisions that block the next major milestone, in priority order. The complete list of gates is `FOUNDER_DECISIONS.md`. **Nothing here is decided by this document, and none of these is enabled.** Total cost of what is recommended: **none**.

Reply with the numbers and your answer, for example: "1 will do; 2 yes; 3 yes; 4 yes; 5 yes; 6 A; 7 A".

| # | Decision | Recommended | Milestone it unblocks |
|---|---|---|---|
| 1 | Run the approval journey yourself, about 15 minutes, after about 20 for CI to build | Do it | Core MVP (F4) |
| 2 | Allow task stop without paid signing | Yes | Core MVP (F4) |
| 3 | Download two files to benchmark one model: the weights (2.74 GB) and `llama.cpp`'s runner (19.5 MB) | Yes | First real model capability |
| 4 | Tauri for one desktop app on all three OSes | Yes | Cross-platform app |
| 5 | Activate forms in the browser (narrow SG-000122) | Yes | Browser usable for real tasks |
| 6 | Release builds and the browser | A: stay development-only for now | F4 closeout |
| 7 | Read a workbook in the report task, through the confined parser | A: yes | F5 spreadsheet journey |

---

## 1. Run the client approval journey (F4 slice 4)

- **Unlocks:** the first evidence of a real client driving Orcel to a verified report with your approval, one of F4's acceptance items.
- **Recommended:** run `prep/F4_SLICE4_CLIENT_JOURNEY.md` with Claude Code. Alternatives: Codex; or later.
- **Security and licensing:** you answer real prompts; no agent can do this for you. An unsigned build on your own PC, in a scratch folder. You temporarily remove your configured workspaces from Orcel's list (files untouched), and restore them afterwards.
- **Cost:** none, about 15 minutes, after about 20 for CI to build.
- **Evidence:** the same journey up to the prompt passes in CI on every commit (#453); the kit checks the outcome (#608).
- **Unqualified:** the approved commit through a real client has never run. That is the point.
- **Reversible:** yes. It writes a scratch folder, Orcel's configuration (the workspace list, which you restore) and Orcel's journal and approval history. `orcel uninstall` removes the build.

## 2. Allow `task.stop` without paid signing (F4 slice 5)

- **Unlocks:** stop and takeover in the Windows app, F4's remaining functional items, without buying a certificate.
- **Recommended:** option 2, amend the rule for this one method. Alternatives: buy signing first; or record stop as open in F4. Details and the exact text: `prep/F4_SLICE5_AMENDMENT.md`.
- **Security:** stop can only remove the ability to write. **You would accept one residual:** another program running as you could stop your in-flight report tasks. That is denial of progress, not new authority, and such a program can already kill orceld. Licensing: none.
- **Cost:** none.
- **Evidence:** the kernel work and its race tests (#607). Nothing is exposed yet.
- **Unqualified:** the method, the app's Stop control and its UI test don't exist yet. A security judge is required before it merges.
- **Reversible:** yes: remove the method, or add a publisher check once signing exists.

## 3. Download two files to benchmark one model (M4)

- **Unlocks:** the first measurement of real model capability. Today, every agent result is scripted.
- **Recommended:** benchmark only, on this PC, exactly these two files, each verified against its pinned SHA-256 (listed in the package): `Qwen3.5-4B-Q4_K_M.gguf` (the weights) and `llama-b11567-bin-win-cpu-x64.zip` (a third-party **executable**, llama.cpp, MIT, which runs them on your PC). Fallback, only if it misses the bar: Granite 4.0 H-Tiny. Alternatives: a larger Qwen on better hardware; or wait. Details: `prep/M4-selection-package.md`.
- **Security and licensing:** Apache-2.0, no use restrictions passing to users. Local only, no paid inference, no telemetry, and the agent stays read-only under `orceld`. The file is a third-party conversion, so it is pinned by hash; shipping would convert from the vendor's weights.
- **Cost:** none in money; about 2.76 GB of disk.
- **Evidence:** licence and tool-calling documentation read from the vendor at the pinned revision. **No independent tool-call score exists for this model**; the nearest is a small community test of its larger sibling.
- **Unqualified:** everything about its real capability. It may fail the bar, and then the honest result is "no qualified model yet".
- **Reversible:** yes: delete the files. **Not asked now:** shipping any model.

## 4. Tauri for one desktop app (FD-03)

- **Unlocks:** the same Orcel window on Windows, macOS and Linux. Today only Windows has one.
- **Recommended:** Tauri 2, keeping WPF on Windows until a parity gate. Alternatives: Electron (conflicts with "no bundled browser"); three native apps (slowest); WPF only. Details: `prep/CROSS_PLATFORM_DEV_BUILDS.md`.
- **Security and licensing:** MIT/Apache. Strict CSP, no remote content, no shell or filesystem plugins. It starts read-only: authority delta none, and the UI never answers approvals.
- **Cost:** none. Unsigned development builds need no Apple membership.
- **Evidence:** the toolkit-neutral client exists and is tested on all three OSes (CR-02); the comparison is in `AGENT_RUNTIME_INTEGRATION.md`, its numbers unmeasured.
- **Unqualified:** no Tauri code exists yet. WebKitGTK accessibility is a known risk.
- **Reversible:** yes. WPF stays until the parity gate passes.

## 5. Activate forms in the browser (narrow SG-000122)

- **Unlocks:** an agent can fill in and submit a form on an admitted page, with your approval per action. Today it can only read, click links and download.
- **Recommended:** the narrow first scope in `prep/SG-000122.md`: fill, select, check, Enter to submit, text waits, the verifier. Alternatives: the full scope (adds uploads, dialogs, tabs); or wait.
- **Security:** `orceld` stays the sole authority, with one approval per action, bound to page, element and value. Local only, Windows only, development builds only. **Three limits to accept:** fields that look secret are refused, but a secret typed into an ordinary field isn't detected; a page's script can read a filled value and send it to its admitted origin without a submit; and the effect of pressing Enter can't be known in advance, so the limit is the one admitted destination. It widens SG-000108's A13 and decision 4, which is why it needs you. Licensing: already-admitted code.
- **Cost:** none.
- **Evidence:** the host and worker actions pass their native tests (BR-02, BR-07).
- **Unqualified:** the orceld dispatch and MCP tools don't exist yet, and no agent has used them. Showing the value in the prompt and an Enter-only limit are new work. Each slice needs its own review.
- **Reversible:** yes: remove the tools from the profile tables.

## 6. Release builds and the browser (F4 slice 7)

- **Unlocks:** with A, a clear F4 closeout; a browser in a distributed build comes later.
- **Recommended:** **A: stay development-only for now.** Then, if you want a browser in the first distributed build, B: Node from its official installer in Program Files. Alternatives C and D, and the design conflict behind them: `prep/F4_SLICE7_RELEASE_BROWSER.md`.
- **Security:** A changes nothing. B keeps the folder rule, but needs recorded changes and its own judge. Licensing: Node and playwright-core notices would ship under B.
- **Cost:** none for A or B.
- **Evidence:** the browser is qualified on Windows in development builds (SG-000108). No release-build run exists.
- **Unqualified:** any release path. A browser update can also disable it until Orcel updates.
- **Reversible:** yes.

---

## Not asked now

- **SG-000115 activation:** stays off, with its residuals not accepted. Mitigation work continues.
- **SG-000096 shell, SG-000124 and SG-000125 sandboxes, signing, publication:** none blocks the milestones above.
- **F4 stays unexited while signing is open.** Its closeout records engineering qualification only, as the spec requires.

## 7. Read a workbook in the report task (F5, Journey 2)

- **Unlocks:** a workbook to a verified report with source cell references, on any machine, with no Excel and no desktop control. Full proposal: `prep/F5_SPREADSHEET_JOURNEY.md`.
- **Recommended:** A, the confined parser. Alternatives: B, installed Excel through a read-only COM adapter, which needs a licensed Excel and a new automation surface; C, stay on text sources, which leaves the journey open.
- **Security and licensing:** a hostile workbook is the realistic threat. The parser has no network and can't start processes, macros are refused, and nothing is calculated or followed. `report_start`, a local-only tool, would accept a binary source, which is why this needs a grain. No new dependency. Packaging the parser brings its zip advisory exceptions into shipped code: they're recorded as unreachable, and they're not accepted risk.
- **Cost:** no money. It does bring those exceptions into shipped code.
- **Evidence, pending merge when this was written:** on #617, the reader passes on files from XlsxWriter and openpyxl and on two of Apache POI's samples of Excel 12.0 files. An earlier version of it passed under containment on all three OSes. On branch `f5/parse-verified-bytes`, the test-only integration passes the full journey locally on Linux with scripted consent, including a denial then a fresh approval, a changed workbook going stale and false figures refused.
- **Unqualified:** a current Excel's files. A real approval. A value is only what the file last saved, since nothing recalculates. Opening the workbook on screen is left out. The proposal lists what's still needed before exposure.
- **Reversible:** yes, slice by slice. Nothing a client can reach changes until slice 3.
