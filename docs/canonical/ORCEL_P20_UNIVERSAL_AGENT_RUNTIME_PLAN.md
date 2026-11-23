# ORCEL-P20 Universal Agent Runtime Plan

Status: ACTIVE PROGRAM PLAN
Program: ORCEL-P20
Activation grain: SG-000092
Planning base: `835200a90fd47425ff3ad40b5b8815dc8ad7871c`
Date: 2026-10-07

## 1. Product objective

ORCEL-P20 turns Orcel from a bounded trusted computer-access layer into a user-selectable universal local agent runtime while preserving one authority boundary: Orcel decides what an AI client may do, and donor implementations only execute already-authorized work.

The target is one Orcel connection through which an AI client can, when the user enables the corresponding mode:

- inspect and modify files available to the selected Windows authority;
- run PowerShell, CMD, WSL, Git, Node, Python, package managers, build tools, and long-running or interactive processes;
- launch, focus, inspect, and close applications and windows;
- capture windows or the desktop, inspect accessibility state, and control mouse and keyboard;
- use structured UI Automation first, visual grounding second, and raw foreground input as the final fallback;
- browse, scrape, crawl, map, search, extract, and parse web and document content;
- reuse a signed-in user browser only when the user explicitly selects that browser-control mode;
- perform administrator operations after the user grants a legitimate elevated Windows session;
- expose the same governed runtime locally or remotely when a separately local-issued remote full-control lease permits it;
- diagnose which backends are healthy and route to an available backend without silently widening authority.

P20 is reuse-first. Existing authorized, proven implementations are copied, adapted, or isolated as sidecars before any new implementation is written.

## 2. Non-goals

P20 does not implement:

- UAC bypass, Windows Hello bypass, secure-desktop automation, credential-provider bypass, or privilege escalation without an OS-issued token;
- stealth credential harvesting or password-field extraction;
- model self-approval, model self-grant, donor self-grant, or remote self-grant;
- hidden persistence;
- generic unauthenticated LAN listeners;
- arbitrary donor MCP servers exposed beside Orcel;
- mandatory paid APIs, cloud VMs, hosted browser services, or founder-funded cloud infrastructure;
- runtime download of donor source or floating `latest` dependencies.

## 3. Reuse-first rule

For every P20 capability:

1. search the pinned donor set and current Orcel implementation;
2. reuse a technically suitable implementation if permission and dependency obligations are satisfied;
3. preserve the donor source language and isolate it as a private host when that minimizes rewriting and risk;
4. port only the narrow mechanics that cannot be safely packaged as-is;
5. write new code only for Orcel-specific authority, adapters, integration, supervision, or a genuinely missing capability.

The intended engineering ratio is integration-heavy, not rewrite-heavy. No percentage is an acceptance claim; exact reuse is measured from the final provenance ledger.

## 4. Authority modes

### 4.1 Safe

Safe preserves the shipped bounded Orcel model and current compatibility behavior. Existing workspace, approvals, protected executable registry, P18 computer-use ceilings, and remote restrictions remain available as the conservative default.

### 4.2 Full User

Full User is a locally granted, revocable `FullControlLease` bound to:

- local Windows user and logon session;
- device identity;
- Orcel session;
- tool-surface profile;
- policy revision and lease epoch;
- issue time and expiry or explicit session lifetime;
- optional remote principal binding when remote use is separately enabled.

While valid, routine operations inside the current user's native Windows authority do not require a fresh per-click or per-command approval. The user can revoke the lease at any time.

### 4.3 Full Admin

Full Admin is Full User plus an `AdminLease` backed by a real elevated Windows token. The user approves Windows elevation through the normal OS mechanism. After that approval, the privileged broker may service requests within the granted Orcel lease without another UAC prompt for every command.

Full Admin never means bypassing UAC, Windows Hello, CredentialUIBroker, secure desktop, or Windows credential boundaries.

### 4.4 Persistent Admin

Persistent Admin is a separate opt-in mode. It may maintain a privileged broker across ordinary client restarts only after a dedicated grain proves install, service identity, ACLs, caller authentication, token lifetime, update, revoke, crash recovery, and uninstall semantics.

Persistent Admin is never enabled merely because Full Admin was used once.

### 4.5 Remote Full Control

Remote Full Control requires both normal remote authentication and a locally issued `RemoteFullControlLease` bound to the exact principal, device, route/session epochs, local full-control profile, expiry, and local policy revision.

A remote caller cannot create, widen, renew, persist, or convert a Safe session into Full User, Full Admin, or Persistent Admin.

## 5. Runtime architecture

```text
AI / MCP client
      |
Orcel MCP edge
      |
orceld authority kernel
      |
      +-- FullControlLease / AdminLease / RemoteFullControlLease
      +-- policy / audit / revoke / result-state contract
      |
      +-- private Computer Host
      |     Open Computer Use-derived Windows implementation
      |
      +-- private Shell Host
      |     Desktop Commander-derived terminal/process implementation
      |
      +-- private Web Host
      |     Firecrawl-derived scrape/crawl/extract implementation
      |
      +-- private Elevation Host
      |     gsudo-derived elevation/cache mechanics
      |
      +-- Capability Router / Doctor
      |     Agent Reach-derived routing/probe model
      |
      +-- optional Visual Agent Adapter
            UI-TARS-derived action parsing / model adapter
```

Only the Orcel edge is caller-facing. Sidecars use private per-user IPC or inherited stdio/named-pipe channels, authenticate their parent/session, expose no public listener, and do not decide authority.

## 6. Execution preference

Desktop interaction follows this order:

1. semantic UI Automation or application-native action;
2. browser DOM/accessibility action when the target is a governed browser page;
3. visual proposal grounded to a fresh screenshot or capture;
4. coordinate/raw foreground input.

Failure at a higher layer does not silently authorize a lower layer. The active profile must already permit the fallback class.

## 7. Computer Host

The Windows Computer Host reuses the Open Computer Use Windows runtime rather than rebuilding UI Automation, Win32, GDI capture, SendInput, app/window discovery, key parsing, drag, scrolling, or coordinate freshness mechanics.

Target Orcel operations include:

- app list and launch;
- window list, get, activate, minimize, maximize, restore, and close where supported;
- app/window state with accessibility tree and optional screenshot;
- click, double-click, right-click, drag, move, scroll;
- Unicode text entry, key, and hotkey;
- set-value and semantic accessibility actions;
- exact-window and whole-desktop capture according to the active profile;
- cursor position and multi-monitor coordinate normalization.

The donor's caller-facing MCP contract is not exposed. Orcel assigns identities, profiles, leases, audit records, and remote eligibility.

## 8. Shell and process Host

The Shell Host reuses Desktop Commander terminal and process mechanics.

Target operations include:

- one-shot shell execution;
- PowerShell, pwsh, CMD, WSL, and configured Unix-like shells;
- long-running process sessions;
- stdin interaction and REPL support;
- bounded stdout/stderr pagination;
- process/session listing;
- graceful stop and force termination;
- descendant/process-tree cleanup on lease revoke where technically supported;
- explicit cwd, environment, timeout, output and resource ceilings.

Safe mode keeps the current registered-executable behavior. Full User permits shell execution under the current user. Full Admin routes an authorized elevated request through the privileged broker.

## 9. Filesystem and clipboard

P20 extends, rather than discards, Orcel's existing filesystem identity and mutation code.

Full User may address paths available to the current user, subject to canonicalization and Windows reparse-point/device-path handling. Full Admin may address paths available to the elevated token.

Target parity includes:

- text and binary reads/writes;
- ranged and paginated large-file reads;
- list, stat, find, search, copy, move, rename, mkdir, edit, and recursive removal when the active full-control profile permits it;
- explicit overwrite semantics;
- rich-file helper paths where useful for PDF, DOCX, XLSX, and images;
- clipboard read/write under the selected local authority.

No caller-supplied path is trusted before canonical target resolution.

## 10. Elevation Host

The Elevation Host reuses the gsudo service/cache/RPC model selectively.

Initial P20 elevation supports administrator high-integrity execution only. SYSTEM and TrustedInstaller modes are excluded from the initial authority surface.

Required properties:

- one user-visible OS elevation grant;
- broker authentication bound to the expected local Orcel process/session and user SID;
- private named-pipe or equivalent IPC with ACL verification;
- bounded lease duration and explicit revoke;
- no generic public elevation endpoint;
- process output and exit-state forwarding;
- broker termination on revoke, uninstall, policy invalidation, or unsupported identity drift;
- no silent conversion from user authority to administrator authority.

## 11. Browser modes

P20 supports three explicit browser modes.

### Isolated browser

The P18 Orcel-owned automation profile remains the conservative browser default.

### Existing user browser

The user may explicitly enable control of an existing signed-in browser session. This mode is separate from isolated browser automation, is visibly disclosed, and is bound to the FullControlLease.

The implementation prefers browser-native/structured control when safe and can fall back to desktop computer control. P20 does not require exporting browser cookies to provide this workflow.

### Full desktop browser

Chrome, Edge, or another browser can be controlled as an ordinary desktop application through screenshot/UIA/input when structured browser integration is unavailable.

## 12. Web Host

The Web Host selectively reuses Firecrawl source without shipping the full hosted SaaS stack.

Reuse targets:

- scrape request normalization and result model;
- engine selection and fallback;
- fetch and Playwright/browser mechanics that are suitable for local packaging;
- HTML cleanup and Markdown transformation;
- sitemap and robots handling;
- crawl discovery and URL traversal;
- map/link discovery;
- structured extraction;
- document/PDF parsing where dependencies are locally supportable;
- browser action/replay model;
- abort, timeout, retry, typed-error, safe-mode, and threat-check patterns.

Excluded hosted product layers include billing, credits, hosted teams/organizations, hosted account management, cloud telemetry, hosted concurrency accounting, GCS persistence, mandatory managed proxies, and cloud-only infrastructure.

The preferred browser engine integration is a `orcel-browser` adapter that lets Firecrawl-derived pipelines use the already-supervised Orcel browser host instead of launching an unrelated second authority surface.

## 13. Search and capability routing

The Capability Router adopts Agent Reach's ordered-backend and health-probe model.

A capability record includes:

- stable capability name;
- ordered backend candidates;
- user override;
- exact backend identity/version;
- installation/configuration state;
- lightweight executable health probe;
- credentials/config status without secret disclosure;
- active backend;
- fallback policy;
- local/remote eligibility.

Initial capability families include desktop, shell, admin, browser, web.read, web.scrape, web.crawl, web.search, GitHub, YouTube/media tooling, and other installed CLI/MCP integrations.

`orcel doctor` and machine-readable equivalent must report real usability rather than executable presence alone.

## 14. Visual Agent Adapter

UI-TARS-derived code is proposal-only.

```text
fresh Orcel screenshot
    -> selected model/VLM
    -> UI-TARS-compatible action parser
    -> ComputerActionProposal
    -> Orcel target/lease/policy validation
    -> Orcel executor
    -> fresh observation and postcondition
```

No model output can mint a Orcel target ID, approval, FullControlLease, AdminLease, RemoteFullControlLease, or execution result.

A local UI-TARS model is optional. The connected AI host may perform visual reasoning instead.

## 15. Remote control

P18 remote device, relay, OAuth, route binding, and lease-isolation foundations are retained.

P20 may reuse Desktop Commander reconnect, heartbeat, duplicate-delivery, local-executor recovery, and atomic session-persistence patterns, but not its hosted service as Orcel's authority backend.

Remote mutation must preserve exactly-once or deduplicated dispatch semantics where supported. A reconnect never invents success or automatically retries an already-dispatched mutation.

## 16. Emergency stop and revoke

A local emergency stop must invalidate, at minimum:

- FullControlLease;
- AdminLease;
- RemoteFullControlLease;
- active raw-input authority;
- browser action leases;
- active shell and process sessions where termination is supported;
- queued but not dispatched mutations;
- privileged broker acceptance;
- optional persistent-admin service authorization.

After revoke, new work requires a new local grant.

## 17. Failure semantics

All mutating providers expose or are wrapped into these states when technically possible:

- `not_started`;
- `dispatched`;
- `completed`;
- `cancelled`;
- `outcome_unknown`.

No provider crash, transport timeout, or reconnect may be represented as success without postcondition evidence.

Mutation is not automatically retried after dispatch. A new attempt requires fresh state and current authority.

## 18. Resource and privacy bounds

Every host receives explicit hard ceilings for:

- process count and descendant count;
- stdout/stderr and retained history;
- input payloads;
- screenshots, pixel count, byte size, and capture rate;
- accessibility tree size/depth;
- browser tabs/pages and transfers;
- scrape/crawl URL counts, bytes, redirects, depth, queue size, and lifetime;
- document size/pages;
- IPC frame size;
- concurrent local and remote actions.

Raw screenshots, page bodies, clipboard data, credentials, terminal output, file contents, and secrets are not emitted to ordinary telemetry or diagnostic logs.

## 19. Packaging

Donor code is pinned and shipped as source-built Orcel components or bundled fixed-version sidecars. No production path uses `npx ...@latest`, a floating Git branch, runtime clone, or runtime package download.

The release SBOM and third-party notices enumerate every imported package and binary.

Sidecars are versioned against a Orcel private-host protocol. A protocol mismatch fails startup rather than falling back to an uncontrolled executable.

## 20. Donor and license rule

Every copied file or substantial adapted implementation records:

- donor repository;
- exact commit;
- source path;
- applicable file/package license or direct-permission evidence;
- third-party dependency obligations;
- Orcel destination;
- COPY / ADAPT / PORT / REFERENCE / REJECT classification;
- modification status;
- owning SpecGrain;
- tests and qualification evidence.

Firecrawl's public repository root is AGPL-3.0. The founder has stated that separate direct permission exists to use Firecrawl-owned source. Before Firecrawl-owned code is imported, the implementation grain must attach or reference a durable evidence record establishing the rights needed for the intended copy, modification, combination, redistribution, and commercial distribution. Third-party code and dependencies remain governed by their own licenses.

## 21. Grain sequence

### SG-000092 - P20 architecture, donor, and authority freeze

Planning/provenance only. No donor import or authority delta.

### SG-000093 - Full-control authority and profile model

Implement Safe, Full User, Full Admin intent, FullControlLease, AdminLease shape, local grant/revoke, expiry, policy binding, emergency revoke integration, and exact tool-profile rules. No donor executor exposure yet.

### SG-000094 - Windows Computer Host import

Import/adapt the pinned Open Computer Use Windows implementation behind private Orcel IPC. Prove app/window discovery, accessibility observation, capture, and host supervision without exposing input yet.

### SG-000095 - Desktop input and full computer-control surface

Expose qualified semantic UIA actions, screenshots, cursor, click/double/right, move, drag, scroll, Unicode text, keys, hotkeys, and window lifecycle under Full User. Preserve screenshot/window freshness and human interruption behavior.

### SG-000096 - Shell and process sessions

Import/adapt Desktop Commander terminal/process mechanics for one-shot and interactive execution, output pagination, process/session lifecycle, descendant cleanup, and Safe-vs-Full User policy.

### SG-000097 - Full filesystem and local workstation parity

Complete full-user filesystem, large/binary file, copy, recursive mutation, clipboard, process inspection/termination, and developer-workstation parity without weakening path identity or result semantics.

### SG-000098 - Full Admin elevation broker

Import/adapt gsudo elevation/cache mechanics for one-UAC administrator sessions. Bind broker identity to Orcel, implement AdminLease dispatch, output/result forwarding, expiry, and revoke. SYSTEM/TrustedInstaller remain absent.

### SG-000099 - Persistent Admin lifecycle

Separately implement optional persistent administrator service install, ACLs, authentication, lifecycle, restart, update, rollback, revoke, and uninstall. Default off.

### SG-000100 - Browser profile expansion

Retain isolated P18 browser mode, add explicit user-browser control, and qualify structured-browser-to-desktop fallback without cookie export as a requirement.

### SG-000101 - Local web scrape and extraction runtime

Import/adapt the Firecrawl scrape pipeline, engine model, transformations, safe local browser integration, timeouts, retries, typed errors, and structured output while excluding hosted SaaS layers.

### SG-000102 - Crawl, map, documents, and bounded web jobs

Add crawl/map/sitemap/robots, PDF/document parsing, bounded multi-URL jobs, cancellation, progress, storage limits, and local-only persistence where required.

### SG-000103 - Capability router and doctor

Adapt Agent Reach's ordered backend, real probe, override, health, fallback, and diagnosis model. Add `orcel capabilities` and `orcel doctor` machine-readable parity.

### SG-000104 - Visual grounding and model adapters

Integrate the pinned UI-TARS action parser/adapter and optional model loop behind ComputerActionProposal. Prove no model-to-authority shortcut.

### SG-000105 - Remote Full Control

Map qualified local full-control capabilities through the existing relay only under a locally issued RemoteFullControlLease. Prove cross-principal/device/session isolation, reconnect behavior, deduplication, revoke, and no remote self-grant.

### SG-000106 - Unified installer, sidecar lifecycle, update, rollback, and emergency stop

Package all selected hosts, provenance, licenses, SBOM, startup supervision, version/protocol compatibility, update/rollback, repair, uninstall, and kill-switch behavior.

### SG-000107 - P20 adversarial qualification and release exit

Run native Windows end-to-end, adversarial, privacy, resource, failure, remote, elevation, packaging, supply-chain, and tool/profile parity qualification. Close only with no exposed unverified P20 capability.

## 22. Native Windows acceptance matrix

P20 release qualification includes real Windows evidence for:

- Explorer, Notepad, Settings, Windows Terminal, PowerShell, CMD, VS Code, Chrome, and Edge;
- launch/focus/minimize/maximize/restore/close;
- click/double/right/drag/scroll/move;
- Unicode typing and hotkeys;
- UIA set/invoke/select/toggle/scroll where supported;
- screenshot and mixed-DPI/multi-monitor coordinates;
- stale screenshot/window movement and process/HWND replacement;
- long shell processes, interactive REPLs, large output, cancellation, and termination;
- user-authority and elevated-authority file/process/service operations;
- one-UAC admin session, expiry, revoke, broker crash, and restart;
- isolated and signed-in browser modes;
- web scrape, crawl, map, dynamic page, PDF, and document paths;
- capability backend failure and fallback;
- local and remote emergency revoke.

## 23. Review and merge discipline

Every P20 grain uses:

- one active grain at a time unless a later canonical plan explicitly proves safe independence;
- normal merge commits only;
- no rebase, squash, force-push, or history rewrite;
- exact-head CI and expected-head merge;
- independent code review of the exact head, recorded on the PR (from 2026-11-23; before that, genuine TypeSafe Jev exact-diff semantic review);
- targeted security review for authority, permissions, filesystem boundaries, network or privilege, with negative and adversarial regression tests;
- Alibaba Open Code Review exact-range review;
- manual review of unsupported/excluded security-sensitive files;
- zero unresolved blocking review threads;
- post-merge canonical verification.

Windows-only claims require native Windows evidence.

## 24. P20 definition of done

P20 is complete only when one Orcel connection can perform the full intended user-authorized workflow across computer control, shell/processes, filesystem, browser, web, and optional administrator authority; remote use is locally leased; donor provenance is complete; emergency revoke works; no hidden parallel authority surface exists; all exposed capabilities are qualified; release artifacts are reproducible and supply-chain documented; and SG-000107 closes canonically.
