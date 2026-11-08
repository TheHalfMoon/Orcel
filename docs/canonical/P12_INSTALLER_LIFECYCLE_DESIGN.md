# COTRA-P12 Installer and Lifecycle Design

> **Windows state root, 2026-11-07:** it is now `%USERPROFILE%\.orcel`, not `%LOCALAPPDATA%\Orcel`, which this document may still name. Other software on an ordinary account can hold rights on `AppData` that Orcel rightly refuses. See `crates/orcel-platform/src/paths.rs` and `legacy.rs`.

Status: canonical design review for the COTRA-P12 program, authored after the COTRA-P11 exit (merge `b69c5ba7cf9b4a6c2009e301ccc1eda97f934353`, post-merge CI `36785474877`) and before any P12 implementation grain.

Scope: `ARCHITECTURE_AND_DELIVERY_PLAN.md` section 23 (COTRA-P12), section 20 (Secure MCP Tunnel integration), section 21 (zero-cost architecture rule), the threat model (`docs/security/THREAT_MODEL.md`), and the closed `cotra-tunnel` supervisor.

This document is the complete design review required before P12 implementation. Implementation grains must not contradict it; a deviation requires a governance change recorded in this file, never a silent implementation choice. SpecGrain identifiers after the first P12 grain are assigned by each grain's own activation packet and are deliberately not asserted here.

## 1. Constraints

- Zero founder cost: no paid certificates, CI, signing services, installer frameworks, or hosted infrastructure. GitHub Actions and GitHub Releases on the existing public repository are the only release infrastructure in scope.
- Per-user install: no administrator privileges are required for install, start, stop, status, doctor, update, rollback, or uninstall. The installer refuses avoidable elevation: a UAC split-token administrator who chose "Run as administrator" is refused so that no administrator-context files land in the user's profile. A system without a split token (UAC disabled, as on CI runners) cannot drop elevation; installation proceeds there and the residual is documented (amended by SG-000042).
- No Windows service. Evidence: SOFT approval is delivered through an interactive `MessageBoxW` prompt and STRONG approval through Windows Hello in the user's interactive session (`cotra-approval`). A session-0 service cannot present either prompt, so a service install would break the approval boundary. A service model may only be introduced by a later governance change with hardening evidence.
- Local first: the only network activity introduced by P12 is a loopback-only (`127.0.0.1`) probe of the health endpoint that the official tunnel client itself advertises. No update check, telemetry, or download is performed by Cotra (section 7).
- Cotra does not reimplement the OpenAI Secure MCP Tunnel. It configures and supervises the official tunnel-client executable through the closed `cotra-tunnel` validation and launch-plan code.
- No fabricated health. Every `status` and `doctor` field is derived from an inspection actually performed; a check that cannot be performed is reported as `unknown`, never as healthy.
- Secrets never appear in logs, model-visible output, child environments, support output, or lifecycle transcripts. The tunnel runtime key is passed to the tunnel client by `file:` reference only, as the closed launch plan already does.
- P12 adds no MCP tool and no capability to the agent surface. Every P12 surface is a local CLI invoked by the human user.

## 2. Prerequisite finding: protected Cotra state is not isolated from trusted workspaces

Design review of the existing code found that `cotra-policy` admits any existing directory as a workspace root, and every workspace-scoped provider (filesystem read, search, and write; Git; scoped browser uploads and downloads) is bounded only by that root. Cotra protected state (`trust.jsonl`, `approval-history.jsonl`, `audit.jsonl`, and `browser-profile` under `%LOCALAPPDATA%\Cotra`, or their configured overrides) is therefore reachable by agent tools whenever the user trusts a directory that contains it, for example the user profile or a drive root. The P12 installer would add configuration, binaries, and the tunnel runtime key under the same root, which would turn this gap into secret exposure.

The canonical plan requires protected Cotra surfaces to be excluded from automation (threat model T05: "deny protected Cotra paths where enforceable"), so this is a pre-existing release blocker. It is repaired by the first P12 grain, before any installer code lands:

- the policy kernel computes the protected Cotra state roots (the Cotra state root plus every configured state-file override);
- a configured workspace whose resolved final root equals, contains, or is contained by any protected root is refused when the policy engine is constructed, so `cotrad` fails closed at startup with a typed workspace denial;
- comparisons use resolved final Windows paths (existing prefixes canonicalized, case-insensitive on Windows), not string prefixes;
- junctions or symlinks inside a workspace that point into protected state remain denied by the existing final-path containment checks, which the grain regression-tests.

## 3. Components

The release payload contains only what is required at runtime:

- `cotra.exe` — the lifecycle CLI (install, uninstall, update, rollback, tunnel setup, start, stop, status, doctor, version) and the internal `supervise` mode used by `start`;
- `cotra-mcp-host.exe` — the stdio launcher the tunnel client executes as its MCP command; it locates the active version, builds the sanitized environment, and runs the compiled `cotra-mcp` app with the validated Node.js runtime;
- `cotrad.exe` — the closed policy kernel daemon, unchanged;
- `app\cotra-mcp\` — the compiled `cotra-mcp` JavaScript plus its production dependency tree only;
- `manifest.json`, `LICENSE`, and third-party notices.

`cotra-tunnel.exe` remains a developer binary and is not installed; its library is reused by `cotra.exe`. Node.js is a validated prerequisite, not redistributed (section 4). The official tunnel client is user-provided and not redistributed.

## 4. Install layout and prerequisites

Install root `R` = `%LOCALAPPDATA%\Cotra` (the existing Cotra state root, so one protected tree holds everything):

- `R\bin\cotra.exe` — stable copy of the active version's lifecycle CLI, optionally added to the user `PATH`;
- `R\versions\<version>\` — immutable verified payload per version (`cotra.exe`, `cotra-mcp-host.exe`, `cotrad.exe`, `app\`, `manifest.json`); at most the active and one previous version are retained;
- `R\current.json` — the single activation pointer (`version`, manifest SHA-256), replaced atomically by write-temp-then-rename;
- `R\install.json` — install record (installed versions, previous version, whether a `PATH` entry was added);
- `R\state\config.json` — schema-versioned user configuration (workspaces, tunnel profile, Node.js path);
- `R\state\secrets\tunnel-runtime-key` — the tunnel runtime key file;
- `R\state\update.json` — pending or failed update marker;
- `R\logs\` — bounded, redacted lifecycle and tunnel-client logs;
- `R\run\` — supervisor record, stop-result record, and the tunnel health URL file;
- existing retained history: `R\audit.jsonl`, `R\approval-history.jsonl`, `R\trust.jsonl`, `R\browser-profile\`.

Prerequisites, validated fail-closed by `install` and reported by `doctor`:

- Windows 10 build 17763 or later, or Windows 11;
- no avoidable elevation (see section 1);
- Node.js 20 or later at an absolute path (auto-detected from `PATH` or given with `--node`), verified by actually running `node --version`;
- the official tunnel client is required only by `tunnel setup` and `start`, not by `install`.

ACLs: `install` sets a protected DACL on `R` granting full control only to the installing user's SID and `SYSTEM`, with object and container inheritance propagated to existing children. It then reads the DACL back and fails the install unless the DACL is protected and contains no other principal. No `Users`, `Authenticated Users`, `Everyone`, or world-writable entry is ever created. `doctor` re-verifies the same property.

## 5. Artifact model and install flow

A release directory contains `manifest.json` and the payload. The manifest records the schema version, Cotra version, configuration schema range, and for every payload file its relative path, byte length, and SHA-256. Paths are validated as relative, normalized, free of `..`, drive, UNC, alternate-data-stream, and reserved-name components; files present in the directory but absent from the manifest are rejected.

`cotra install --source <dir>` (run from the extracted release):

1. refuse avoidable elevation; validate prerequisites;
2. verify every payload file against the manifest before copying anything;
3. create or re-protect `R` (section 4 ACL rules);
4. copy into `R\versions\<version>.staging-<nonce>`, re-hash every copied file, then rename to `R\versions\<version>`;
5. atomically write `R\current.json`, then `R\install.json`, then replace `R\bin\cotra.exe` (a running `cotra.exe` is renamed aside first);
6. optionally append `R\bin` to the user `PATH` in `HKCU\Environment` (default on, `--no-path` to skip) and record it;
7. run the install-integrity verification and print every installed and retained path.

A failure before step 5 leaves any previous install untouched; staged directories are inert because nothing references them. A failure during step 5 restores the previous pointer.

Uninstall: `cotra uninstall` first performs `cotra stop` and aborts unless termination is verified. It then removes `R\versions`, `R\bin`, `R\current.json`, `R\install.json`, `R\run`, and the recorded `PATH` entry. By default it retains, and prints, the user-owned data classes: `R\state` (configuration and the tunnel key file), `R\logs`, and the history files. `--purge-data --yes` additionally removes those classes and prints each removed path. The running `cotra.exe` is renamed into `%TEMP%` for OS cleanup and that path is printed. Uninstall never touches workspaces.

## 6. Lifecycle runtime

Supervision chain: `cotra start` -> detached `cotra.exe supervise` -> official tunnel client -> `cotra-mcp-host.exe` -> Node.js `cotra-mcp` -> `cotrad`. P12 adds no new daemon beyond the supervisor.

`cotra tunnel setup` (interactive or flag-driven): records the absolute tunnel-client path (validated as an existing file), the tunnel id (validated against the closed `tunnel_<32 lowercase alphanumeric>` format), and the runtime key, read through a no-echo console prompt or `--key-file <path>` and written to `R\state\secrets\tunnel-runtime-key`; the key never enters argv of any child, environment, log, or output. Workspaces are configured with `cotra workspace add <id> <dir>` / `remove` / `list`, which apply the same protected-state overlap rule as the policy kernel. `cotra workspace trust|untrust`, `cotra approvals`, and `cotra emergency-revoke` are human-invoked local clients of the existing `cotrad` `workspace.trust.grant|revoke` (STRONG), `approval.history.query`, and `trust.revoke_emergency` (STRONG) paths; they add no approval class and are not reachable from MCP (amended by SG-000043). The configuration is validated through the closed `TunnelConfig::validate()` path and written atomically; a failed validation leaves the previous configuration untouched.

`cotra start`: refuses when a live verified supervisor exists; builds the closed launch plan with `mcp_command` = the active version's `cotra-mcp-host.exe`; spawns the detached supervisor, which places itself in a kill-on-close Job Object before launching the tunnel client, so every descendant is bound to the supervisor's lifetime; records `R\run\supervisor.json` (pid, process creation time, image path); clears the inherit flag on its own standard handles before launching the supervisor so a caller capturing `cotra start` output is never held open by the detached supervisor; normalizes the casing of OS execution variables before the closed case-sensitive environment allowlist (amended by SG-000043); waits a bounded time for the health URL file and reports `running`, `degraded` (process alive, health not verified), or `failed` honestly.

`cotra stop`: opens the recorded pid, verifies the process image path and creation time (PID-reuse defense), signals a per-user named stop event, and waits. The supervisor terminates its job, confirms that no process other than itself remains in the job, writes that result to `R\run\stop-result.json`, and exits. `stop` reports `stopped (verified)` only when the supervisor has exited and its job-empty result was recorded. If the supervisor does not respond within the deadline, `stop` terminates it (kill-on-close then terminates the job) and reports that the supervisor exit was verified while descendant termination was enforced by the job but not independently observed.

`cotra-mcp-host.exe`: resolves the active version from its own location, reads `R\state\config.json`, sets `COTRA_DAEMON` to the version's `cotrad.exe` and `COTRA_WORKSPACES_JSON` from the configuration, filters the inherited environment through the closed `cotra-tunnel` sanitizer, and runs `node <version>\app\cotra-mcp\dist\index.js` with inherited stdio, propagating the exit code.

`cotra status` (human and `--json`): installed, active and previous version, configured, running state with process identity verification, health URL presence, and update marker. `cotra doctor`: the full matrix below; exit code non-zero when any required check fails. Each check yields `pass`, `fail`, or `unknown` with one evidence line:

- platform version and absence of avoidable elevation;
- install integrity: pointer parses, version directory exists, every payload file matches the manifest;
- version consistency: `R\bin\cotra.exe` matches the active version's `cotra.exe`;
- ACL: protected DACL, only the user and `SYSTEM`;
- configuration: parses, schema supported, workspaces resolve and pass the protected-state overlap rule, tunnel configuration passes `TunnelConfig::validate()`;
- Node.js runtime: path exists and `node --version` reports 20 or later;
- tunnel client: configured path is an existing file;
- process health: supervisor record, identity verification;
- tunnel health: health URL is `http://127.0.0.1:<port>/...` and a bounded loopback HTTP GET receives a response;
- IPC health: spawns the active `cotrad` with the configured workspaces, sends the closed read-only `system.status/get` request, checks the typed response, then terminates it and verifies exit;
- approval surface: presence method and availability as reported by `cotra-approval`; approval-history readability;
- state integrity: trust and approval-history checksum chains verify;
- update state: pending or failed update marker, previous version availability;
- retained data: paths that uninstall would keep.

`doctor` does not change configuration, approvals, or trust, and leaves no process running. Its IPC probe is an ordinary read-only `system.status/get` request that `cotrad` records in the audit log like any other request (amended by SG-000043).

Logs: the supervisor redirects tunnel-client output into `R\logs\tunnel.log` through a line redactor that replaces key-like token patterns and never reads or writes the runtime key file, with a size cap and one rotated file. Lifecycle transcripts record commands, versions, and outcomes only.

## 7. Update, rollback, and recovery

Version discovery is local and explicit: `cotra version` prints the installed and previous versions; `cotra update --source <dir> --check` prints the candidate version, the upgrade direction, and compatibility without changing anything. New releases are found on the repository's GitHub Releases page. Cotra performs no network update check, which avoids adding a network authority and a remote-trigger supply-chain surface.

`cotra update --source <dir>`:

1. verify the candidate manifest and payload exactly as install does;
2. refuse downgrades unless `--allow-downgrade`; treat the same version as a no-op unless `--reinstall`;
3. compatibility gate: the candidate's supported configuration schema range must include the current configuration schema; otherwise abort with no change (no silent destructive migration; any future migration is a separate explicit command that backs up first);
4. stop a running instance with verified termination, remembering whether it was running;
5. stage and verify the new version, write `R\state\update.json` = pending (while it is pending `cotra start` refuses to run), flip `R\current.json`, replace `R\bin\cotra.exe`, and update `R\install.json` with the new active version and the old version as previous;
6. post-update verification: the installed-state verification runs, then the new version's own CLI runs `cotra self-check`; on failure restore the previous pointer, CLI copy, and install record (as written before step 5), verify them, remove the failed version directory, record `failed` with the reason in `R\state\update.json`, restart if it was running, and report honestly; on success clear the marker, prune every version other than the active and previous ones (including staging leftovers), and restart if it was running. Every outcome is appended to `R\logs\lifecycle.log` (amended by SG-000044).

`cotra rollback` activates the retained previous version through the same verification path, writing the pointer to it and swapping the active and previous versions in `R\install.json` so a second rollback returns to the newer version. If an update was interrupted (pending marker present), `doctor` reports it and `rollback` or a repeated `update` resolves it; the pointer is always either the old or the new verified version because it is replaced atomically. Configuration, secrets, and history are never modified by update or rollback.

## 8. Release and packaging

- `scripts/package-release.mjs` assembles the payload from a release build (`cargo build --release` for the three Rust binaries, `npm run build` plus a production-only dependency install for the app) and writes the manifest with sorted entries.
- A `release` workflow on `v*` tags requires the tag to equal `v<workspace version>` (for example `v0.1.0` for workspace version `0.1.0`), builds on `windows-latest` from the tagged revision, packages, runs the release-artifact qualification, archives, writes `SHA256SUMS.txt`, and creates a draft GitHub Release; publishing the draft is a deliberate maintainer action. SBOM, provenance attestation, and reproducibility testing are P13 deliverables attached to the same pipeline (amended by SG-000044).
- A `release-qualification` CI job packages a real release on every change and qualifies it with the installed real `cotra-mcp` app: exact canonical MCP tool set, a `cotrad`-backed tool call, doctor, update while running, downgrade refusal, rollback, automatic recovery from a release whose CLI cannot verify itself, verified stop, and retaining uninstall (amended by SG-000044).
- Signing: no paid code-signing certificate is available under the zero-cost rule, so binaries are unsigned and SmartScreen may warn; release notes say so plainly. Integrity is enforced by manifest verification at install and update, and P13 adds free GitHub build-provenance attestations for the release archive.

## 9. Threat considerations

- Tampering: every payload file is hash-verified before activation and again after copy; the pointer references only verified versions.
- Rollback attack: downgrades require an explicit flag, recorded in the transcript.
- Privilege: no elevation anywhere; elevated execution is refused; no service or scheduled task.
- ACL: one protected owner-only tree; verification failure aborts.
- Path handling: all operations derive from `R`; manifest paths are validated; recursive deletes are limited to known subtrees of `R`.
- TOCTOU: staged content is verified in place before the atomic pointer flip; process identity checks bind pid and creation time.
- Secret leakage: key by file reference only; no key in argv, environment, logs, status, or doctor output; tests assert absence.
- Confused deputy and MCP drift: lifecycle commands take only human-supplied argv; no lifecycle surface is registered as an MCP tool; protected state is excluded from every workspace (section 2).

## 10. Grain sequence

1. Protected Cotra state isolation from trusted workspaces (section 2).
2. Per-user install foundation: manifest format and packaging script, `install`, `uninstall`, layout, ACLs, `PATH`, retained-data semantics, `version`.
3. Lifecycle runtime: `cotra-mcp-host`, `tunnel setup`, `workspace` configuration, `start`, `stop`, `status`, `doctor`, supervisor Job Object, loopback health probe, redacted logs.
4. Update, rollback, and recovery, the tag release workflow, and a CI lifecycle job that installs from a packaged artifact.
5. P12 exit packet: joint proof of clean install, start, status, doctor, tunnel path, bounded capability operation, stop, restart, upgrade, failed-update recovery, uninstall, and retained-data behavior.

## 11. Qualification

- Unit and integration tests per grain in the repository's existing style; Windows-native behavior (ACLs, Job Objects, process identity, `PATH`, pointer flips) is exercised on the CI `windows-latest` jobs with `LOCALAPPDATA` redirected to an isolated temporary root.
- End-to-end lifecycle is exercised from a packaged release artifact using a repository test fixture that stands in for the tunnel client (writes the health URL file, serves the loopback health endpoint, and drives `cotra-mcp-host` over stdio with MCP requests). The fixture proves Cotra's supervision, launch, and MCP-to-`cotrad` path; it does not prove the OpenAI service. Real ChatGPT connectivity through the OpenAI tunnel requires the owner's OpenAI account and tunnel credentials and is recorded as an owner-performed qualification, never simulated.
- Interactive approval prompts and SmartScreen behavior require a human at the console and are recorded honestly as not proven in CI.
