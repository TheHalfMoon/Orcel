# Changelog

Orcel's published artifacts and release notes are the canonical release history: [GitHub Releases](https://github.com/TheHalfMoon/Orcel/releases). This file documents selected repository-visible changes; it is not a claim that every commit is a released binary.

## Unreleased

- Improve open-source onboarding, contributor documentation, project presentation, and issue/PR templates.
- Keep the existing compatibility and security boundaries explicit for new contributors.
- XP-01: approval history and audit records default to a private per-user state root on every OS (`%LOCALAPPDATA%\Orcel` on Windows, unchanged; `~/Library/Application Support/Orcel` on macOS; `$XDG_STATE_HOME/orcel` or `~/.local/state/orcel` on Linux, mode 0700) and fail closed instead of falling back to the shared temp directory.
  - On Unix the root and every ancestor are checked: an ancestor must be owned by the current user or root and not writable by group or other unless it is a root-owned sticky directory such as `/tmp`.
  - Fail-closed behavior changes: a missing `LOCALAPPDATA`, or one that is relative or contains `..`, is now an error on Windows; an empty or relative `ORCEL_APPROVAL_HISTORY_PATH` or `ORCEL_AUDIT_PATH` is refused instead of resolving against the working directory.
  - API changes: `LocalApprovalBroker::new` and `LocalApprovalBroker::with_presence_verifier` return `Result` and fail with `ApprovalUnavailable`; `impl Default for LocalApprovalBroker` is removed; `default_audit_path` and `default_approval_history_path` return `Result`.
- XP-01B: full-control authority, the executable registry, remote-session leases, trust records and the browser profile also default to the private per-user state root and fail closed instead of falling back to the shared temp directory. Windows paths are unchanged.
  - Migration: none. State an earlier build left under the shared temp directory (`/tmp/orcel` or `$TMPDIR/orcel`) is ignored, never read or trusted; full-control and remote leases must be granted again, trust re-granted and executables re-registered. Delete the old directory by hand.
  - The shared-temp `orcel` directory is no longer a protected state root, since nothing defaults there.
  - Fail-closed behavior changes: an empty or relative `ORCEL_TRUST_PATH`, `ORCEL_REMOTE_LEASE_PATH`, `ORCEL_EXECUTABLE_REGISTRY_PATH` or `ORCEL_BROWSER_STATE_DIR` is refused; a request needing a store whose root is unavailable fails with `PROVIDER_UNAVAILABLE`.
  - API changes: `default_trust_path`, `default_profile_root`, `default_lease_store_path`, `default_registry_path`, `default_authority_dir`, `default_key_path` and `default_store_path` return `Result`.

## 2026-10-16 — Orbital identity adopted (repository change)

- Replace the earlier white-disc Design #17 from [PR #339](https://github.com/TheHalfMoon/Orcel/pull/339) with the founder-approved **Orcel Orbital** identity in [PR #341](https://github.com/TheHalfMoon/Orcel/pull/341): open outer white arc, complete inner ring, detached satellite dot, and lowercase white wordmark on black.
- Synchronize deterministic vector assets across the website and OpenAI/Codex package destinations; provide the public identity gallery, raster export tooling, and downloadable media kit. The previous design remains in Git history and is no longer the active mark.
- **Not automatically a standalone product release**: use the GitHub Releases page for released binaries, checksums, and provenance.
