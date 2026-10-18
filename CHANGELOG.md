# Changelog

Orcel's published artifacts and release notes are the canonical release history: [GitHub Releases](https://github.com/TheHalfMoon/Orcel/releases). This file documents selected repository-visible changes; it is not a claim that every commit is a released binary.

## Unreleased

- Improve open-source onboarding, contributor documentation, project presentation, and issue/PR templates.
- Keep the existing compatibility and security boundaries explicit for new contributors.
- XP-01: approval history and audit records default to a private per-user state root on every OS (`%LOCALAPPDATA%\Orcel` on Windows, unchanged; `~/Library/Application Support/Orcel` on macOS; `$XDG_STATE_HOME/orcel` or `~/.local/state/orcel` on Linux, mode 0700) and fail closed instead of falling back to the shared temp directory.

## 2026-10-16 — Orbital identity adopted (repository change)

- Replace the earlier white-disc Design #17 from [PR #339](https://github.com/TheHalfMoon/Orcel/pull/339) with the founder-approved **Orcel Orbital** identity in [PR #341](https://github.com/TheHalfMoon/Orcel/pull/341): open outer white arc, complete inner ring, detached satellite dot, and lowercase white wordmark on black.
- Synchronize deterministic vector assets across the website and OpenAI/Codex package destinations; provide the public identity gallery, raster export tooling, and downloadable media kit. The previous design remains in Git history and is no longer the active mark.
- **Not automatically a standalone product release**: use the GitHub Releases page for released binaries, checksums, and provenance.
