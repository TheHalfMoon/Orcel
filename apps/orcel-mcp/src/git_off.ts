/**
 * Founder decision of 2026-11-23: Git is off until it runs confined. orceld
 * refuses every `git.*` and `fc.git` request (`crates/orcel-provider-git/src/
 * confinement.rs`); the tools keep their names and schemas, and their
 * descriptions say so first.
 */
export const GIT_OFF =
  "Off: Git is off until it runs confined. Calls are refused (a well-formed one with PROVIDER_UNAVAILABLE); nothing is asked and nothing runs. When Git is on: ";
