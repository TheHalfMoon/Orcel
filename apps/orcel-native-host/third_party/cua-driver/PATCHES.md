# Cua Driver patch queue (Orcel)

Upstream: [trycua/cua](https://github.com/trycua/cua) at
`a802eaf26ca97616a6bf0de6a29729a9346fbb1f` (MIT, `LICENSE.md` in this
directory). Provenance, tree ids and the patched-file list:
[docs/orcel/cua_driver_provenance.json](../../../../docs/orcel/cua_driver_provenance.json).

Every file under `crates/` and `Skills/` is upstream's bytes except the files listed below.
`node scripts/check-vendored-cua.mjs` proves that in CI: it rebuilds each
crate's git tree with the upstream blob put back for every listed file and
requires the upstream tree id.

Each patch is its own commit. Rebasing to a new pin means re-importing the
crates unmodified and replaying this queue.

## Import

The seven crate directories copied blob for blob from the pin (no patch):
`platform-macos`, `platform-linux`, `cua-driver-core`, `cua-driver-contract`,
`cursor-overlay`, `pip-preview`, and `cua-cursor-motion` (a path dependency of
`cursor-overlay`, matrix row T-CUA-38), plus `Skills/cua-driver/` (T-CUA-39):
the Markdown that `cua-driver-core/src/mcp_skills.rs` embeds with
`include_str!("../../../Skills/cua-driver/...")`. It sits at the same relative
place as upstream, so that path needs no patch.

Known out-of-tree reference left as is: the `#[cfg(test)]` module of
`platform-linux/src/wayland/shell_helper.rs` includes
`../../../../../wayland-helper/winrects@cua/*`, the GNOME Shell helper that
XP-12 vendors. XP-05 builds no platform-linux test target, so nothing reads it.

## P-01: workspace wiring

Orcel side: `apps/orcel-native-host/Cargo.toml` is a standalone workspace
(the root workspace does not list it, so orceld's `Cargo.lock` is unchanged).
It carries the `[workspace.package]` and `[workspace.dependencies]` entries
the vendored manifests inherit, copied from upstream's
`libs/cua-driver/rust/Cargo.toml`. `Cargo.lock` started as upstream's lockfile,
and Cargo pruned it to this graph, so every shared crate keeps the version
upstream tested.

The vendored crate layout keeps upstream's relative paths, so no source path
needed rewriting. One manifest line changes in each of two files, so the
workspace's `cua-driver-core` `default-features = false` survives feature
unification. Without it, upstream's defaults `yaml`, `rego` and `script` (the
QuickJS `run_script` engine) come back:

- `platform-macos/Cargo.toml`: `cua-driver-core = { path = "../cua-driver-core", default-features = false }`
- `platform-linux/Cargo.toml`: the same.

`cursor-overlay` already declares `default-features = false` upstream.

## P-02: no cua-driver binary or telemetry in the graph

No vendored file changes. Upstream's telemetry lives in the `cua-driver`
binary crate: `cua-telemetry`'s config reader plus a `ureq` POST to PostHog.
That crate is not vendored, and none of the seven vendored crates depends on
it, on `cua-driver-sdk` or on any HTTP client. The patch is the guard that
keeps it that way. `scripts/check-vendored-cua.mjs` fails if
`apps/orcel-native-host/Cargo.lock` names `cua-driver`, `cua-driver-sdk`,
`cua-daemon`, `cua-telemetry`, `posthog-rs`, `ureq`, `reqwest` or `hyper`.
Cargo.lock lists every package for every target and feature, so absence there
means absence from every build. The same check also fails if the root
`Cargo.lock` names any vendored crate or `orcel-native-host`.
