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
