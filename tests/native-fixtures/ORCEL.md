# Native conformance fixtures (XP-08)

Copied from [trycua/cua](https://github.com/trycua/cua/tree/a802eaf26ca97616a6bf0de6a29729a9346fbb1f/libs/cua-driver/tests/fixtures)
at `a802eaf26ca97616a6bf0de6a29729a9346fbb1f`, path
`libs/cua-driver/tests/fixtures`, tree `995d16166d72cd059443a1e5ed373b1fb6ffc7ac`
(transplant matrix row T-CUA-07, method COPY). MIT: `LICENSE.md` here is
upstream's license file, blob for blob; the repository notice is
`docs/orcel/notices/cua-MIT.txt`.

Every file in this directory is upstream's bytes except the three Orcel-owned
files: this note, `LICENSE.md` (upstream's root license, placed here) and
`orcel-stage.sh`. `node scripts/check-vendored-cua.mjs` proves it in CI: it
rebuilds the git tree from the committed files, leaves the Orcel-owned files
out, puts the removed files back as their upstream blobs, and requires tree
`995d1616`. With `--upstream` it also reads that id from GitHub. The record is
the `fixtures` entry of `docs/orcel/cua_driver_provenance.json`.

## Removed files

The exact-diff review refuses binary files, so these two are not copied
(the same handling as P-05 in the native host's patch queue):

- `apps/cross-platform/tauri/src-tauri/icons/icon.ico` (blob `d1d851e2`, 2,066 bytes)
- `apps/cross-platform/tauri/src-tauri/icons/icon.png` (blob `4c537966`, 2,044 bytes)

Without them the Tauri host does not build. Orcel CI does not build it anyway:
it would add a full Tauri and WebKitGTK compile to every run. The shared web
catalog is driven through Electron on Linux and macOS and through WKWebView on
macOS, and the report lists Tauri as `not_run`.

## How Orcel builds and runs them

`orcel-stage.sh OUT` builds the harnesses from these sources into a directory
outside the checkout: GTK3 is PyGObject and runs as source; AppKit and
WKWebView are compiled with the same `swiftc` command and `Info.plist` as
`build/macos.sh`; Electron is installed with `npm ci --ignore-scripts` from
the pinned `package-lock.json`, and then only Electron's own installer runs.
Upstream's `build/` scripts are kept unchanged but are not used, because they
stage into Cua's repository layout.

The suites are `apps/orcel-native-host/tests/conformance_shared_web.rs` and
`apps/orcel-native-host/tests/conformance_native.rs`. They drive the real
host over `orcel-computer-host/2` and read state only through fixture-owned
oracles: the shared web page's loopback journal and the GTK3/AppKit task-state
file. Neither is the host's accessibility output.
