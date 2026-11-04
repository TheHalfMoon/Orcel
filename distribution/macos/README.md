# Orcel on macOS: unsigned development tarball

**This is a development build, not a release.** It is unsigned and not notarized. Signing, notarization and an app bundle are XP-16, which waits on FD-05 (a paid Apple Developer ID). It is not a published product: the CI artifact of this public repository can be downloaded, but it is never released or offered as one.

No paid Apple membership is needed to build or run it for local engineering.

## What's in it

| File | Purpose |
|---|---|
| `bin/orceld` | The kernel |
| `bin/orcel-contain`, `bin/orcel-contain.sha256` | The contained-tier helper and its pin, beside `orceld`, where orceld looks |
| `doc/` | Licence, third-party notices and this file |

Not in it: a desktop app (waits on FD-03), the `orcel` lifecycle CLI's install flow (it installs on Windows), the MCP edge, and the native host. The live browser is refused on macOS until SG-000115 is activated.

## Run it

```bash
shasum -a 256 -c SHA256SUMS-macos.txt
```

```bash
mkdir -p ~/orcel-dev && tar -xzf orcel-*-macos-*-unsigned-dev.tar.gz --strip-components=1 -C ~/orcel-dev
```

macOS quarantines downloaded files, and Gatekeeper refuses unsigned ones. Clear the attribute on that folder only, and only for an artifact from this repository's own CI. The checksum comes from the same download, so it shows integrity, not origin:

```bash
xattr -dr com.apple.quarantine ~/orcel-dev
```

orceld reads one JSON request per line on stdin. To check it runs:

```bash
mkdir -p ~/orcel-dev-ws && ORCEL_WORKSPACES_JSON="[{\"id\":\"dev\",\"root\":\"$HOME/orcel-dev-ws\"}]" python3 scripts/linux-orceld-probe.py exec ~/orcel-dev/bin/orceld dev
```

The probe is in the repository's `scripts/`; it checks `system.status`.

## Limits

- **Permission grants don't survive a rebuild.** macOS ties Accessibility and Screen Recording to a binary's signature, and an ad-hoc signature changes with each build, so a grant is lost on every rebuild.
- **Unqualified on macOS:** delivered capture and input (XP-07, XP-12) need interactive consent on a real Mac. Approvals were qualified on real hardware (XP-09), but the macOS product as a whole was not.
- CI checks that this tarball unpacks, holds the expected files, carries a matching helper pin, and that `orceld` answers `system.status`. No more than that.
