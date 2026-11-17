# Third-party notices: apps/orcel-computer-host/third_party/hcu

The files in `semantic/` are adapted from microsoft/Hybrid-Computer-Use at
commit `00eaeebe8ac0d275e46f875bdb5347e5f326faa1` under the MIT licence in
`LICENSE` (Copyright (c) 2026 Hybrid Computer Use authors). Orcel's changes
are listed in `PATCHES.md`.

Every adapted file comes from the donor's own MIT code
(`computer-use/internal/core/` and
`computer-use/native/windows/ComputerUse.Windows.Runtime/`). None of the
donor's separately licensed components is included:

| Donor component | Licence | In Orcel |
|---|---|---|
| macOS provider portions (open-codex-computer-use, cua-yabai) | MIT (separate notices) | not included |
| OSWorld-V2 modified files (`osworld-overlay/`, `hcu/osworld/`) | Apache-2.0 | not included |
| `StableIndexer` portions (Linux provider, Playwright-derived) | Apache-2.0 | not included |
| Go `golang.org/x/text` | BSD-3-Clause | not included |
| `santhosh-tekuri/jsonschema` v6.0.3 | Apache-2.0 | not included |
| FlaUI, System.Drawing.Common (NuGet) | MIT | not included |

The package imports only the Go standard library.
