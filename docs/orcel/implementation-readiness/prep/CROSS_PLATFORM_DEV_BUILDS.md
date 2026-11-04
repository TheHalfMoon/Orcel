# Three-platform development builds: the zero-cost path

**Status: PLAN.** Nothing here claims a release. Unsigned builds are development builds on every OS. macOS and Linux desktop capability remain unqualified, and the live browser stays Windows-only until SG-000115 is activated.

## Where each platform stands

| | Windows | Linux | macOS |
|---|---|---|---|
| orceld, CLI, MCP edge | Built, tested | Built, tested | Built, tested |
| Installable package from CI | Yes: release candidate zip | Yes: deb, rpm, tarball (XP-17) | **No** |
| Desktop app | WPF (read-only timeline) | **None** | **None** |
| Native host | Go host | Rust, vendored Cua (XP-05 to XP-12) | Rust, vendored Cua |
| Live browser | Development builds | Refused (SG-000115) | Refused (SG-000115) |
| Approvals | System dialog | polkit (XP-10); GNOME and KDE sessions not yet run | XP-09, on real hardware for approvals only |

**So two gaps stand between today and three-platform development builds:** a macOS package, and a desktop app outside Windows.

## Step 1: a macOS development package (no decision needed)

The backlog gates **signed** macOS packaging (XP-16) on FD-05. An unsigned development tarball is explicitly allowed: "macOS ships unsigned dev builds only". It adds a CI job that builds a tarball on the macOS runner, as the Linux tarball does, labelled unsigned, and installs it to confirm it runs. **No paid Apple membership is needed for local engineering.** Limits to state plainly: Gatekeeper warns, and macOS ties Accessibility and Screen Recording grants to the signature, so a rebuilt unsigned binary may need re-granting. A release still needs FD-05.

## Step 2: one desktop app (needs FD-03)

| Option | Cost | Reach | Notes |
|---|---|---|---|
| **Tauri 2, keeping WPF until the CR-04 parity gate (recommended)** | None (MIT/Apache) | All three | Uses each OS's own webview, so no bundled browser. Rust, like the kernel. The existing `apps/orcel-control-room` client is toolkit-neutral and reusable. WebKitGTK accessibility is the known weak spot and must be tested |
| Electron | None | All three | **Conflicts** with the "no bundled browser" rule, and adds roughly 100+ MB (estimate) |
| WPF plus a native app per OS | None in money; three codebases | All three | Slowest |
| WPF only | None | Windows | Leaves macOS and Linux without a window |

Windows is not disturbed: WPF stays until Tauri passes a parity gate (CR-04).

**Implementation-ready once FD-03 is yes** (backlog CR-03, grain SG-000119):
1. `src-tauri` with a strict CSP (`default-src 'self'`), no remote content, no shell or filesystem plugins, no updater.
2. One Tauri command proxying only the read-only app API methods, by name.
3. A view for status, capabilities and the task timeline. The client currently refuses `task.list` and `task.get`, so it needs those authorized first; they are read-only and served today.
4. CI builds per OS as unsigned development artifacts, with an accessibility check on each.

Authority delta: none. The UI never answers approvals.

## Step 3: what stays gated

| Item | Gate |
|---|---|
| macOS signing and notarization | FD-05 (paid) |
| macOS capture and input delivery | Interactive consent on the founder's Mac |
| GNOME and KDE approval sessions | Interactive, on real desktops (XP-10) |
| Browser on macOS and Linux | SG-000115 activation, with its residuals not accepted |
| Pinned Node runtime per OS | XP-18, after packaging |

## Fastest order

1. macOS development tarball, now.
2. FD-03 decision.
3. Tauri read-only shell on all three OSes.
4. Stop in the shell, if F4 slice 5's decision allows it.
