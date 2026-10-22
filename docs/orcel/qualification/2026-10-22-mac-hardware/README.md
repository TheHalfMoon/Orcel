## Real Mac qualification update — 2026-10-22

Device: macOS 26.6.2 (Apple Silicon), authenticated Aqua GUI. No paid account, full Xcode, signing, distribution or release.

Pinned test implementation: 34cb67567c2f2eca8f66c4336a313f6bcf6fe06c, temporary CI artifact 12415006707 from successful hosted macOS build.

### Confirmed PASS
- XP-09 approval/security regressions: 22/22 passed locally (unit/contract tests; real approval qualification on #362 is a separate record).
- Orcel native host protocol v2 starts and negotiates on this Mac.
- Rust live_capture report mode: 1/1 PASS; direct capture correctly refused. NOT delivered-capture qualification.
- Rust live_input report mode: 1/1 PASS; raw input correctly refused. NOT delivered-input qualification.
- Real native Swift AppKit synthetic fixture: standalone host probe **15/15 PASS**. Verified process-generation owner, nonempty real accessibility tree (8 mapped elements), password redaction and no secret leakage, protected secure-field action refusal, approval-window refusal, a successful semantic value write into the test window, and independent readback. Used original Orcel release-mode binary from CI.
- A direct native AX client returns AXWindows success and accessible children against this Swift fixture.

### Confirmed FAIL — fixture repair required
- Rust live_observation (XP-06): 0/1 FAIL. JXA osascript probe window is listed, but observe_window returns an empty tree. Independent native AX check against JXA yields AXErrorCannotComplete (-25204). The native Swift fixture works.
- Rust live_actions (XP-11): 0/1 FAIL due to the same JXA fixture issue. Standalone Swift test passes, but the official Rust suite is not yet qualified.

### Remaining blockers
- direct_capture_consent=false in actual host hello despite general screen_recording=true. XP-07 delivered capture and XP-12 delivered input are NOT qualified.
- XP-06/XP-11 official Rust manual suites should replace nonresponsive JXA fixture with native Swift AppKit fixture, preserving all negative assertions.
- Linux real GNOME/KDE approvals still require an actual desktop.
- macOS paid commercial packaging/signing XP-16/FD-05 excluded.
- No changes to Opus SG-000108 or main.

Do not claim complete macOS release qualification. Preserve these results and fix the fixture without weakening security assertions.

## Reproduction and test-fixture repair

The old macOS JXA/osascript fixture did not respond to native AX window requests (AXErrorCannotComplete -25204). A native Swift AppKit synthetic fixture based on existing Orcel/Cua fixture design worked on the real Mac, passing 15/15 independent host checks.

For manual XP-06 and XP-11 Rust suites:
1. In apps/orcel-native-host, build the native fixture with swiftc -O -parse-as-library tests/fixtures/appkit_probe_native.swift -o /private/tmp/orcel-xp06-fixture.
2. Set ORCEL_MACOS_AX_PROBE_BIN=/private/tmp/orcel-xp06-fixture in the test process.
3. Set ORCEL_XP06_LIVE=1 and run the native-host live_observation test; set ORCEL_XP11_LIVE=1 and run live_actions.
4. Repeat with kernel adapter tests xp06_native_host_live and xp11_native_actions_live. Run only against synthetic AppKit windows.
5. Preserve original negative assertions and label any unavailable capture/input as unavailable, not qualified.

Do not treat the standalone Python host probe as official Rust qualification. Exact-head compiled Rust suites still need real-hardware execution after fixture repair.

XP-07 delivered capture and XP-12 delivered input remain blocked on direct-capture consent. Do not force, spoof, or silently change TCC permissions.
