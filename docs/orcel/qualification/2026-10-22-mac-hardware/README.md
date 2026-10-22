# Orcel real macOS hardware verification — 2026-10-22

**Result:** XP-06 real observation and XP-11 semantic actions passed at the native-host and kernel-adapter layers on a real Apple Silicon Mac. XP-07 capture and XP-12 input passed only their fail-closed/report-mode checks, not delivery qualification. No release was made.

Source at time of executable/test build: `0ce4a2d7604e885c16372883fd2b1087529a47af`. A subsequent test-only Swift fixture adjustment adds the accessible name "Plain field" required by the XP-11 registry assertion; the Orcel host binary and authorization implementation did not change.

- Platform: macOS 26.6.2 arm64, logged-in Aqua session; no paid runner, full local Xcode installation, signing certificate, release or distribution.
- Exact-head hosted CI for the source/test build: https://github.com/TheHalfMoon/Orcel/actions/runs/39756322705 (PASS); 1-day test-only artifact 12415604423 supplied the actual native-host/test binaries.
- XP-09 local security/approval unit regressions: **22/22 PASS**. Earlier physical SOFT/STRONG approval checks are separately recorded in #362.
- Rust native-host tests: **4/4 PASS** with actual fixture windows: XP-06 live observation and XP-11 live actions delivered, plus XP-07 capture and XP-12 raw input *report-mode refusals* (neither delivery-qualified).
- Rust kernel-adapter tests on the same real Mac: **XP-06 1/1 PASS** (4 listed windows, 1 protected window omitted, 8 nodes); **XP-11 1/1 PASS** (8 nodes, no unauthorized action, exactly armed action, approval consumed, exact value binding, password refusal). The latter needed an explicit accessibility label in the native test fixture.
- Independent native Swift AppKit / Orcel protocol synthetic-window probe: **15/15 PASS**, including actual field write and readback, protected window refusal, secure-field redaction and absence of secret in frames.
- XP-06 native-host run: 29 response frames secret-free; p95 list_windows about 588 ms; p95 observe_window about 201 ms on this Mac (hardware-specific measurements, not a general product SLA).

## Historical failures and repairs

1. An older JXA/osascript synthetic fixture produced an empty tree on macOS, independently reproduced as AXErrorCannotComplete (-25204). This was a fixture failure; its replacement, a compiled AppKit native fixture, passed the actual XP-06 and XP-11 suites. The old failures are retained in `rust-suite-results.json` for audit chronology; the final successful reruns are in `final-hardware-verification.json`.
2. XP-11 live actions initially asserted only cancelled/provider_unavailable for a pixel request whose host had already advertised permission_missing. The repaired assertion requires the exact advertised reason, no delivered action, and still requires cancelled/provider_unavailable if raw input support is available.

## Remaining qualification boundaries

- Orcel host reports `screen_recording=true` but `direct_capture_consent=false`. macOS uses a separate system-recorded direct-capture consent, which this test did **not** override, prompt for, spoof, or bypass. XP-07 real capture delivery and XP-12 real input delivery (SPI off/on) remain **unqualified**; safe failure only is confirmed.
- XP-10 approvals must still be checked on real GNOME and KDE desktops.
- XP-16 signing/package distribution requires an explicit founder decision and paid Apple Developer credentials; not undertaken.
- This verifies the native-host and registry tests, not full user-facing orceld Full User lease integration, or an overall macOS release.
- No interaction was directed toward private user apps, no secret was published, and Opus's SG-000108 browser lane was untouched.

## Reproduce on macOS

Compile `apps/orcel-native-host/tests/fixtures/appkit_probe_native.swift` with `swiftc -O -parse-as-library` to a temporary executable, then set `ORCEL_MACOS_AX_PROBE_BIN` to that executable when running `ORCEL_XP06_LIVE=1` and `ORCEL_XP11_LIVE=1` for `live_observation`, `live_actions`, `xp06_native_host_live`, and `xp11_native_actions_live`. For a downloaded CI host, `ORCEL_NATIVE_TEST_HOST` may name the original release host and `ORCEL_COMPUTER_HOST_BIN` may name it for the kernel tests. Only controlled AppKit fixture windows may be used.

The regular locked native-host build on this Mac initially failed due to a local Swift PackageManager/Command Line Tools manifest linker error. Hosted macOS CI produced the same source's working native binary without disabling or stubbing runtime facilities. Native-source builds on this Mac remain a separate toolchain requirement.

## Repeatable non-prompting capability preflight

From the repository root, run:

```sh
python3 scripts/macos_native_capability_preflight.py --host /absolute/path/to/orcel-native-host
python3 scripts/macos_native_capability_preflight.py --host /absolute/path/to/orcel-native-host --require XP-07
```

The preflight sends exactly one read-only Orcel protocol `hello` request; it does not open Settings, read pixels, move the pointer, submit keyboard input, or trigger approval prompts. It reports which real-hardware test suites are *eligible to run*, not which capabilities have passed qualification. An unavailable or malformed host returns exit 2. If the named `--require` precondition is missing, it returns exit 3. Tests: `python3 -m unittest discover -s tests -p test_macos_native_capability_preflight.py -v`.

On the October 22 Mac, Accessibility and Screen Recording were true, while `direct_capture_consent=false`, so XP-07/XP-12 delivery preflight correctly refused. Granting direct-capture consent requires legitimate user interaction with macOS; do not fake the grant, change system privacy databases, or claim delivery qualification based on the readiness report.
