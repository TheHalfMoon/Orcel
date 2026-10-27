# Independent macOS qualification evidence — 2026-10-27

**Scope:** macOS hardware observation only, without enabling new authority, requesting a system grant, touching the user's desktop, or publishing a release. These findings supplement the previous XP-06/XP-11 hardware records and merged XP-14 slice #487.

## Hardware and exact source

- Checkout: isolated, shallow main at `e71d790644c372385e1791b5b2ee8ced7a25d477`, with no changes to any other agent worktree.
- Apple Silicon arm64, macOS 26.6.2 (25G83), 8 GiB RAM, Rust 1.96.0.
- Swift 6.4, active developer directory `/Library/Developer/CommandLineTools`; full Xcode **not installed**.
- Only about 4–5 GiB disk free during testing. Neither Chrome nor Edge was installed in `/Applications` or `~/Applications`; neither LibreOffice nor GnuCash was installed.

## BM-02: pinned taskpack integrity and included test suites

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests/benchmarks/tests -p test_taskpack.py -v
```

**PASS: 11 tests; 1 Windows-only junction test skipped.** Fetched the exact locked donor `trycua/cua@a802eaf26ca97616a6bf0de6a29729a9346fbb1f`. Verified locked tree, file set, git blobs, SHA-256, licensing, permission bits, task manifest digests, Python task suites, and JavaScript tests. Confirms the LF-based digest validation succeeds on this Mac. No donor files copied into Orcel.

A subordinate `cdb-s02` schema evaluator was **skipped** because `cb/jsonschema` was unavailable. Actual LibreOffice/GnuCash GUI tasks, Orcel agent-driven execution, reset and scoring are **not qualified** by these unit tests.

## XP-14: browser discovery and signature-refusal tests

```sh
CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_PROFILE_DEV_DEBUG=0 \
cargo test --locked -p orcel-browser-host --lib discovery -- --nocapture --test-threads=2
```

**PASS: 10 tests, 0 failures; 172 unrelated tests filtered.** The tests verify pinned macOS Apple-team requirements, version/plist parsing, unknown engine refusal, and a Chrome-metadata fake with Apple's rather than Google's signature being refused.

**Evidence limit:** neither signed real browser bundle was present. The test cases for installed vendor bundles and tampered installed Chrome **returned successfully through their non-CI no-browser paths**, not via positive verification on this Mac. The signed real-bundle evidence from #487's hosted macOS runner remains separate. This does not qualify XP-14 launch authority; SG-000115 governance remains applicable.

## XP-07/XP-12: no-prompt preflight unit contracts

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p test_macos_native_capability_preflight.py -v
```

**PASS: 6 unit tests.** The tests enforce a single read-only Orcel /2 `hello` request, reject malformed host/permission frames, and report XP-07/XP-12 as ineligible without separate direct-capture consent. These six tests are synthetic protocol tests, not delivered capture/input tests. A **separate live, read-only native-host** observation was subsequently completed below.

## Real native-host build blocker

Attempted:

```sh
CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 \
cargo build --locked --manifest-path apps/orcel-native-host/Cargo.toml --bin orcel-native-host
```

**FAILED before the binary was produced.** The transitive `apple-cf 0.9.3` and `apple-metal 0.6.0` Swift bridges failed `swift-bridge: Invalid manifest`, with an arm64 link error for `PackageDescription.Package.__allocating_init`. The active macOS Command Line Tools Swift 6.4 cannot complete this SwiftPM manifest on this host. Full Xcode is absent; `xcodebuild -version` explicitly reports that it requires Xcode.

This is a **local SwiftPM/CommandLineTools source-build blocker** (also reproduced with `swift package dump-package` on an independent upstream manifest), not an Orcel protocol failure. The binary was later obtained via a pinned macOS CI build and its **real host hello passed** below. No TCC change, screenshot, input event, privacy prompt, large Xcode/browser installation, security bypass, or cost was incurred.

## Native-host physical Mac hello completed (read-only, 2026-10-27)

The local SwiftPM blocker was bypassed **without changing the security behavior of Orcel or the Mac** by obtaining the actual `orcel-native-host` executable from a verified GitHub macOS CI build.

- Source checkout: `e71d790644c372385e1791b5b2ee8ced7a25d477` plus a **temporary, never-to-merge GitHub CI artifact-upload step only** in draft PR #490 at `160ad354513272fd71d5ec8269194e96cd0edbc5`.
- Build: [GitHub CI run 40517824930](https://github.com/TheHalfMoon/Orcel/actions/runs/40517824930), native-host macOS job; artifact ID `12739489881`, name `orcel-macos-native-preflight-160ad354513272fd71d5ec8269194e96cd0edbc5` (short retention).
- Artifact metadata's `workflow_run.head_sha` and repository ID matched the intended code. Downloaded artifact contained one `arm64` Mach-O binary (`orcel-native-host`); SHA-256: `48cea9864b76762cbbed42e470edf909a557bd0ad11d2439c5b9a056837d1a8c`.
- Actual `orcel-native-host --version`: `orcel-computer-host/2`.
- Ran `python3 scripts/macos_native_capability_preflight.py --host <extracted-orcel-native-host>`. It sent **one** read-only Orcel /2 `hello` frame, returned exit **0**, and reported:

```json
{
  "permissions": {
    "accessibility": true,
    "screen_recording": true,
    "direct_capture_consent": false,
    "macos_background_spi": false
  },
  "manual_test_preflight": {
    "XP-06": {"eligible_for_manual_test": true, "missing": []},
    "XP-11": {"eligible_for_manual_test": true, "missing": []},
    "XP-07": {
      "eligible_for_manual_test": false,
      "missing": ["direct_capture_consent", "host capability capture_window: unavailable"]
    },
    "XP-12": {
      "eligible_for_manual_test": false,
      "missing": ["direct_capture_consent", "host capability input_click: unavailable"]
    }
  }
}
```

- Explicit `--require XP-07` and `--require XP-12` both returned **exit 3**, as designed for missing preconditions.
- This is a **real macOS host-permission and capability handshake**, not proof of delivered screenshots, clicks, or keystrokes. No capture/input operation, macOS grant request, browser launch, or real-world desktop action occurred. XP-07 and XP-12 delivery **remain unqualified** until macOS separately records direct-capture consent and the controlled live tests pass. XP-06/11 prior actual delivery evidence from #425 remains independent.
- Temporary artifact-upload branch is intended to be closed **without merging** and its diagnostic executable/worktree removed after evidence capture; no new product authority or release artifact is introduced.

## Safe follow-up

1. **Completed:** a real Mac native-host `hello` observation was obtained using the macOS CI-built binary without installing full Xcode. The SwiftPM CommandLineTools source-build mismatch remains a **local reproducibility** blocker, not a blocker to this preflight. Fix the toolchain only when local source builds are needed.
2. XP-07/XP-12 delivery remains unqualified until explicit macOS direct-capture consent is granted and controlled-window tests really pass. Do not infer consent from Screen Recording alone.
3. XP-14 positive installed-bundle verification requires actual vendor-signed Chrome/Edge; the absence of browsers on this Mac must not be reported as a successful positive hardware test.
4. BM-02 application-level qualification requires the remaining optional schema evaluator plus real controlled LibreOffice/GnuCash and Orcel-driven tasks with reset/scoring.
5. Existing Oct 22 XP-06/XP-11 real-hardware evidence is unaffected. This document grants no new authority or release status.
