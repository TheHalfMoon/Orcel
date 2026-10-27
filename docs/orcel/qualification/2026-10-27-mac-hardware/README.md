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

**PASS: 6 unit tests.** The tests enforce a single read-only Orcel /2 `hello` request, reject malformed host/permission frames, and report XP-07/XP-12 as ineligible without separate direct-capture consent. These are synthetic protocol tests, **not** a fresh real-Mac TCC observation or delivered capture/input tests.

## Real native-host build blocker

Attempted:

```sh
CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 \
cargo build --locked --manifest-path apps/orcel-native-host/Cargo.toml --bin orcel-native-host
```

**FAILED before the binary was produced.** The transitive `apple-cf 0.9.3` and `apple-metal 0.6.0` Swift bridges failed `swift-bridge: Invalid manifest`, with an arm64 link error for `PackageDescription.Package.__allocating_init`. The active macOS Command Line Tools Swift 6.4 cannot complete this SwiftPM manifest on this host. Full Xcode is absent; `xcodebuild -version` explicitly reports that it requires Xcode.

This is a **local toolchain blocker**, not evidence that the Orcel host itself fails its protocol. No TCC change, screenshot, input event, privacy prompt, large Xcode/browser installation, security bypass, or cost was incurred.

## Safe follow-up

1. On a compatible, authorized Mac with a working full Xcode/SwiftPM toolchain, build the native host. Run `python3 scripts/macos_native_capability_preflight.py --host /absolute/path/to/orcel-native-host` and save the actual read-only `hello` report.
2. XP-07/XP-12 delivery remains unqualified until explicit macOS direct-capture consent is granted and controlled-window tests really pass. Do not infer consent from Screen Recording alone.
3. XP-14 positive installed-bundle verification requires actual vendor-signed Chrome/Edge; the absence of browsers on this Mac must not be reported as a successful positive hardware test.
4. BM-02 application-level qualification requires the remaining optional schema evaluator plus real controlled LibreOffice/GnuCash and Orcel-driven tasks with reset/scoring.
5. Existing Oct 22 XP-06/XP-11 real-hardware evidence is unaffected. This document grants no new authority or release status.
