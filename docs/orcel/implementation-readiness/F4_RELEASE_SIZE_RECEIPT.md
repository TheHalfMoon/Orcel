# F4 size inventory — preliminary extracted-release receipt

Status: **PRELIMINARY / NOT F4 QUALIFIED** (2026-10-25). This receipt records
an actual Windows CI artifact, not a simulated package or a full installed app.

## Reproduction

- Source: [main CI run 40169462488](https://github.com/TheHalfMoon/Orcel/actions/runs/40169462488), commit `e6585a4dbd43f1f2137672400ac537e41e8745a2`.
- Artifact: `orcel-release-candidate-e6585a4dbd43f1f2137672400ac537e41e8745a2`.
- File: `orcel-0.2.0-windows-x64.zip`.
- Artifact ZIP SHA-256 from its verified `SHA256SUMS.txt`:
  `d4ca083d77f78c8c344f559078b343e25f065cbf5589a58cd18c96c917784184`.
- Method: download CI artifact; verify all `SHA256SUMS.txt` records;
  extract ZIP into an empty directory; run
  `node scripts/release-size.mjs --release <extracted-dir>`.
- Report format: `orcel-release-size/1`; counts real regular-file lengths
  including `manifest.json`, refuses symlinks and unlisted or mismatched files.

## Observed result

| Measurement | Value |
|---|---:|
| Extracted payload | **22,561,253 bytes** |
| Budget (decimal MB) | 400,000,000 bytes |
| Enumerated files | 987 |
| Top-level executables | 7,691,264 bytes |
| MCP app including packaged dependencies | 14,212,402 bytes |
| Notices, manifest, helper pin, and other files | 657,587 bytes |
| Payload-only ceiling | PASS |

The original archive is about 6.2 MB compressed; compressed download size
is not the basis for the 400 MB installed-size target.

## Deliberately excluded and still open

This archive contains **no packaged native desktop UI**, and the runtime
requires a separately installed Node.js and installed Edge/Chrome. Those
prerequisites were **not measured as zero**. Windows allocation sizes,
installer-created CLI copies, version history, app logs/state, update overhead,
the full end-to-end installed app, and signing/attestation also remain open.
The 400 MB target is **not fully qualified** by this receipt.

A CI action on the preparation branch will check the extracted archive's real
file lengths against the same 400,000,000-byte limit at each qualified build;
the tested script includes regression cases for an over-budget package,
unlisted files, manifest mismatches, forbidden symlinks and bad parameters.
Full F4 requires installed-tree measurement on Windows with all intended UI,
runtime, and release components, plus the other F4 acceptance gates.
