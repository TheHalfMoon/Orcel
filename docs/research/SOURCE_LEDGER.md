# Orcel Source Ledger

Snapshot date: 2026-09-23
Purpose: research, provenance, dependency evaluation, and bounded source reuse.

This ledger records the source state used for Orcel planning. A pin is not automatic authorization to copy code. Reuse still requires a file-level provenance and license decision.

## Official product and platform references

### OpenAI Secure MCP Tunnel

Reference:
https://developers.openai.com/api/docs/guides/secure-mcp-tunnels

Planning facts:
- the private MCP server can remain private;
- tunnel-client initiates outbound HTTPS;
- no inbound public firewall port is required;
- local targets may be stdio or HTTP;
- ChatGPT and other supported OpenAI surfaces can use the hosted tunnel endpoint;
- tunnel transport and Orcel authorization are separate concerns.

Orcel use:
- default connectivity for ChatGPT;
- do not reimplement the tunnel in v1;
- supervise the official client and keep its runtime key out of tool payloads and child environments.

### OpenAI MCP servers guide

Reference:
https://developers.openai.com/api/docs/guides/tools-connectors-mcp

Orcel use:
- MCP compatibility;
- explicit approval semantics at the product boundary;
- local/private server connectivity through tunnel_id.

## Windows platform references

### Microsoft UI Automation

References:
https://learn.microsoft.com/en-us/windows/win32/winauto/entry-uiauto-win32
https://learn.microsoft.com/en-us/windows/win32/winauto/uiauto-controlpatternsoverview

Orcel use:
- structured desktop inspection/action before coordinate input;
- selectors based on process/window/AutomationId/control type/name/patterns;
- invoke/select/value/toggle/scroll patterns.

### Final path resolution

Reference:
https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfinalpathnamebyhandlew

Orcel use:
- handle-based final path resolution for workspace enforcement;
- mitigation for symbolic-link/junction escape and path aliasing.

### Windows DPAPI

Reference:
https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata

Orcel use:
- one option for per-user secret protection;
- not sufficient by itself for all service/multi-identity designs.

### PowerShell language modes

Reference:
https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_language_modes

Orcel use:
- ConstrainedLanguage can reduce attack surface under supported application-control policy;
- Orcel does not treat language mode alone as an independent sandbox.

## GitHub source pins

### openai/tunnel-client

Pin:
cce7a8226654c432ce53c7e05e17a9825a34b6e3

Default branch:
master

Upstream license:
Apache-2.0

Role:
- official transport implementation;
- runtime/health/doctor behavior reference;
- preferred dependency rather than fork.

### wonderwhy-er/DesktopCommanderMCP

Pin:
2434718a0a8993d882cb05dc648c669f09bb4399

Default branch:
main

Upstream license:
MIT

Role:
- behavioral baseline for filesystem/process/tool UX;
- reconnect/recovery patterns;
- benchmark against unrestricted-shell failure modes.

Rule:
Do not inherit advisory path/blocklist controls as the Orcel security boundary.

### gunwoo55/unlimited-agent

Pin:
44c350c7c94963006c6f9d48d8e730e8626f9f7b

Default branch:
main

Upstream license:
MIT

Role:
- Windows-first installer/runtime research;
- local agent lifecycle and packaging patterns.

### yuga-hashimoto/localant

Pin:
217b53bc80ea6c98847f0fed162408b03ebb3a9b

Default branch:
main

Upstream license:
MIT

Role:
- local ChatGPT application/MCP connectivity research;
- operator UX and local integration ideas.

### opensymph/open-computer-use

Pin:
5b433b98019c18201a15d11e8c3cb0010879a3d8

Default branch:
main

Upstream license:
MIT

Role:
- semantic desktop control research;
- structured-before-visual provider philosophy;
- desktop command architecture reference.

### microsoft/playwright-mcp

Pin:
f1257a5a67aff872f947fae274759f7d54853862

Default branch:
main

Upstream license:
Apache-2.0

Role:
- structured browser MCP research;
- accessibility/DOM-first browser control;
- WebMCP handling;
- optional future provider/dependency.

Security note:
Web/page-provided tool metadata and schemas are untrusted input.

### trycua/cua

Pin:
37212d264504230d7d771ff8f615fab6a3492910

Default branch:
main

Upstream license:
MIT

Role:
- sandbox/runtime isolation research;
- secret delivery and guest/host boundary patterns;
- not required for Orcel MVP.

### browser-use/browser-use

Pin:
d8110c5ff87ccba887aaa726cdb780f2f84bef8d

Default branch:
main

Upstream license:
MIT

Role:
- browser-agent ergonomics and provider research;
- not an authority boundary.

### browserbase/stagehand

Pin:
2c098f44857665045dbed31168ac36af920774d9

Default branch:
main

Upstream license:
MIT

Role:
- browser action abstraction research;
- optional future provider comparison.

### opensandbox-group/OpenSandbox

Pin:
2dd6e027bc3ee5b4f906c162d611ce9aa684aab7

Default branch:
main

Upstream license:
Apache-2.0

Role:
- isolation and egress-policy research;
- optional future remote/sandbox provider;
- not required for local Windows MVP.

### cpjet64/rappct

Pin:
c02f9dd960645522009da3827a79bdc99f50c9c1

Default branch:
main

Upstream license:
MIT

Role:
- AppContainer process-launch research;
- custom CreateProcessW environment diagnostics;
- comparison source for RAII/lifetime and Job Object composition.

Reuse classification for SG-000008:
CONCEPT ONLY.

Orcel independently implements its bounded qualification probe. No rappct implementation source is copied. The source was consulted after the first native Windows launch returned Win32 error 203; its diagnostics informed the investigation. Orcel's repaired implementation is based on Microsoft AppContainer documentation requiring LOCALAPPDATA/TEMP/TMP profile redirection and uses an independently written fixed safe-name environment allowlist.

### alibaba/open-code-review

Pin:
v1.12.9

Release commit/source:
https://github.com/alibaba/open-code-review/releases/tag/v1.12.9

Upstream license:
Apache-2.0

Role:
- deterministic review file selection and rule resolution;
- Delegation Mode qualification without an OCR-managed LLM credential.

Integration:
EXTERNAL REVIEW TOOL. NO SOURCE COPIED.

Orcel downloads the official Alibaba OpenCodeReview v1.12.9 Linux release binary, verifies its pinned SHA-256 before use, and runs `ocr delegate preview` and `ocr delegate rule` against the exact PR base/head range. OCR Delegation Mode does not itself constitute semantic judgment; the host reviewer must review every OCR-selected file and manually review excluded files. The candidate checkout is treated only as data and its package scripts are never executed.

### devagrawal09/jev-review

Status:
RETIRED 2026-11-23 (`docs/governance/2026-11-23-jev-retirement.md`). The entry below records the integration as it was until then; the workflow job and its adapter are removed.

Pin:
31f89602797fb7bea007f8a480bf368bf564954e

Upstream license:
MIT

Role:
- TypeSafe Jev staged semantic/security code review;
- exact-diff review evidence.

Integration:
EXTERNAL REVIEW TOOL. NO SOURCE COPIED.

Orcel uses a base-controlled `pull_request_target` workflow, checks out the exact base SHA, fetches the PR head only as Git data, and runs the base SHA's exact-diff adapter against `base..head`. The adapter sends every changed-file hunk, including deletions, to genuine TypeSafe Jev structured judgments, records per-hunk coverage and severity-rated findings, and fails closed on incomplete coverage or a blocking finding. PR-controlled code is never executed in the secret-bearing job. The Jev checkout and SDK remain under `RUNNER_TEMP`, outside the Orcel repository working tree. A TypeSafe API key is required. Missing credentials fail the Jev gate explicitly rather than being treated as a pass.

## Source-use decision matrix

openai/tunnel-client:
USE AS EXTERNAL OFFICIAL COMPONENT FIRST.

DesktopCommanderMCP:
STUDY BEHAVIOR; SELECTIVE COMPATIBLE REUSE ONLY AFTER FILE-LEVEL REVIEW.

unlimited-agent:
STUDY WINDOWS LIFECYCLE; SELECTIVE REUSE POSSIBLE.

localant:
STUDY LOCAL CONNECTIVITY/UX; SELECTIVE REUSE POSSIBLE.

open-computer-use:
STUDY DESKTOP PROVIDER DESIGN; SELECTIVE REUSE POSSIBLE.

playwright-mcp:
PREFER DEPENDENCY/PROVIDER INTEGRATION OVER SOURCE FORK.

cua:
RESEARCH ONLY FOR MVP.

browser-use:
RESEARCH/OPTIONAL PROVIDER.

stagehand:
RESEARCH/OPTIONAL PROVIDER.

OpenSandbox:
RESEARCH/OPTIONAL FUTURE PROVIDER.

## Provenance requirement

Any future donor-derived change must record:
- source repository;
- exact source commit;
- source path;
- Orcel destination path;
- upstream license;
- copied vs adapted vs concept-only;
- modifications;
- retained attribution/notice;
- reviewer confirmation.

No donor import is authorized merely by appearing in this ledger.
