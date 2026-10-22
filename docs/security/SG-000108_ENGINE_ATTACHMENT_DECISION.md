# SG-000108 engine attachment and resolved-address enforcement decision

Status: PROPOSED; security review passed on PR #291. This record resolves
the first two `open_questions` of `.specgrain/specs/SG-000108.json`. The
record itself granted no authority and admitted no dependency. The frozen
SG-000074 command line in `crates/orcel-browser-host/src/argv.rs` stays
unchanged. Implementation progress is tracked at the end of this record.

## Evidence

The evidence comes from throwaway spikes outside the repository. They ran on
Windows 11 (10.0.26300) against the installed Microsoft Edge 155.0.4283.45
with `playwright-core` 1.63.0. The package was installed with
`--ignore-scripts`, and its lockfile integrity equals the admitted
`sha512-rYCsBF/M…nyxo5mCg==`. No browser binary was downloaded, and no Edge
or Chrome policy key was present (`HKLM`/`HKCU\Software\Policies\Microsoft\Edge`,
`HKLM\Software\Policies\Google\Chrome`). The implementation PR turns each
probe into a native Windows test.

The probes behind the second, third and fifth rows ran with the policy route
removed, so they test layers 1 and 2 alone. They used the full proposed flag
set from the next section.

| Probe | Result |
|---|---|
| `launchPersistentContext` with `ignoreDefaultArgs: true`, the seven frozen flags, `--user-data-dir`, `--remote-debugging-pipe`, `about:blank` | Launches and is driven, and an ARIA snapshot of a fixture page is returned. The OS-reported engine command line is exactly those arguments: no `--enable-automation`, no debugging port or address, no Playwright default flag. |
| Resolver rules mapping only admitted names, then `MAP * ~NOTFOUND` | A real public name (`example.com`) and unmapped names fail. The fixture saw only admitted requests. |
| Proxy `http://0.0.0.0:9` with an exact bypass list plus `<-loopback>`, and hostile TCP listeners on `0.0.0.0:9`, `127.0.0.1:9` and `[::]:9` | IPv4 literal, IPv6 literal (`[::1]`), IPv6 metadata (`[fd00:ec2::254]`) and unmapped names fail with `ERR_PROXY_CONNECTION_FAILED` in 55–75 ms. **Zero** connections reach any listener. The admitted name still connects directly. |
| `MAP <name> <ip>:<port>` | A request for the admitted name on another port is delivered to the pinned port. Without the port, any port is reachable. Pins therefore carry `:443`. |
| WebRTC STUN to IP literals (loopback and LAN), and TURN over TCP | Without a policy flag, UDP reaches an arbitrary address (4 packets), bypassing layers 1 and 2. On Edge 155, `--force-webrtc-ip-handling-policy=…` had no effect. `--webrtc-ip-handling-policy=disable_non_proxied_udp` yields zero candidates, zero packets and zero TURN-TCP connections. |
| WebTransport | Not reachable from the HTTP fixture: it requires a secure context. **Untested.** It is a required HTTPS-fixture test (see below). |

## Decision 1: engine launch and attachment (option a)

**Launcher.** The private worker launches the verified engine through
`playwright-core` `launchPersistentContext` over `--remote-debugging-pipe`.

**What the host still owns:**
- engine discovery and signature verification;
- profile adoption and the fingerprint check;
- the scrubbed environment;
- the complete argv.

**What the worker receives.** The worker gets the engine path, the profile
directory, the argv and the environment from the host, and passes them
unchanged with `ignoreDefaultArgs: true`. The worker has no code path that
adds a flag.

**Drift detection, not containment.** After launch, the host compares the
engine's OS-reported command line with the argv it built. It also enumerates
every process in its Job Object and refuses any second browser-process engine
(an engine process without `--type=`). This catches drift, for example a
Playwright upgrade that adds default flags, a wrong engine, or a stray
process. It does **not** defend against a compromised worker:
- the worker holds a full-access handle to the engine, so it could rewrite
  the command line the OS reports after the engine has parsed it;
- a compromised worker is a full-user process and needs no browser to reach
  the network.

Worker compromise is a residual risk (below).

**Supervision.** The worker runs in the host's kill-on-close Job Object
without breakaway, so the engine and its child processes inherit the job.

**Option (b) rejected.** Option (b) would have the host launch the engine and
hand the pipe to the worker. It was rejected because Playwright has no public
API for an inherited pipe: it would need a private adapter that breaks on
upgrades, and the drift check above gives the same assurance.

### SG-000074 argv amendment

This is the explicit authority delta of the implementation. It is made
without widening the SG-000074 path: `ALLOWED_FLAGS` and `assert_argv_clean`
stay frozen and keep refusing every flag below. A separate, exact worker-launch
builder (`build_worker_argv`) emits the frozen flags plus exactly these six,
and `assert_worker_argv_exact` accepts only that argv. `FORBIDDEN_FLAGS` is
unchanged:
`--remote-debugging-port`, `--remote-debugging-address`, `--enable-automation`
and `--disable-component-update` stay forbidden.

| Flag | Value |
|---|---|
| `--remote-debugging-pipe` | none |
| `--host-resolver-rules` | host-built for this launch: `MAP <name> <pin>:443, …, MAP * ~NOTFOUND` |
| `--proxy-server` | fixed: `http://0.0.0.0:9` |
| `--proxy-bypass-list` | host-built for this launch: `<name>;…;<-loopback>` |
| `--webrtc-ip-handling-policy` | fixed: `disable_non_proxied_udp` |
| `--disable-quic` | none |

A host-valued flag is accepted only when its value equals the string the host
built for that launch. A fixed-value flag is accepted only with its fixed
value. A flag present by name only, or with any other value, is refused.

## Decision 2: actual-traffic enforcement of SG-000075

Three layers, each fail-closed on its own, plus the required flags and
launch preconditions below.

1. **Host-pinned resolution, port-pinned.** The engine never resolves names.
   - For each admitted destination, the host resolves the name and chooses
     the pin with the existing `select_public_address`. Public addresses
     only: loopback, private, link-local, metadata and mapped forms are
     denied by `is_public_address`.
   - The host emits `MAP <name> <pin>:443` for each name, then
     `MAP * ~NOTFOUND`. This enforces SG-000075's port-443 rule at the
     resolver.
   - DNS rebinding is impossible within an engine lifetime because the map is
     fixed at launch.
   - A redirect, frame or subresource to a name outside the map fails.
   - Widening the set means a host-mediated relaunch after a fresh
     `check_rebinding_consistent` check, never an in-place change.
2. **No route for IP literals or unmapped names.** The host sets
   `--proxy-server=http://0.0.0.0:9` and
   `--proxy-bypass-list=<admitted names>;<-loopback>`.
   - Only admitted names connect directly. Their address and port come from
     the layer 1 pin (`:443`), not from the bypass list.
   - Everything else, IPv4 and IPv6 literals included, goes to `0.0.0.0:9`,
     which accepted no connection even with listeners bound to `0.0.0.0:9`,
     `127.0.0.1:9` and `[::]:9`.
   - `<-loopback>` removes the engine's implicit loopback bypass.
   - Measured later (A8, Edge 155): layer 1's catch-all `MAP * ~NOTFOUND` refuses IP literals as well. With the proxy removed, a navigation to a LAN IP literal still failed and reached no listener. Each layer is sufficient on its own, and only removing both let it through (`SG-000108_TESTERARMY_E2E.md`).
   - On Linux, connecting to `0.0.0.0` reaches the local host, so this
     choice is valid only for the Windows release.
3. **Policy gate.** The worker's context-level route consults the host's
   SG-000075 decision for every request it sees: navigation, redirect,
   frame, popup, subresource and download. Layer 3 carries policy (scheme,
   origin, exact host, download rules); layers 1 and 2 carry addresses.
   - `serviceWorkers: "block"` is set.
   - WebSocket is denied through the context WebSocket route until a later
     grain admits mediated WebSocket.
   - Layer 3 does not see every request: preconnect, keepalive after unload,
     and internal fetches are not routed. Layers 1 and 2 therefore must hold
     without it, and the tests prove that.

**Required flags.**
- `--webrtc-ip-handling-policy=disable_non_proxied_udp`: WebRTC UDP otherwise
  bypasses layers 1 and 2.
- `--disable-quic`: SG-000075 denies QUIC.

Permission-gated page APIs stay denied by `permission_allowed`.

**Launch precondition: no mandatory policy.** Managed browser policy
outranks command-line settings. A machine proxy policy would turn layer 2
into a working proxy, which resolves names itself and so skips layer 1 too.

Before every launch, the host reads the mandatory policy keys for the
verified engine's family:
- `HKLM` and `HKCU\Software\Policies\Microsoft\Edge` for Edge;
- `HKLM` and `HKCU\Software\Policies\Google\Chrome` and
  `\Software\Policies\Chromium` for the Chromium family (Google Chrome reads
  the first, Chromium builds the second).

It refuses to launch, with a typed error, when **any** mandatory policy
value or subkey is present. This is simpler, and fails closed better, than
keeping lists of proxy, DNS, WebRTC and QUIC policy names.
`Recommended` subkeys do not override command-line settings, but the first
slice refuses them as well.

Cloud-managed policy that is cached locally outside these keys is a
hypothesis to test. Release qualification therefore also runs the layer 1
and 2 probes against the installed engine, which catches any override in
effect whatever its source.

### Hostname and value hygiene

- **Hostnames.** The host builds the rule and bypass strings from validated
  ASCII LDH hostnames only:
  - lowercase;
  - labels of 1 to 63 characters, 253 characters in total;
  - at least two labels;
  - a last label that is not all-numeric and does not start with `0x`, so
    that a name can never be parsed as an IPv4 address.
  - This also rules out wildcards and the separators `,` `;` and whitespace.
- **Addresses.** Values come from typed `IpAddr`, formatted by Rust. IPv6
  pins are bracketed.
- **Construction.** No page, caller or worker string reaches any flag.

### Test-only fixture pinning

Fixtures listen on loopback, which `is_public_address` correctly rejects.
Tests therefore need a test-only pin source. It must be compiled only into
test builds (a `cfg(test)` path or a non-default feature that the release
build never enables). A release-qualification check must prove that it is
absent from the shipped binaries. No runtime configuration may enable it.

## Residual risks (for review)

- **WebTransport to admitted names (#300, accepted by the founder on
  2026-10-11).** A page can open a WebTransport session, over QUIC on UDP,
  to an admitted name. The traffic reaches only that name's host-pinned
  address, because the resolver refuses unadmitted names and the no-route
  proxy refuses IP literals. Its contents are not inspected by the SG-000075
  policy route, which denies the equivalent WebSocket traffic. No Chromium
  switch disables the API, and patching it out of pages and workers in
  JavaScript has known bypass classes. Revisit if an engine-level measure
  appears. The native probe enforces the boundary.
- **Admitted host is hostile.** An admitted name pinned to its public address
  still serves whatever that host returns. Content is never policy (SG-000076
  redaction and SG-000077 approvals still apply).
- **Worker compromise.** A compromised worker equals user-level code with
  network access. The drift check does not contain it. Mitigations are the
  pinned, integrity-checked dependency, the scrubbed environment, no CLI and
  no install scripts. The implementation PR must evaluate running the worker
  under a restricted token or AppContainer without network capability, and
  record the outcome.
- **Same-user processes.** The debugging pipe is not reachable by other users
  or the network. But a same-user, medium-integrity process can duplicate the
  pipe handles out of the worker or engine and take full CDP control. This
  matches the existing threat model, where same-user code is not a security
  boundary. Tests must show the pipe handles are not inherited by the
  engine's child processes.
- **Browser-internal update and reputation traffic.** The no-route proxy also
  blocks:
  - component updates, including CRLSet revocation data (so SG-000074's
    choice not to pass `--disable-component-update` has no effect while
    this decision stands);
  - Safe Browsing / SmartScreen lookups.

  This is an explicit decision for the first slice. Admitted traffic stays
  TLS-verified, and downloads are staged and host-checked (size, type,
  digest) rather than trusted to SmartScreen. Revocation freshness relies on
  the OS certificate stack. Admitting specific update endpoints is a later
  grain decision.
- **Engine drift.** A future Edge may change how it honours these flags
  (the WebRTC switch name already differs from the `--force-` spelling). The
  A10 supported version window must re-run every probe per supported engine
  version and refuse versions where any probe fails.
- **Relaunch cost.** Relaunching to widen the destination set costs latency
  in exchange for no in-place mutation. This is accepted for the first
  journey (A6), whose destinations are known up front.

## Tests the implementation PR must add (native Windows, fixture origin only)

- **Argv.** The exact argv, and the OS command line equal to it, before and
  after the navigation. Refusal of every new flag without its host-built or
  fixed value. Refusal of every forbidden flag, as today. Refusal of a second
  browser-process engine in the job.
- **Layers 1 and 2, with the policy route disabled by a test-only hook.**
  Every case below is denied:
  - an unmapped name and a real public name;
  - IPv4 and IPv6 literals;
  - private, loopback and IPv4/IPv6 metadata addresses;
  - another port of an admitted name, which lands on the pinned port;
  - a connection to listeners bound on port 9 (zero accepts).
- **Rebinding.** A fixture resolver whose answers change; the engine keeps
  the pin.
- **WebRTC.** STUN and TURN (UDP and TCP) yield zero packets and zero
  connections.
- **QUIC and WebTransport.** An HTTPS fixture shows no QUIC and a refused
  WebTransport session, both to an admitted name and to an unmapped name.
- **Service workers and WebSocket.** A service worker registration and a
  WebSocket connection are refused.
- **Policy precondition.** A test registry hive with any mandatory Edge or Chrome policy makes the
  launch refuse.
- **Supervision.** The engine is a descendant of the worker inside the host
  job; killing the host leaves no engine process; the pipe handles are not
  inherited by engine child processes; the measured process count stays
  within SG-000074's job process limit.
- **Hostname hygiene.** Names with numeric, hex or wildcard labels, or
  containing separators, are refused.

## Implementation progress

**Slice 1: host-side confinement contract** (`crates/orcel-browser-host/src/confinement.rs`).
- `AdmittedDestination::admit(url, resolver)` is the only public
  constructor. It runs the existing `validate_navigation`, which resolves the
  name and pins its lowest public address with `select_public_address`. So
  every pin comes from the host's own resolution of that name. It then
  re-checks https, port 443 and `is_public_address`, and applies the stricter
  hostname hygiene.
- `resolver_rules`, `proxy_bypass_list` and `build_worker_argv` emit the
  six flags with the exact values in the table above.
- `assert_worker_argv_exact` refuses any argv that differs element for
  element from the host-built one.
- `assert_no_managed_policy` with `RegistryPolicySource` reads the Edge, Chrome or
  Chromium mandatory policy keys in HKLM and HKCU, both registry views, with
  `KEY_READ` only. It refuses on any value or subkey, and fails closed when
  a key is unreadable or the platform is not Windows.
- The SG-000074 `build_argv` and `assert_argv_clean` are unchanged and still
  refuse every confinement flag (a unit test proves this).
- The fixture pin constructor is compiled only into unit tests.
- No launch path uses this module yet, so the slice grants no authority.

**Native check of the emitted format (Edge 155).** An IPv4 pin and a
bracketed IPv6 pin (`MAP six.example [::1]:<port>`) each reached only their
fixture. Unmapped names failed with `ERR_PROXY_CONNECTION_FAILED`.

**Slice 2a: private worker package** (`apps/orcel-browser-worker`). It is standalone, like `apps/web`, so the identity-pinned npm workspaces stay unchanged.
- **Dependency.** `playwright-core` is exactly 1.63.0, with the admitted integrity. It is the only production package in the lockfile, has no install script and no runtime dependencies. All of this is checked mechanically against `dependency_admission`.
- **Protocol.** SG-000074 framing (u32 LE length + JSON, 64 KiB) with a closed generation-1 vocabulary:
  - host → worker: `hello`, `launch {engine, profile_dir, argv, env}`, `ping`, `shutdown`;
  - worker → host: `hello`, `launched`, `pong`, `bye`, `error {code}`.
  Unknown frames or fields are violations.
- **Launch check (defense in depth).** The worker re-checks the launch frame against this contract:
  - the frozen flags and the profile;
  - each resolver entry, parsed with the host grammar: an admitted-host name, an IPv4 or bracketed IPv6 pin, `:443`, and `MAP * ~NOTFOUND` last;
  - a bypass list exactly equal to those names in order, followed by `<-loopback>`;
  - the fixed proxy, WebRTC and QUIC values, and the blank page;
  - engine and environment allowlists, and absolute paths without dot segments.

  Address class stays the host's policy, because test builds pin fixtures to loopback. The worker then hands the argv to Playwright unchanged, with `ignoreDefaultArgs: true`. There is at most one engine per worker. Any violation, refusal, unexpected error, broken pipe, engine exit or end of input closes the engine.
- **Console isolation.** The global console is replaced by one that writes only to stderr. Verified: `console.dir`, `table`, `trace` and `log` put 0 bytes on stdout.
- **Native smoke run (Edge 155, local).** `dist/main.js` went through `hello` → `launch` → `ping` → `shutdown` with exit 0. The OS reported one browser process with the host argv, with no debugging port and no `--enable-automation`. No engine process was left after shutdown.

- **CI.** The root `npm test` runs the worker's install (`npm ci --ignore-scripts`), typecheck and tests. Both Node jobs, ubuntu and windows, therefore cover it without a workflow change. A dedicated `npm audit` of the worker lockfile in the supply-chain job is **pending**: it needs a workflow edit, which the current push token cannot make (no `workflow` scope). Until then the audit is a local check (0 vulnerabilities), and the lockfile admits only `playwright-core`, which has no dependencies.

**Findings that bind slice 2b:**
- The OS command line quotes arguments that contain spaces (the resolver rules), so the host must parse it with `CommandLineToArgvW` rules before the element-for-element comparison.
- Node acts on `NODE_OPTIONS` (verified with `--require`) before any worker code runs. The host must therefore build the worker environment from an allowlist and never inherit it; the worker's own refusal is only a second line.
- Inspector activation: **decided and enforced by the worker in slice 2b-i**. The worker refuses to start (exit 2, nothing on stdout) unless Node is 22.14+ and its Node options are exactly `--disable-sigusr1` (`startupRefusal`, with tests). A later `--no-disable-sigusr1` would otherwise re-enable activation (verified), and no `--inspect*`, `--require` or `--import` may accompany the flag. The slice 2b-ii launcher passes the flag and reports the browser as typed unavailable when the worker refuses.
- Service workers: Playwright's `serviceWorkers: "block"` only replaces `navigator.serviceWorker.register` with an init script, so page script may be able to bypass it. Block service workers by engine or protocol means, and prove it with a native probe.
- Worker environment allowlist: also exclude the OpenSSL start-up variables (`OPENSSL_CONF`, `OPENSSL_MODULES`, `OPENSSL_ENGINES`, `SSL_CERT_FILE`, `SSL_CERT_DIR`). The worker refuses them as a second line.
- Release packaging (A2): the `playwright-core` NOTICE, the SBOM entry and provenance enter the release with the packaged worker. Packaging strips the `node_modules/.bin` link to the Playwright CLI, which is never exposed.

**Slice 2b-i: native confinement probes in CI** (`apps/orcel-browser-worker/src/native.test.ts`). These run against the installed Edge through the root `npm test`, so the **Node / windows-latest** job produces real-engine evidence. On Windows a missing engine fails the suite. On other platforms the suite is skipped, because only Windows results count. The probes use owned loopback fixtures on port 443 and an argv the worker contract accepts.

1. **Lifecycle.** The worker drives the engine through `hello` → `launch` → `ping` → `shutdown`.
   - Exactly one browser process exists. Its OS command line, split with `CommandLineToArgvW` rules, equals `[engine, ...argv]`.
   - No process carries `--remote-debugging-port`/`-address` or `--enable-automation`.
   - Exit code 0, and no engine process remains.
2. **Worker kill.** Killing the worker takes the engine down with its pipe. The Job Object of slice 2b-ii remains the guarantee.
3. **Layers 1 and 2 with no policy route at all.** The admitted name reaches the fixture, and another port of it lands on the pinned port. All of the following fail:
   - an unmapped name;
   - a real public name;
   - IPv4 and IPv6 literals (including the fixture's own address and port);
   - a private address;
   - IPv4 and IPv6 metadata addresses.

   Listeners on `0.0.0.0:9`, `127.0.0.1:9` and `[::]:9` accept nothing, and the fixture sees only the two admitted requests.
4. **WebRTC.** STUN to loopback and to the first LAN address, and TURN over TCP, gather no ICE candidate, send no UDP packet and open no TCP connection.
5. **Inspector.** With `--disable-sigusr1`, `process._debugProcess` from a same-user process is refused and no listener appears on 9229. A negative control without the flag shows that the probe detects an activated inspector.

**Evidence validity (review of PR #295).**
- Each probe that could pass vacuously has a control:
  - WebRTC is re-run with the default policy, outside the contract, and must then gather candidates and reach the STUN listener. ICE gathering is awaited to completion, not a fixed sleep. The UDP trap listens on every interface, so the LAN case can be observed.
  - The inspector control activates a plain Node process and must see a listener.
- Each denied destination must fail with `ERR_PROXY_CONNECTION_FAILED` specifically, so that a regression in layer 2 cannot hide behind layer 1.
- A failing process query throws instead of reporting "no processes".
- Cleanup runs last-in, first-out and always runs every step, so a failed probe cannot leave an engine, a server or a profile behind. A fresh run leaves 0 profiles.

**Contract tests not yet covered (slice 2b-ii, with the host launcher):**
- comparing the command line after a navigation;
- checking that every engine process is a descendant of the worker inside the host Job Object;
- TURN over UDP;
- QUIC and WebTransport, and the service-worker block (these need an HTTPS fixture);
- the managed-policy refusal on a test hive;
- DNS-rebinding resistance with a fixture resolver whose answers change;
- refusal of a second browser-process engine in the job;
- the job process limit;
- whether pipe handles are inherited.

**Local result (Windows 11, Edge 155):** all 25 worker tests pass, 5 of them native, and the run exits cleanly in about 45 s.

**Slice 2b-ii-a: host launcher** (`crates/orcel-browser-host/src/worker_launch.rs`, `worker_process.rs`). The launch sequence:

1. Validate the request. A missing Node or worker is typed `UnsupportedRuntime`; a missing engine is `NoEngine`.
2. Apply the managed-policy precondition. Any policy, or an unreadable key, is typed `ManagedPolicy` and refuses before anything starts.
3. Build the engine argv with `build_worker_argv`.
4. Build the worker environment from an explicit allowlist (SystemRoot, SystemDrive, PATH=System32, TEMP, TMP). It is never inherited.
5. Start Node with exactly `--disable-sigusr1` and the worker entry point:
   - **suspended**, then assigned to a kill-on-close Job Object (the SG-000074 limit of 32 active processes), then resumed;
   - with `DETACHED_PROCESS`, so there is no console and no `conhost.exe`;
   - with inheritance restricted by `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` to its stdin, stdout and a `NUL` stderr.
6. Exchange `hello`, then `launch`, over the closed protocol with bounded waits (15 s handshake, 60 s launch). A worker that exits with code 2 before answering is typed `UnsupportedRuntime`; a silent worker is typed `LaunchFailed` and its job is terminated.
7. **Verify the job** (`classify_job`):
   - its only members are the worker, running with exactly its host-built arguments, and processes of the verified engine image;
   - no member carries a forbidden flag, in any spelling Chromium accepts on Windows (`--`, `-` or `/` prefix, any case);
   - exactly one browser process exists, where the process type is derived the way Chromium derives it: switches end at a bare `--` or at `--single-argument` (matched in any spelling, which fails closed), the last `type` switch in any accepted spelling wins, and an absent or empty value means the browser;
   - that process's OS command line, read with `NtQueryInformationProcess` and split with `CommandLineToArgvW`, equals `[engine, …host argv]`;
   - a member that cannot be inspected is accepted only if it has left the job in the meantime.

The engine in a launch request is a `discovery::Engine`, so only an engine that discovery verified (kind, version, publisher) can be launched. `node` and the worker entry point must come from Orcel's install records.

Verification runs once, when the launch completes. Afterwards, only the job limit and kill-on-close constrain the worker. The product caller must call `verify` again before any authority is granted for a navigation.

Shutdown asks for `bye` and waits for exit 0. It then terminates the job regardless and confirms it is empty, and finally removes an ephemeral profile. Kill and drop take the same path without the exchange.

**Native tests** (`worker_launch_tests.rs`, real Node worker and Edge 155). These are ignored in a plain `cargo test` with a documented reason. The root `npm test` runs them via `npm run browser-launcher:native`, so the **Node / windows-latest** job runs them. The runner fails unless exactly 12 tests run and pass, so a filter that matches nothing cannot pass vacuously. All 12 pass locally in two consecutive runs. On the first CI run, 10 of the then 11 passed on the hosted runner. The lifecycle test failed there because the runner carries Edge policies, which led to the split below.

| Test | What it proves |
|---|---|
| Lifecycle | With no managed policy (a stand-in source), the job verifies and `ping` answers. Shutdown is graceful, the job empties, every recorded member dies, and the launcher removes the profile. |
| Real registry precondition | On the actual machine, the launch happens exactly when the policy check passes, and is typed `ManagedPolicy` with nothing started exactly when it refuses. The log records which branch ran: GitHub's Windows runners carry Edge policies, this development host does not. |
| Drop | Dropping supervision kills every member and removes the profile. |
| Crash and restart | The killed worker is detected (`ping` fails) and the job empties. The same profile relaunches, answers `ping`, and shuts down clean. |
| Host death | A separate host process is hard-killed with no destructor, and kill-on-close takes the worker, the browser and every helper down. |
| Foreign or second browser | `PING.EXE`, then a second Edge browser process (started suspended, so it cannot exit or start helpers outside the job first), are assigned into the job. `verify` refuses each one, and the job still empties. |
| Handle inheritance | An inheritable pipe that the host created reaches EOF as soon as the host closes its copy, so the worker and engine did not inherit it. Negative control: a process started without a handle list does inherit it. |
| Silent worker | It is typed `LaunchFailed` after the handshake timeout, and its process is dead. |
| Refused runtime | It is typed `UnsupportedRuntime`. |
| Managed policy | `Populated` and `Unreadable` are typed `ManagedPolicy`, and nothing starts. |
| Registry reader | A real test key under `HKCU\Software\OrcelTest` is read as absent, then empty, then populated (by a value, and by a subkey alone), then absent. |

**Findings:**
- **Discovery defect (fixed here; SG-000074 path).** The engine version was probed by running `msedge.exe --version`. On Windows, Chromium prints no version for that, and instead hands the command to an already running browser session ("Opening in existing browser session."), so it can touch the user's personal profile. Discovery therefore always failed on Windows, which made SG-000074's `live_host_or_typed_unavailable_with_lifecycle` pass as "unavailable" without exercising the live host. The version is now read from the executable's version resource, without executing anything. On this host, discovery verifies Edge 155.0.4283.45 (publisher verified) and the SG-000074 live host launches.
- **`conhost.exe`.** `CREATE_NO_WINDOW` still attaches a hidden console host to Node, which the job check correctly refused as a foreign process. `DETACHED_PROCESS` removes it.
- **Kernel-held profile files.** After every job member is dead, Restart Manager has reported `System` (pid 4) briefly holding memory-mapped profile files. Under load this exceeded 10 s. No Edge or Node process outside the job held a profile in these runs. Removal now retries for up to 30 s and reports `profile_removed: false` if the files are still held. The tests fail unless the launcher itself reported removal; on failure they diagnose the held file and clean up.
- **Profile lock after a crash.** Chromium's exclusive `lockfile` in the profile stays held for 0.2–4.4 s after every job member has exited. A relaunch on the same profile inside that window makes the new engine exit (typed `LaunchFailed`). The crash test now waits, with a bound, for the lock to be released before it relaunches. A fresh profile per lifetime, as production uses, avoids this entirely.
- **No out-of-job residue.** At the end of every supervised native test, a machine-wide native process snapshot (Toolhelp, plus each process's OS command line) must find no inspectable process that still names the profile on its command line. A leftover engine of the same user is always inspectable; processes of other users or protected processes are skipped. A control confirms that the same query does see the engine while it runs.
- **Host death and the profile directory (#298, resolved below).** Kill-on-close takes the worker and the engine down, but a host that dies never removes its ephemeral profile itself. A profile named by `ephemeral_profile_dir` is removed by the next launch in the same root; see the #298 section.
- **Crash-session restore.** A profile reused after a crash restores the previous session (9 renderers instead of 2). Production must use a fresh ephemeral profile per lifetime, because reusing one carries state over. The launcher does not enforce this (`ephemeral_profile: false` is accepted, and the crash test reuses a profile on purpose), so the future product caller must.
- **Unit variants in serde.** With `deny_unknown_fields`, serde still accepts unknown fields on unit variants of an internally tagged enum. The worker replies use empty struct variants instead. The SG-000074 host protocol (`proto.rs`: `Shutdown`, `Bye`) has the same looseness; it is tracked in #296.
- **No crash-report uploads from a crash.** An abrupt worker kill leaves only Crashpad metadata (no report or dump), so a crash produces no upload candidate.

**Slice 2b-ii-b, part 1: HTTPS-fixture probes** (`apps/orcel-browser-worker/src/native.test.ts`).

The fixture origin is served over TLS on 127.0.0.1:443, advertising `alt-svc: h3`. Its certificate is a throwaway one, generated at test time with Git for Windows' OpenSSL, and only the direct test launches trust it (`--ignore-certificate-errors-spki-list`). The production argv carries no certificate flag. UDP listeners on 127.0.0.1:443 (the admitted name's pin) and 127.0.0.1:4433 (an IP literal) count datagrams.

| Probe | Result (Edge 155, local) |
|---|---|
| Alt-Svc HTTP/3 upgrade under the confinement argv | **Holds.** 0 datagrams over two navigations; `--disable-quic` stops it. |
| WebTransport to an IP literal | **Holds.** 0 datagrams; the no-route proxy refuses it. Control: without the confinement flags, the same attempt sends UDP. |
| WebTransport to an admitted name | **Accepted residual risk (#300; founder decision 2026-10-11).** QUIC Initial packets reach the admitted name's pinned address directly, uninspected by the SG-000075 policy route. No engine switch disables it (`--disable-features=WebTransport`, `WebTransportOverHTTP3` and `--disable-blink-features=WebTransport` were all tested), and Playwright routing does not see it. The probe asserts the boundary that must hold: unadmitted names, unmapped public names and IP literals all fail with `WebTransportError`, and no datagram reaches the pin or the literal for those attempts. It logs the admitted-name datagram count as evidence. |
| Service-worker denial | **Closed (#301).** The worker launches with `serviceWorkers: "allow"`, which keeps service-worker requests routable, and the route stack aborts every request carrying `Service-Worker: script`, so same-origin registration (direct or through the prototype) fails. A cross-site iframe could still register, because its script fetch never reaches routing. Since slice 3a, the policy route refuses cross-origin frames (`mediate_frame`), so that iframe never loads. A native probe asserts the frame was asked about and refused, `other.test` was never contacted, and no web service worker runs. A second probe pins the route order by running the stack with an allow-everything policy. |

In these probes the no-route proxy refuses the IP literal and nothing leaves the admitted pin. The earlier HTTP-fixture probe covers unadmitted names. Both gaps stayed inside admitted destinations but evaded the policy route, which already denies the equivalent WebSocket traffic. #300 is now a founder-accepted residual risk. #301 is closed by slice 3a, so `KNOWN_GAPS` is empty and the gate is open. This is enforced in code. `gaps.ts` lists the known gaps (`KNOWN_GAPS`), which the `todo` probes reference. While that list is non-empty, a conditional type makes `tsc` (build and typecheck) fail if `HostFrame` gains any frame name outside the launch vocabulary, however that frame is written. Named types, quoting, spacing and a widened `string` frame were each verified to fail. The gate covers frame names only: a field added to an existing frame is not caught by it, though `parseHostFrame`'s exact-key checks would have to change visibly for such a field to be accepted. `gaps.test.ts` mirrors the check at runtime (`parseHostFrame` rejects other frame names) and requires every gap to keep its `todo` probe.

**Still to be done in slice 2b-ii-b:**
- revisiting #300 if Chromium gains an engine-level WebTransport kill switch;
- a real public name pinned by the host reaching only its pin;
- the job process limit under a heavy page;
- the release packaging of the worker (NOTICE, SBOM, `.bin` strip).

**Slice 3a: live navigation decided by the host.** Code: `worker_navigation.rs`; the worker's `routes.ts`, `redirect-guard.ts` and `routing.ts`; worker protocol generation 2.

The host stays the authority. **An engine lifetime admits exactly one destination** (`validate_launch`). `navigate` first runs `NavigationPolicy::begin`, which requires an HTTPS URL on that admitted name.

Two layers then govern traffic:
- **Network layer (complete).** The pinned resolver and the no-route proxy make every other host unreachable, whatever issues the request: pages, workers, or the browser process itself. The one exception is the accepted residual #300: WebTransport UDP to the admitted name's own pin.
- **Per-request layer.** Engine requests on the admitted origin are described to the host as `route_request`s and continue only on an explicit allow, by the means listed below.

A fresh-context judge measured that the browser process issues some requests outside every route and guard: `fetchLater`, Reporting API and CSP reports, FedCM, audio-worklet modules, and NoStatePrefetch (`<link rel=prerender>`). With a second admitted name, those reached it undecided. With one admitted name they can reach only the page's own origin, which SG-000075 permits for subresources anyway. No capability is lost: the policy is exact-origin, and another site means another lifetime.

The per-request means are:
- **Routed requests.** Documents, frames, popups, fetch and XHR, and other subresources, including dedicated-worker scripts and their imports.
- **Redirect hops.** Playwright routes never see them. A per-page CDP `Fetch` guard pauses each hop and forwards it as a `redirect` query.
- **Service workers and SharedWorkers.** Service-worker scripts are refused by the route stack. SharedWorker requests are never routed (measured), so the API is removed from the engine; see the argv amendment below.
- **Speculation rules.** Speculation-rules prefetch and prerender run in the browser process, outside every route and guard. This was measured: an undecided request to another admitted name, and a prerender whose activation moved the page with no request at all. Engine switches did not stop them (`Prerender2`, `SpeculationRulesPrefetchProxy`, `--disable-blink-features=SpeculationRules`, and CDP `Page.setPrerenderingAllowed` were tested). The profile preference "Preload pages: never" (`net.network_prediction_options` = 2) does stop them, so the host writes it into the profile before every launch (`seed_profile_preferences`). Existing preferences are kept, and malformed ones fail closed.

The decisions are the existing SG-000075 policy:
- the first document must be the requested URL;
- a page-initiated top-level navigation must stay on the page's origin;
- redirects of a navigation are checked by `RedirectChain` (same origin, at most 5 hops, no loops);
- a later subresource redirect must stay on the page's origin;
- frames, popups, fetch and subresources are checked by `mediate_*` (exact origin).

All of these are checked against the **host's own** page origin: the begun origin during a navigation, otherwise the committed one. A request whose reported origin disagrees with the host's is refused, so a page that moved itself without a decision gains nothing. The committed document must be on the navigation's origin, and a failed navigation is aborted so its state authorizes nothing.

**Argv amendment (authority delta, narrowing):** the confinement argv gains `--disable-blink-features=SharedWorker`. It is applied by the host builder (`confinement.rs`), required by the worker's exact-argv contract, and covered by the OS command-line verification.

**Implementation findings:**
- A refused navigation's error page commits late, sometimes more than once, and interrupts the next navigation in the same page. Each host navigation therefore runs in a fresh, guarded page.
- Edge runs a built-in component extension service worker even with `--disable-extensions`. The probes count only web service workers.

**Known limits:**
- Browser-process requests (see above) on the admitted origin are not individually decided. They are bounded by the one-destination network layer, but the host cannot decide, log or rate-limit them, and a deferred `fetchLater` POST or a batched report can reach the admitted site after the host has moved on. A later slice that adds write approval or a non-GET audit must account for this. Options are to close these APIs with engine switches, or to close the lifetime before trusting such controls.
- (Fail closed) The host decides only while it is in a call. A page's own requests made while the host is idle wait for up to 10 s and are then refused.
- A popup's first navigation is not completed, so popups do not work, but nothing leaks.
- WebTransport to admitted names remains the founder-accepted residual risk #300.

**Native end-to-end evidence:** the real host, worker and Edge run against a two-name HTTPS fixture (`scripts/https-fixture.mjs`, test only). The ground truth is the fixture's request log.
- An admitted page loads, and a same-origin redirect commits.
- A cross-origin redirect, a redirect loop and a 7-hop chain are refused, typed as denied.
- Non-admitted, `http:` and IP-literal URLs are refused before anything is sent.
- The mixed page contains cross-origin iframe, image, fetch, `<link rel=prefetch>`, speculation-rules prefetch and prerender, beacon, `EventSource`, a blob worker importing a cross-origin script, a CSS `@import`, `<a ping>`, a SharedWorker, and popups including one that redirects cross-origin. It never contacts `other.test`, while the same-origin resources load.
- In the prerender-then-activate escape, the page's navigation to `/redirect-evil` is observed and its cross-origin hop is refused.

The mixed page also issues the browser-process requests the judge measured (`fetchLater`, a CSP report-to violation with `Reporting-Endpoints`, FedCM, an audio worklet, `<link rel=prerender>` of a cross-origin redirect); none reaches `other.test`. The judge's runs with two admitted names are the control: with two names admitted, these requests did reach `other.test`.

The test passed in repeated local runs. The fresh-context judge's rounds 1 and 2 on this slice were BLOCK. The speculation-rules, SharedWorker and host-origin findings, and the one-destination rule, are their fixes.

**Test-only certificate trust:** `WorkerLaunch.test_trusted_spki` exists only under `cfg(test)` and appends `--ignore-certificate-errors-spki-list`. The worker accepts that flag only when every admitted pin is loopback; production pins are never loopback. A governance test pins the flag to `cfg(test)` code.

**Slices 3b and 3c: observation and approval-gated activation** (worker protocol generations 3 and 4).

- **Observation (SG-000076).**
  - The worker sends a bounded tree from `ariaSnapshotJSON({mode:"ai"})`, covering shadow DOM and iframes. Each node carries a ref, a role, an accessible name and, for links only, a bounded URL. Field values are never forwarded; this was measured, because the snapshot shows a password value in clear text under role `textbox`.
  - An accessible name can still carry a field's text: a button labelled by a password field through `aria-labelledby` was measured. Names are therefore keyed with a per-lifetime secret from the system RNG before they enter SG-000076, so a caller cannot check a digest against a guessed value. Within one lifetime, equal names still produce equal digests, so a caller can tell that two names match, and could confirm a value it planted itself through an approved fill. Raw names stay in a host-only index, and no product API exposes them.
  - The snapshot must be of exactly the committed URL. Node identities are bound to the document generation.
  - Worker truncation is propagated, and only nodes the caller actually received can be acted on.
- **Activation (SG-000077).**
  - Selection is host-side and typed: `select_latest_dated_link`. It scans bytes only, so non-ASCII names cannot crash the host, and it refuses ties.
  - The host does not model element state. A target's `state` must instead be the link's host-resolved destination (`link_destination`; absolute `https://` or root-relative links only), so the one-shot approval covers where the click goes.
  - The destination is checked against the page's origin before the approval is consumed.
  - During the click, the host accepts exactly one page-initiated document request, and it must be that destination. A script redirect and an `href` swapped after observation were both measured and are refused at the request. A click that requests no document (`pushState`, a script action) is not a verified activation.
  - The destination's server may still redirect same-origin. That is decided hop by hop by `RedirectChain`, so the committed URL can differ from the approved destination; the server already controls what it serves there.
  - The host does not see the HTTP method, so a click handler that submits a form to the destination is accepted as well. That gives the page nothing it cannot already do with a same-origin `fetch`.
  - Matching is by exact string. A link that Chromium normalizes before requesting it (spaces, `..`, a fragment) is therefore refused, failing closed, and its approval is spent.
  - The worker clicks by `aria-ref`. A replaced node or an overlay makes the click time out rather than hit another element (measured).
- **Known limits.**
  - Off-screen or `opacity:0` links appear in the snapshot and can win the date selection. Host policy still applies to whatever they open.
  - A click that has a side effect without opening a document (for example `fetch`) is refused as unverified only after it has happened, and its approval is consumed.
  - A `target=_blank` click that opens a popup is not an activation; the popup itself is mediated by host policy.

**Evidence (local, Edge 155), native end-to-end tests on the HTTPS fixture:**
- Observation never shows a raw name, the user name or the password to the caller, and the secret-named button's digest is keyed. The host index holds the dated links and their URLs, and a page that moved itself is refused as stale.
- Activation follows the latest dated link with an approval. A forged digest, a replayed approval, the stale node, the cross-origin latest link (without consuming its approval), the script redirect and the swapped `href` are all refused, and none of their destinations is requested.

A fresh-context judge's first round on these slices was BLOCK. The byte-safe date scan, keyed names, destination-bound approvals, host-side state and propagated truncation are its fixes.

**Slice 3d: the approved inert-PDF download journey** (worker protocol generation 5).

- **Founder amendment to SG-000078 (2026-10-11): inert PDFs.** `validate_inert_pdf` admits a download only if every check holds:
  - the **file name actually written** (the approved destination's own name) ends in `.pdf`;
  - the declared media type is `application/pdf` (parameters allowed);
  - the content sniffs as PDF;
  - the size is within `MAX_TRANSFER_BYTES`.

  The worker's suggested name (from Content-Disposition or the URL) is advisory and never decides the check, so a PDF-headed polyglot cannot be committed as `.cmd` or `.html`. Every other destination name goes through the general `validate_download_type` allowlist. "Inert" describes how Orcel treats the bytes: the engine never renders them, and the host never opens or executes them; it only stores them.
- **Destination names.** `validate_relative_destination` additionally refuses:
  - a curated set of Unicode format characters (bidi controls, zero-width marks, the BOM, tag characters; not every Cf character), which could make a name display with another extension;
  - device names with trailing spaces before the extension (`con .pdf`), `COM0`–`COM9`/`LPT0`–`LPT9` including the superscript digits, and `CONIN$`, `CONOUT$` and `CLOCK$`;
  - 8.3 short names (`~` followed by a digit), which could alias an existing entry.

  Non-ASCII names stay allowed.
- **Approval.** A download needs its own SG-000077 action, `download` (a `click` approval is refused, and an activation refuses a `download` approval). The target's `state` is the host's `download_binding`: the link's host-resolved destination, the approved folder's real path and the normalized file path. The one-shot approval therefore covers what is fetched and where it lands, and an approval for another folder or file is refused without being consumed. The link is checked against the page's origin before the approval is consumed. During the click, the host accepts exactly one page-initiated document request, and it must be that link.
- **Capture (measured).** Headless Edge renders a PDF navigation in its built-in viewer. It raises no download event, and the navigation's response body is the viewer's wrapper page. Seeding `plugins.always_open_pdf_externally` did not change this.
  - While a download is armed, the worker's per-page CDP `Fetch` guard pauses the next main-frame document at the response stage.
  - It reads the original bytes as a stream (`Fetch.takeResponseBodyAsStream` and bounded `IO.read` calls), sending no new request, and stops at 8 MiB, so an oversized body without a `content-length` is never held whole.
  - A non-2xx response, including a redirect, is refused: redirects are not followed.
  - It then fulfils the navigation with an empty `text/plain` page, so the document is never rendered; if fulfilling fails, the request is failed instead. Response-stage pausing ends after each capture.
  - Once a capture has timed out, any later main-frame document of that page is failed, and the worker closes the page whenever a download fails after the click.
  - The click does not wait for the navigation, so a slow server is bounded by the capture's own 30 s timeout.
  - Playwright's `acceptDownloads` stays off. The per-page `Page.setPrerenderingAllowed(false)` switch is kept as a second layer behind the seeded preference.
- **Staging and commit.** The worker writes the bytes create-only (`wx`) to a staging path chosen by the host, inside the lifetime's own staging directory. The protocol accepts only an absolute `.part` path and refuses relative, UNC and other paths. The host then:
  - requires the captured URL to equal the approved link exactly, on the page's origin;
  - reads the staged file once, through a bound;
  - checks the declared size against the actual size;
  - applies the type check to the destination's name;
  - requires that the approved link was the document requested;
  - records the SHA-256 digest;
  - commits create-only through held handles (#307, below). Each folder below the approved folder, and the file itself, is opened relative to its parent's handle without following any reparse point.

  An existing destination is refused before anything is sent. The staging directory exists before the approval is consumed. The staging file is always removed, and the staging directory is removed at shutdown.
- **After a download**, the committed document is the inert blank page, one generation later, and every earlier node identity is stale. A caller observes again only after navigating again.

**Known limits:**
- The host cannot see the HTTP method, the same limit as for activation.
- A link whose server redirects, even within the same origin, cannot be downloaded. It fails closed, and the approval is spent.
- A link with a fragment (`#...`) cannot be downloaded. It is refused before the approval is consumed.
- A PDF can still contain active content. Orcel does not render or open it, but a user who opens the stored file later is outside this boundary.
- The junction check now has native tests (#307): junctions are created with `DeviceIoControl` and `FSCTL_SET_REPARSE_POINT`, with no shell.

**Evidence (local, Edge 155), from the native journey E2E test on the HTTPS fixture** (`the_journey_downloads_the_latest_report_create_only_and_verified`):
- The host selects the latest dated report. The approved download stores exactly the fixture's bytes, verified independently along with their SHA-256 digest, at the approved relative path.
- A traversal destination is refused before dispatch, and its approval is not consumed.
- A click approval, and a download approval naming another file, are both refused without being consumed.
- A second download to the same destination is refused (create-only), and the first file is unchanged.
- Each of the following is refused, and none leaves a file:
  - an oversized PDF (9 MiB);
  - an executable disguised as a PDF (`MZ` bytes served as `application/pdf`);
  - a PDF-headed batch/HTML polyglot committed as `evil.cmd`, as `evil.html`, or under a right-to-left-override name.

The worker's unit tests cover the generation-5 frames, the staging-path rules, and typed download failures. The host's unit tests cover the new destination-name rules, with non-ASCII controls.

A fresh-context judge's first round on this slice was BLOCK. The destination-name type check, the `download` action and its binding, the exact-URL check, the junction-safe folder creation, the bounded reads, the restored prerender switch and the post-timeout failing of documents are its fixes.

**Slice 3e: typed outcomes for timeouts, cancellation and crashes** (acceptance A6; issue #307, item 1).

- **Typed failure reasons.** `UnavailableReason` gains `TimedOut`, `ActionFailed`, `WorkerExited` and `Cancelled`. Before this slice:
  - worker-reported `timeout`, `failed` and `busy` mapped to `LaunchFailed`;
  - a worker that died mid-operation mapped to `ProtocolViolation`.

  Worker-reported `denied` stays `Invalid`, and unknown reasons stay `ProtocolViolation`.
- **The lifetime ends on a channel failure, a host deadline or a cancellation.** After the handshake, the host terminates the whole job at once, so nothing stays in flight, and every later call returns the same reason. The reasons:
  - a malformed or cut-short frame is `ProtocolViolation`, whatever the worker does next;
  - output that ends cleanly while the worker still runs is `ProtocolViolation`;
  - a worker that has exited is `WorkerExited`;
  - the host's own deadline is `TimedOut` (the worker's own reported timeouts are ordinary typed results, and the lifetime stays usable);
  - a cancellation outranks whatever symptom it caused.

  During the handshake, the deadline stays `LaunchFailed`, and exit code 2 is `UnsupportedRuntime`; neither mapping applies after it.
- **Cancellation.** `BrowserWorker::cancel_handle` returns a `CancelHandle`. It is `Send`, `Clone`, holds only a weak reference to the job (so it never keeps the job alive), and grants nothing else. `cancel()` may be called from any thread while an operation runs: it terminates the job, and the blocked call returns `Cancelled`. A cancellation that arrives after the worker's reply still wins: the host checks the flag again just before the create-only commit, so nothing is written. An ended or cancelled lifetime refuses `activate` and `download` before the approval is checked, so the approval is not spent.
- **Evidence (local, Edge 155), from the native test `a_stalled_cancelled_or_killed_download_is_typed_and_commits_nothing`.** It uses a fixture PDF whose body never ends. Each trigger fires only after the fixture has logged the stalled request, so the download is provably in flight.
  - **Timeout:** the request is logged, and the download fails as `TimedOut` after at least 29 s and before the host's 45 s deadline. The approval is spent, nothing is committed or staged, and the worker still answers `ping`.
  - **Cancellation:** another thread cancels mid-download. The outcome is `Cancelled`, and the approval is spent. A later download on the cancelled lifetime returns `Cancelled` and leaves its approval unspent. Nothing is committed or staged, every job member dies, and a later `ping` reports `Cancelled`. `kill` reports the job empty and removes the staging folder and the profile.
  - **Crash:** in a second lifetime, the worker is killed mid-download. The outcome is `WorkerExited`, the approval is spent, nothing is committed or staged, and every member dies. A later `navigate` reports `WorkerExited`, and `kill` cleans up as above.
- **Known limits (follow-ups in #309).**
  - A worker that writes the staged `.part` file and then dies before replying: now tested natively (#309, below).
  - A host crash is outside A6, which is about the worker and its operations. Since #307 it can no longer leave a partial file under the approved name, and since #309 the next launch sweeps the staging folder. The content is written to a hidden temporary file marked for deletion, which the system removes when the host's handles close. Two short windows remain, listed in the #307 section below, where a `.orcel-dl-*.part` file can be left behind. A host crash also leaves its staging folder in `temp_dir`, which the next launch removes (#309).

**#307: download commits through held handles, and typed download failures.**

- **The approved folder is bound at commit.** The approval's `download_binding` names the approved folder's real path. At commit, the host opens the folder once and requires the handle's real path (`GetFinalPathNameByHandleW`) to equal the bound one. A folder whose path now leads elsewhere, such as a junction retargeted between approval and commit, is refused as "the approved folder changed since it was approved".
- **No window between check and create.**
  - **The folder is held:** it is held without delete sharing for the whole commit, so it cannot be renamed or removed. Because the hold shares write access, another process could still turn the held, empty folder into a mount point. The next relative open then fails as a reparse point (`STATUS_REPARSE_POINT_NOT_RESOLVED`) and nothing is written.
  - **Handle-relative opens:** each subfolder, and the file, is opened or created relative to its parent's handle with `NtCreateFile` and `OBJ_DONT_REPARSE`. A junction, symlink or mount point anywhere below the folder therefore refuses the write ("a reparse point below it") instead of redirecting it.
  - **Subfolders are held too:** each is held without delete sharing until the file has its name.
  - **Replaced:** this takes the place of the earlier path-based checks, which re-canonicalised the folder and could write once before the post-write check removed an escaped file.
- **No partial file under the approved name.**
  - **Write:** the content goes to a hidden temporary file in the target folder, marked delete-on-close (`FileDispositionInfo`), so the system removes it if the host dies while it is marked.
  - **Rename:** the file is flushed and its hidden and temporary attributes are cleared while it still has its temporary name, so the committed file is an ordinary file and never stands under the approved name hidden. Then the mark is cleared (a file marked for deletion cannot be renamed), and the file takes its name relative to the folder's handle with `NtSetInformationFile` (`FileRenameInformation`, no replace), so an existing file is never replaced.
  - **Final check:** the named file's real path must be inside the held folder.
  - **Any failure after creation** marks the file for deletion again, through a drop guard.
  - **The returned path** is the one the held handle reached, not one rebuilt from the caller's text.
  - **Windows that remain if the host dies:**
    - between creating the temporary file and marking it, which leaves an empty, hidden temporary file;
    - between clearing the mark and the rename, which leaves the full content in a visible temporary file.

    The temporary name is `.orcel-dl-<16 hex>.part`, one per destination since #309.

    Neither leaves a file under the approved name, and since #309 the next commit to the same destination removes the leftover (below). After the rename the commit only checks the result, so a crash there leaves the complete, ordinary file under its approved name.
- **Typed download failures.** A download that commits nothing reports a `HostError::Download` reason:
  - `HttpStatus`: a non-2xx answer, a redirect included, since the approved document is exactly the approved link;
  - `Oversized`: past the transfer bound;
  - `TimedOut`: no document in time; a request the browser policy refuses never answers, so it also ends here;
  - `EngineFailed`: the click or capture failed.

  A worker that reports `busy` stays `Unavailable(ActionFailed)`, and unknown reasons stay `ProtocolViolation`.
- **Evidence.**
  - **Unit tests on real NTFS** (`approved_folder.rs`, Windows; junctions made with `FSCTL_SET_REPARSE_POINT`, no shell):
    - a nested create-only commit leaves exactly one file, an ordinary one (neither hidden nor temporary), and no temporary file;
    - a second commit to the same name is refused, and the first is unchanged;
    - a junction directly below, or two levels below, the folder refuses the write, and its target stays empty, while the same folder accepts a write that does not pass through it;
    - a folder path retargeted from one real folder to another after approval is refused, and neither folder receives a file;
    - a held folder can be neither renamed nor removed until it is released;
    - a file where a folder should be refuses the write and is unchanged.
  - **Unit tests on all platforms:** the download failure mapping.
  - **Native E2E** (Edge, HTTPS fixture):
    - the stalled download is `Download(TimedOut)`, and the 9 MiB one is `Download(Oversized)`;
    - a 404 and a same-origin redirect are both `Download(HttpStatus)`, and nothing lands;
    - a real download to `link\plain.pdf`, where `link` is a junction inside the approved folder to a writable outside folder, is refused with "reparse point", and the outside folder stays empty;
    - the same download to `real\plain.pdf` commits the fixture's exact bytes.
- **Known limits.**
  - A request the browser policy refuses during a download surfaces as `TimedOut`, not as a policy refusal, because the refused request never produces a response for the capture.
  - The hold needs the approved folder to be shareable: if another process already holds it with delete access, or without sharing write, the commit is refused as "cannot be held" (fails closed; Explorer and indexers share everything).
  - Subfolders created for a destination stay if the commit is then refused (for example on a name collision); they are empty.

**#309: staged-file crash tests and leftovers after a host crash.**

- **A worker that dies or hangs after staging.**
  - **The instrumented worker:** the test runs the real worker through a test-only entry point that replaces its staged write (`writeFileSync` of a `.part` path; the module's named import is a live binding, updated with `syncBuiltinESMExports`).
  - **A worker that dies:** it writes the staged file, then exits without replying. The download fails as `WorkerExited`.
  - **A worker that hangs:** it blocks for 50 s, past the host's 45 s deadline, then writes. The download fails as `TimedOut`, because the host terminates the job on its own deadline. Right after the failure the worker process is dead (the guarantee), and 55 s after the failure, past the latest moment the block could end, nothing was written (the evidence).
  - **In both cases:** nothing is staged afterwards, nothing reaches the approved folder, the job empties, and the staging folder is removed at shutdown.
- **A host killed mid-commit.**
  - **The test:** an ordinary test (no browser needed) runs a real commit in a child process: the test binary itself, running a child test that does nothing without its parent's environment. The child stops at a test-only crash point and is killed hard (`TerminateProcess`):
    - after the temporary file is created: an empty hidden temporary file is left;
    - after the content is written, while marked for deletion: nothing is left;
    - after the mark is cleared, before the rename: the full content is left in a visible temporary file.
  - **The approved name:** in every case nothing stands under it.
  - **The next commit:** a commit to the same destination succeeds and leaves only the committed file. The temporary name is now the same for every attempt at a destination (`.orcel-dl-<first 16 hex of SHA-256 of the lower-cased file name>.part`), so a leftover is found and removed.
  - **Removing a leftover:** it is opened exclusively, without following a reparse point. A commit still in progress holds its temporary file exclusively, so a second commit to the same destination is refused ("in progress") rather than removing it (tested). A hard link to a user file loses only its name; the user file keeps its content.
  - **A leftover that cannot be removed refuses that destination:** a read-only file, a reparse point, or a file another reader holds open (an indexer, antivirus) gives a typed "cannot be removed" or "in use" refusal until it is released or removed. The commit code never creates such a leftover itself.
  - The crash points exist only in test builds.
- **Staging folders of a host that died.**
  - **The sweep:** at launch, the host removes every `orcel-sg108-staging-<pid>-<hex>` folder in its temp directory whose owning process is no longer running. A process that cannot be queried for any other reason counts as running, so only certainly-dead owners lose their folder.
  - **What it never touches:** its own folder, and a reparse point named like a staging folder (or its target).
  - **Bounds:** 4,096 staging-named entries looked at and 64 folders removed per launch. `BrowserWorker::swept_staging()` reports the count.
  - **Enumeration:** only names matching `orcel-sg108-staging-*` are listed (`FindFirstFileW` with that pattern), so a crowded temp directory cannot use up the bound before them.
  - **Tested:** with a pid no process can have (`0xFFFF_FFFC`; spawning a process is reserved to `worker_launch_tests.rs`), plus a live host's folder, an unrelated folder, such a junction, and more than 4,096 entries sorting before the prefix. The judge verified separately that a really exited pid, with or without its handle still held, counts as not running.
- **Known limits.**
  - A leftover temporary file for a destination that is never committed again stays until the user removes it; it is in Orcel's own hidden `.orcel-dl-*.part` namespace.
  - A dead host's pid reused by an unrelated live process keeps that host's staging folder until the pid is free again.
  - Ephemeral browser profiles left by a host crash are handled by #298 (section below).
  - The temporary name folds case with Rust's Unicode lowercasing, not NTFS's upcase table. Two names NTFS keeps distinct but that fold together (the Kelvin sign and `k`) share a temporary name. One commit is then refused while the other runs, and the approved names stay protected by the no-replace rename.

**#324: browser-process services that reach the network outside the policy layers.**

- **Finding.** Found while qualifying A8 (#323), then reproduced against the production confinement. Edge 155, launched with exactly the production argv and a profile seeded as the host seeds it, reached the network outside the resolver, no-route and policy layers. Each connection was observed with the OS's connection tables over its process tree:
  - the browser process opened a TLS connection to a Microsoft 365 address (`2603:1046:…:443`), with Edge's `identity_helper.exe` started: the account integration with the Windows account;
  - the network service opened a TCP connection to a Cast device on the LAN (`192.168.x.x:8009`);
  - the browser process bound mDNS (UDP 5353), and so did WebRTC's own mDNS responder (`WebRtcHideLocalIpsWithMdns`) once a page created an `RTCPeerConnection`. The responder listens on all interfaces and answers LAN queries.

  None of these goes through Chromium's proxied page networking. They are raw sockets to IP literals, or browser-process services, so `--host-resolver-rules` and the no-route proxy never apply to them.
- **Argv amendment (authority delta, narrowing).** The confinement argv gains one flag, `--disable-features=MediaRouter,DialMediaRouteProvider,CastMediaRouteProvider,msImplicitSignin,msEdgeOSAccountInfoSubstrate,msEdgeOnlineAccounts,msOneAuthWAM,msLoadOneAuthInBackground,msIdentityCore,WebRtcHideLocalIpsWithMdns`:
  - **What it disables:** Chromium's Media Router (Cast and DIAL discovery, which also does mDNS) and Edge's account integration (implicit sign-in, OneAuth/WAM, the Microsoft 365 "Substrate" account info, online accounts) and WebRTC's mDNS responder. A headless automation browser needs none of these. With the responder off, WebRTC exposes no candidate a peer could use: `disable_non_proxied_udp` already sends no UDP that is not proxied.
  - **How it was chosen:** each name was found in the installed `msedge.dll`. The set was narrowed by experiment, since Media Router plus `msImplicitSignin` alone, or plus `msEdgeOSAccountInfoSubstrate` alone, still reached Microsoft 365.
  - **Where it is enforced:** the host builder (`confinement.rs`) applies it, and the worker's exact-argv contract requires it (`DISABLE_FEATURES`). The OS command-line verification covers it.
  - **Not a boundary itself:** a feature list is not a boundary. The boundary is that the job holds no endpoint but loopback, which the next item verifies at the OS level.
- **Evidence (Windows, Edge 155), from two native tests that read the OS's TCP and UDP tables** (`GetExtendedTcpTable` / `GetExtendedUdpTable`, IPv4 and IPv6, by owning process):
  - **`a_confined_lifetime_holds_no_network_endpoint_but_loopback`:** a real lifetime, with every process in the worker's job (browser, every helper, `identity_helper` included), navigates to the loopback fixture and is polled every 500 ms for 90 s. It found no endpoint that is not loopback, and the fixture stayed reachable through the admitted path. The test fails on any such endpoint.
  - **`a_page_cannot_reach_the_lan_through_webrtc_fetch_or_sockets`:** an admitted fixture page tries, every 5 s for 60 s, WebRTC ICE (STUN over UDP, TURN over TCP), `fetch`, WebSocket and `sendBeacon` toward this host's own LAN address. The last three use `https://` and `wss://`, because the secure page's mixed-content blocking would stop `http` and `ws` in the renderer before any network layer is tested. The test listens there on UDP and TCP, and first proves the listeners reachable at that address by sending a datagram and opening a connection to them itself, so a firewall drop cannot make the result vacuous. This is enforcement evidence on the receiving side, not a browser log: nothing arrived. The OS tables, read with ports, showed no TCP connection, no listener and no UDP 5353 endpoint of the job beyond loopback. WebRTC still binds ephemeral UDP sockets on the LAN interface for ICE gathering. The test counts them (each address and port once), and requires at least one, which shows the page's WebRTC code ran. The listener shows they send nothing to the address the page targeted. A judge run with listeners on the LAN address, `127.0.0.1` and `::1` saw nothing either, while a raw Edge on the same page sent to all of them. Sends to arbitrary internet addresses would need packet capture, which needs administrator rights and is not done here. On a host with no non-loopback interface, the test reports that it skipped.
  - **`the_endpoint_scan_detects_an_unconfined_engine`, the negative control:** the same scan over an Edge started with the production argv minus the disabled features found the leak. It saw the LAN Cast connection, the Microsoft 365 connection and the UDP endpoints. With `ORCEL_SG108_EXPECT_LEAK=1`, it must see a UDP endpoint and an outbound TCP connection to port 443 or 8009 whose remote address is none of this host's own addresses in either family. The variable is set per run by whoever runs the suite on a host known to leak; the host and the suite never set it.
  - **The tests catch what they claim (mutation runs):**
    - with `WebRtcHideLocalIpsWithMdns` removed from the flag, the page test fails, naming `0.0.0.0:5353` and `[::]:5353`;
    - with the scanner reading the local address fields as the remote ones, the control fails, because the "leak" it sees is only this host's own addresses.
  - The native suite passes 25/25 on this host with the control required.
- **Known limits.**
  - **Edge versions:** feature names are Edge's own and may change between versions. The OS-level test is what fails if a new service reaches out, and release qualification re-runs it on the installed engine.
  - **The control is host-dependent:** it finds a leak only on a host that has something to leak to (a Microsoft account, LAN devices). Elsewhere it reports its result without requiring a leak.
  - **Duration:** the 90 s window covers start-up and an idle page, not every possible long-running service.
  - **Polling:** the tables are read every 500 ms, so a connection opened and closed between two reads can be missed. The scan counts outbound connections, non-loopback listeners and non-loopback UDP endpoints. It shows what the OS holds at each read, not every packet.
  - **Blind spots of the tables:** a connection in TIME_WAIT is owned by pid 0 and is not attributed to the job. A TCP socket that is bound but neither listening nor connected is not in these tables at all (one was seen with `Get-NetTCPConnection`: `0.0.0.0` in the network service, sending nothing). Traffic that Edge delegates to a Windows service (for example the Windows account broker, or DNS through the system resolver service) is owned by that service, not by the job. The 5353 and LAN-listener checks cover the services this finding saw; they do not prove that no system service acts on the browser's behalf.
  - **Scope of the claim:** these tests show that the confined lifetime opened no non-loopback TCP connection or listener and sent nothing to the LAN address under test, during the windows measured. They are not a firewall. An OS-level egress boundary (a Windows Filtering Platform filter or an AppContainer) would need system configuration, which this grain does not make.

**#298: ephemeral profiles of a host that died.**

- **Ownership is provable from the name.** `ephemeral_profile_dir(root)` names a new profile `orcel-sg108-profile-<owning host pid>-<16 random hex>` under `root`, a directory the caller owns. The random part comes from the system RNG. The helper creates the directory new: an existing one of that name is an error, never reused.
- **Sweep at launch.** A launch with `ephemeral_profile: true` whose profile carries this host's own pid in such a name sweeps that profile's root first. The sweep is #309's (`leftovers.rs`), now generalized over a name prefix:
  - it lists only names with the profile prefix (`FindFirstFileW`), at most 4,096;
  - it removes a profile only when the owning pid is certainly gone, and a process that cannot be queried counts as running;
  - it never touches this host's own pid;
  - it never follows a reparse point: one named like a profile is left alone, and links inside a dead profile are removed as links, their targets untouched; it also ignores a file named like a profile;
  - it removes at most 64 per launch;
  - a profile it cannot remove yet, such as one with a file still held, is left for a later launch and is not counted.
- **Who may call it.** The host that launches the profile must create it: the name records the creator's pid, so a profile handed to another process would become sweepable once its creator exits. The root must be absolute (a relative one is never swept), and pid 0 is never taken as an owner.
- **Scope.** Profiles not named this way are never looked at: a caller's persistent profile, a fixed test profile, or an unrelated folder in the same root. A root is swept only once a caller has chosen it for such profiles, by launching one there. There is still no product caller of `launch_worker`; the product caller adopts the helper when it lands.
- **Reporting.** `BrowserWorker::swept_profiles()` returns how many profiles this launch removed, as `swept_staging()` does for #309.
- **Evidence.**
  - **Unit test:** `only_profiles_of_hosts_that_are_gone_are_removed` sets up a dead owner's profile with `Default/Preferences`, which is removed and counted. These are left alone:
    - a live owner's profile;
    - a dead owner's folder with the staging prefix (each sweep keeps to its own prefix);
    - a persistent profile;
    - a junction named like a profile, whose target keeps its file;
    - a file named like a profile.

    A second sweep finds nothing. Name parsing is strict for both prefixes.
  - **Native test:** `killing_the_host_process_takes_the_worker_and_engine_down` covers the real crash path.
    - The child host makes its profile with `ephemeral_profile_dir` and launches it as ephemeral.
    - After the hard kill, the dead host's profile is still on disk.
    - The next ephemeral launch in the same root removes it and reports `swept_profiles() == 1`.
    - The test allows up to three launches, because a file the dead engine held for a moment can delay removal by one launch.
    - **Mutation run:** with the launch-time sweep replaced by `0`, the test fails: "the dead host's profile stayed", `swept_profiles() == 0`.
- **Known limits.**
  - A dead host's pid that an unrelated live process reuses keeps that host's profile until the pid is free again, as with #309's staging folders.
  - A root that no later launch uses is never swept.
  - The sweep runs during launch, so removing many dead profiles (at most 64) adds launch latency. The listing stops at 4,096 prefix-matched names, so dead profiles listed after that many live or still-held ones wait for a later launch.

**A10: the supported engine window.**

- **Decision (narrowing).** The live worker runs only on an engine whose kind and major version are in `QUALIFIED_WORKER_ENGINES` (`discovery.rs`).
  - **When it is checked:** at every launch, before anything is spawned. `validate_launch` first re-verifies the engine file (`Engine::reverify`), exactly as discovery did: name, presence, version resource and Authenticode. It requires the same kind and version. So an engine updated or replaced in place since discovery (Edge and Chrome update by replacing their executable) is refused.
  - **The gap that remains:** the engine starts a moment later, when the worker launches it after the handshake, so a short window between check and use remains. Replacing the file inside it requires writing into the engine's install folder, which is already past the boundary.
  - **Platforms:** on Windows nothing is spawned for the check. Elsewhere, the re-check runs the engine's `--version` (bounded), and the worker is Windows-only.
  - **Recovery:** a caller refused after an update must discover the engine again (`discover_engine`), which reads the new version and applies the window to it. Anything else is refused with the typed `Unavailable(UnsupportedEngine)`: another major of either kind, or an unparseable version. Today four engines are qualified:
  - **Edge 155:** the evidence host, Edge 155.0.4283.45. The full native suite passed with the #324 leak control required (#325, #326).
  - **Chrome 154:** CI's windows-latest runner (image 20260925.250.1), Chrome 154.0.8037.58, which the native suite now reports (`SG108-EVIDENCE engine: …`).
    - The full suite passed there on this PR's head, the #324 endpoint tests included. The page probe saw 36 ICE sockets, so the WebRTC probe ran, and the leak control saw mDNS sockets on 5353.
    - The leak control is not required there, because the runner has no account and no LAN devices for an outbound connection.
  - **Chrome 155:** a later windows-latest image, added with its CI native-suite run in #337 (commit 48c10ae).
  - **Chrome 156:** windows-latest image 20261021, Chromium 156.0.8078.48, added by #431. Its CI native-suite run on that engine is the qualification evidence and must pass before merge; the run is recorded on #431.
- **Why a list of qualified majors, not a range.** The engine-drift risk above means a new engine can change how it honours a confinement flag. The leaks #324 found came from services that only some engine builds start. So "supported" means that every probe re-ran on that version, not that playwright-core can attach. A range would admit versions no probe has run on.
- **What it is checked with.**
  - **Discovery, unchanged:** the engine's kind, path and Authenticode publisher are verified as before (SG-000074).
  - **The window, at launch.** Unit tests:
    - `only_qualified_engine_versions_run_the_worker`;
    - `an_unqualified_engine_version_is_refused_before_anything_runs`: with every other prerequisite present, Edge 154, Edge 156, Chrome 157 and Chrome 153 are refused with the typed error, and Edge 155 passes the rule. The first test also asserts that Chromium 156.0.8078.48 is qualified while Edge 156 stays refused: each kind has its own majors.
  - **Native:** every native test runs under the window on the installed engine, which the suite reports once per run.
  - **`an_engine_replaced_after_discovery_is_refused_at_launch`:**
    - a held, qualified engine (a copy of the installed Edge) passes `validate_launch`;
    - once its file is replaced with another signed Windows binary of another version, the launch is refused with `UnsupportedEngine`;
    - with the re-verification removed, the test fails: the replaced file passed (mutation run).
- **What the signature check means.** `WinVerifyTrust` accepts any trusted signer; the publisher is not pinned, and this predates A10. So "Chrome 154" means a validly signed `chrome.exe` whose version resource says 154. The version cannot be spoofed without signing a binary.
- **Order of refusals.** On an unqualified engine, `UnsupportedEngine` comes before the managed-policy and runtime refusals. Until requalification, those two native tests fail with it instead of testing their own refusal. This is fail-closed, and it is the CI signal below.
- **Discovery does not prefer a qualified engine.** It returns the first verified candidate. On a host with an unqualified Edge and a qualified Chrome, launch refuses Edge rather than falling back. This is safe, at a cost to availability.
- **Qualifying a new version.**
  1. Open a PR that adds the major to `QUALIFIED_WORKER_ENGINES`.
  2. Its own native-suite run on that engine is the evidence: CI's run for the runner's engine, and a run on the evidence host for Edge, with `ORCEL_SG108_EXPECT_LEAK=1` on a host with something to leak to.
  3. Until that PR merges, the worker is unavailable on that engine, with a typed reason, and never runs unqualified.
- **Known cost.** Edge and Chrome update themselves about every four weeks, and so does CI's runner image. When the runner's Chrome moves to a new major, CI's native suite fails with `UnsupportedEngine` until a qualifying PR merges. This is intended: a typed refusal, never an unproven launch. On an updated user host, the worker becomes unavailable until requalification; there is no product caller yet. The release process must schedule requalification.
