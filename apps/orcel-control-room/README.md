# @orcel/control-room (headless)

CR-02: the Control Room's protocol layer and headless client for orceld's
local app API, [`orcel-app-api/1`](../../docs/orcel/implementation-readiness/protocol/ORCEL_APP_API_1.md)
(CR-01). It renders nothing. The UI shell (CR-03, Tauri 2) waits on founder
decision FD-03, so this package makes no UI framework choice.

## What it does

- **Reads only.** The client can send `status.get`, `capabilities.get` and
  `events.subscribe` and nothing else. `encodeRequest` refuses any other
  method name before a byte is written. Although orceld serves SG-000126
  `task.list` and `task.get`, neither is authorized for this client; tests
  prove both are refused even when advertised. There is no approval, submit, cancel
  or stop path, no MCP server and no listener. `no-authority.test.ts` checks
  the shipped sources and build for each of these.
- **Connects only to this user's endpoint.** On Windows that is the pipe
  `\\.\pipe\orcel-<user SID>-app`, whose DACL admits this user only. On
  macOS and Linux it is `orcel/app-api.sock` in the user's short runtime
  directory (macOS `getconf DARWIN_USER_TEMP_DIR`, Linux `$XDG_RUNTIME_DIR`),
  or `<state root>/run/app-api.sock` without one, exactly as orceld derives
  it (#381). Before connecting on Unix, the client checks without following
  links that the socket's directory is this uid's with no group or other
  access, and that the socket is a socket owned by this uid.
- **Follows events with epoch-aware cursors.** Every `events.subscribe`
  carries the epoch its cursor belongs to (#375 item 4). Events must be
  contiguous within the epoch. A gap is reported and rejected before the
  cursor moves, a duplicate is reported and dropped, and an event of
  another epoch ends the stream. A `snapshot` from orceld, for a gap or a
  new epoch, replaces the status and cursor. A new epoch also clears the
  timeline. The client then resubscribes from the snapshot's cursor.
  Resubscribing never re-sends or re-dispatches anything.
- **Reconnects** with capped exponential backoff after the daemon exits or
  answers `BUSY`. It stops with an error only on `UNSUPPORTED_VERSION`.

## Windows: refused by default

The pipe namespace is shared, so another account can create
`\\.\pipe\orcel-<SID>-app` before orceld does. Node's libuv opens pipes
without `SECURITY_SQOS_PRESENT` (the server could impersonate the client) and
cannot read the server's process or token, so this connector cannot verify
the server as ORCEL_APP_API_1.md section 7 requires. It therefore **refuses
to connect on Windows**, and it has no option to do otherwise (#398 item 4).
The tests start the daemon themselves and connect through
`src/tests/unverified-pipe.ts`. The production build (`npm run build`,
`tsconfig.build.json`) excludes `src/tests/` and every `*.test.ts`, so that
connector is never compiled into it. The Windows Control Room transport is the CR-03 Tauri
bridge, which must open the pipe from Rust with
`SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION` and require the token user
of `GetNamedPipeServerProcessId` to equal its own.

## Unix: socket path limit

`sun_path` holds 104 bytes on macOS and 108 on Linux. The runtime directory
keeps the socket path short whatever `HOME` is, so a long home still gets
the app API (#381). Only on the state-root fallback can a path pass 100
bytes; orceld then refuses it with a reason on stderr (it never truncates or
waits), and the client refuses the same path before connecting and names
the fix.

## Backpressure

A consumer that lags never makes the client buffer without bound. The queue
holds at most 256 frames: bytes are decoded one line at a time while there
is room, the socket is paused while read bytes wait, and reading resumes
once they are decoded and the queue is down to 64 (#381 item 3).

## Provenance

The protocol, client and conformance files are adapted from Agent-Native
AgentKit (`BuilderIO/agent-native@9c277b79`, MIT). Each file's header names
its donor file and lists Orcel's changes, and
[`docs/orcel/control_room_agentkit_provenance.json`](../../docs/orcel/control_room_agentkit_provenance.json)
records the donor blobs. The notice is in
[`docs/orcel/notices/agent-native-MIT.txt`](../../docs/orcel/notices/agent-native-MIT.txt).
The transport (`src/agentkit/transport`) is Orcel code.

## Tests

```bash
cargo build -p orceld
npm ci --prefix apps/orcel-control-room --ignore-scripts
ORCEL_REQUIRE_LIVE_ORCELD=1 npm --prefix apps/orcel-control-room test
```

The contract tests (`client.contract.test.ts`) and the adapted conformance
suite (`conformance.test.ts`) run the real `orceld`. Each daemon gets its
own `ORCEL_APP_API_INSTANCE`, workspace, audit file and state root. Without
the binary these tests skip, unless `ORCEL_REQUIRE_LIVE_ORCELD=1` is set, in
which case they fail; CI sets it on Windows, macOS and Linux. Every daemon that fails to listen is
killed at once with orceld's reason, and the CI job has a 30-minute limit.
On Linux and
macOS, CI also sets `ORCEL_APP_API_OTHER_USER_TEST=1`, which makes `nobody`
try the connect and requires EACCES. Stream faults that orceld never
produces (a skipped sequence, a duplicate, an event of another epoch, an
extra envelope field) are covered in `client.test.ts` with an in-memory
scripted server.
