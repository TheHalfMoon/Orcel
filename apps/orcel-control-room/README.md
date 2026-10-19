# @orcel/control-room (headless)

CR-02: the Control Room's protocol layer and headless client for orceld's
local app API, [`orcel-app-api/1`](../../docs/orcel/implementation-readiness/protocol/ORCEL_APP_API_1.md)
(CR-01). It renders nothing. The UI shell (CR-03, Tauri 2) waits on founder
decision FD-03, so this package makes no UI framework choice.

## What it does

- **Reads only.** The client can send `status.get`, `capabilities.get` and
  `events.subscribe` and nothing else. `encodeRequest` refuses any other
  method name before a byte is written. There is no approval, submit, cancel
  or stop path, no MCP server and no listener. `no-authority.test.ts` checks
  the shipped sources and build for each of these.
- **Connects only to this user's endpoint.** On Windows that is the pipe
  `\.\pipe\orcel-<user SID>-app`, whose DACL admits this user only. On
  macOS and Linux it is `<state root>/run/app-api.sock`. Before connecting
  on Unix, the client checks without following links that `run/` is this
  uid's directory with no group or other access, and that the socket is a
  socket owned by this uid.
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

## Windows limitation

Node's libuv opens named pipes without `SECURITY_SQOS_PRESENT`, so this
connector cannot make the identification-only open that
ORCEL_APP_API_1.md section 7 asks of clients, and it cannot confirm that the
pipe's server runs as this user. Until the CR-03 Tauri bridge does both in
Rust, this connector is for headless and test use.

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
which case they fail; CI sets it on Windows, macOS and Linux. On Linux and
macOS, CI also sets `ORCEL_APP_API_OTHER_USER_TEST=1`, which makes `nobody`
try the connect and requires EACCES. Stream faults that orceld never
produces (a skipped sequence, a duplicate, an event of another epoch, an
extra envelope field) are covered in `client.test.ts` with an in-memory
scripted server.
