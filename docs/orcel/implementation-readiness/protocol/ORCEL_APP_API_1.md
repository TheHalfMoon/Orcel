# orcel-app-api/1

Status: implemented in CR-01 (read-only slice), with the #375 and #381 follow-ups. Code: `crates/orceld/src/app_api.rs`. Tests: `crates/orceld/src/app_api/tests.rs`.

`orcel-app-api/1` is the local, per-user, read-only interface through which the Control Room and other local clients of the same user read `orceld` state. `orceld` remains the only authority. Nothing in this protocol submits work, changes state, or answers, mints or forwards an approval. Approvals stay with the OS presence surfaces (XP-09, XP-10); the UI only displays what is waiting.

## 1. Endpoint

| OS | Endpoint | Access control |
|---|---|---|
| Windows | named pipe `\\.\pipe\orcel-<user SID>-app` | protected DACL `D:P(A;;GA;;;<user SID>)`: the current user only, nothing inherited, no Everyone, Authenticated Users, Users, Administrators or SYSTEM entry. An explicit mandatory label `S:(ML;;NWNR;;;ME)` (#375 item 2), so a Low-integrity process of the same user cannot open the pipe for reading or for writing. `FILE_FLAG_FIRST_PIPE_INSTANCE`, so the daemon never joins a pipe another server created first. `PIPE_REJECT_REMOTE_CLIENTS`. |
| macOS | Unix socket `<DARWIN_USER_TEMP_DIR>/orcel/app-api.sock`, in the per-user `/var/folders/<xx>/<id>/T/` that `confstr(_CS_DARWIN_USER_TEMP_DIR)` names (never `TMPDIR`). If the system names none: `<state root>/run/app-api.sock`, state root `$HOME/Library/Application Support/Orcel` | socket mode 0600 inside a directory that `orcel_platform::paths::ensure_private_dir` (XP-01) holds at 0700, owned by the user, not a symlink, with no ancestor another user can modify; a lock file beside it (see below) |
| Linux | Unix socket `$XDG_RUNTIME_DIR/orcel/app-api.sock` when `XDG_RUNTIME_DIR` is an absolute path (normally `/run/user/<uid>`, the directory XP-17's `orceld.socket` uses too). Otherwise `<state root>/run/app-api.sock`, state root `$XDG_STATE_HOME/orcel` or `$HOME/.local/state/orcel` | as macOS |

- No TCP or UDP listener exists, loopback included.
- `ORCEL_APP_API_INSTANCE=<suffix>` (1-32 of `a-z`, `0-9`, `-`) appends `-<suffix>` to the pipe name or socket file name, for tests and side-by-side installs.
- `ORCEL_APP_API=off` disables the endpoint (rollback). A missing state root, an unsafe location, or a name another live server holds never stops `orceld`: the reason goes to stderr and the request loop runs unchanged.
- One `orceld` holds the endpoint at a time. A second instance (for example a one-shot `orcel` CLI call, or another per-connection instance of XP-17's `orceld.socket`) finds it held and retries every 5 seconds, so a long-lived daemon takes it over once the other exits.
- **A held endpoint is visible (#375 item 1).** The first time an `orceld` finds the endpoint held, it writes one stderr line, `orceld app api: waiting for <endpoint>: <reason>; retrying every 5 s`, and publishes an `app_api.endpoint_in_use` event. Later attempts only count. Once it takes the endpoint, its `status.get` reports the wait in `endpoint_wait`. On Windows the reason names the holder: the server process of the existing pipe, and whether it runs as this account (another `orceld`) or as another account (a squatted name). It reads these by opening the pipe as an identification-only client.
- **Short socket path (#381).** A Unix socket address holds about 100 bytes: `sun_path` is 104 bytes on macOS and 108 on Linux, NUL included. A path below a long home does not fit. So the socket lives in the short per-user runtime directory whenever the OS has one, whatever `HOME` is. `orceld` and the client derive the location the same way:
  - macOS: from `confstr(_CS_DARWIN_USER_TEMP_DIR)`. The client runs `/usr/bin/getconf DARWIN_USER_TEMP_DIR`.
  - Linux: from `XDG_RUNTIME_DIR`. A value that is not absolute, or that has `.` or `..` components, is ignored.

  The directory is created and checked through XP-01's `ensure_private_dir`. There is no `chdir` and no relative bind. The CR-01 state-root location applies only when there is no runtime directory. There, a path over 100 bytes is still refused, never truncated: stderr gets one line with the length and the fix.
- The backlog card placed the Linux socket in `$XDG_RUNTIME_DIR/orcel`. CR-01 moved it to the XP-01 state root, and #381 moved it back, under the same ownership and mode checks.

### Single instance (Unix, #375 item 3)

Before `orceld` inspects, removes or binds the socket, it takes an exclusive advisory lock on `app-api<suffix>.lock` in the same private directory (`flock`, non-blocking). It holds the lock for as long as it serves the socket.

- A second `orceld` that finds the lock held is told "another orceld of this user holds the lock" and leaves the socket alone. Two instances that both see a stale socket therefore can never unlink each other's live one.
- The lock belongs to the open file, so the kernel releases it however the holder exits.
- The lock file itself is never removed. Unlinking a lock file would let two processes lock two different inodes.
- A lock path that is not this user's regular file is refused and left in place.
- On exit, the holder removes its socket (with the dev/inode check below) before it releases the lock.

On Windows, `FILE_FLAG_FIRST_PIPE_INSTANCE` already admits one server per name. The server always keeps a listening instance, so the name is never free between clients.

### Stale sockets (Unix)

Before binding, the socket path is inspected without following links:

| Found | Action |
|---|---|
| nothing | bind |
| a symbolic link | refuse; the link is left in place |
| anything but a socket | refuse; it is left in place |
| a socket owned by another uid | refuse; it is left in place |
| a socket of this user that a live server answers on | do not bind; retry later |
| a socket of this user that nothing answers on | remove it, then bind |

All of this runs under the lock. The parent directory is private (0700, this user), so no other user can swap the entry between the check and the removal. The live-server probe stays: a server that does not take the lock keeps its socket. After binding, the socket is set to 0600 and checked again. On a clean exit `orceld` removes the socket only if the path still names the inode it bound.

## 2. Peer admission

Every accepted connection is identified from the kernel before any byte is read from it. A refused peer is dropped without a read or a write, and the reason goes to stderr.

- **macOS and Linux.** `orcel_platform::peer::unix_peer_credentials` (XP-03) reads the peer's uid and binds it to its process instance (pid and start generation). The uid must equal `orceld`'s effective uid.
  - Linux: the identity must come from `SO_PEERPIDFD` (`source = "linux-so-peerpidfd"`, Linux 6.5+). The `linux-so-peercred` fallback of older kernels can mistake a pid-reusing process for the peer, so it is refused (#367 item 2). On such kernels the app API admits no client.
  - macOS: `LOCAL_PEERTOKEN` audit token, cross-checked with `getpeereid` and the pid version.
- **Windows.** The pipe client's pid (`GetNamedPipeClientProcessId`) must be non-zero. The client's session (`GetNamedPipeClientSessionId`) must equal `orceld`'s. Its token user must equal `orceld`'s (`EqualSid`), which checks a second time what the DACL already enforces. Its start generation is read (`orcel_platform::process::start_generation`). The pipe must still be connected after these reads: while the client's handle is open, its pid cannot have been reused.
- **Gone peers (#367 item 1).** `PlatformError::ProcessGone`, including the pid-0 sentinel, means "refuse this connection" and nothing else. The app API never cleans up, revokes or records anything about a process because of it.
- **Binding.** The connection keeps the instance it was admitted as. Before each request the instance is read again, and if the peer has exited or its pid now names another process, the connection is closed without an answer. A subscription reads no more requests, so while it streams the instance is read again at least once a second and before every heartbeat (#375 item 5). If it changed, the stream ends without a snapshot.
- **Unreadable peers (#375 item 6).** On Windows, if `OpenProcess` fails on the client pid, the connection is refused whatever the cause, and the logged reason names the cause. Only `ERROR_INVALID_PARAMETER` (no such process) counts as gone. `ERROR_ACCESS_DENIED` and other errors count as an unavailable identity.

**Trust level.** Any live process of the same user, in the same session on Windows, is admitted. The protocol is read-only, so the user's own processes may read daemon status. A process of another user cannot reach the endpoint: the Unix directory refuses it with EACCES before the socket is reachable, and the Windows DACL refuses it at open.

**Code identity.** The backlog card also proposed importing Cua's code-signature checks: a macOS SecCode requirement and a Windows Authenticode publisher. Those checks are not in this read-only slice, for two reasons. First, development and CI builds of the Control Room are unsigned, so a signer requirement would refuse them. Second, on Linux, same-user ptrace makes binary identity unprovable anyway (S-27). The first method that changes state or carries authority must add a first-party code requirement before it ships.

## 3. Framing

- UTF-8 JSON, one object per line, terminated by `\n` (a preceding `\r` is ignored).
- At most **65,536 bytes per frame, newline included**, in both directions. An over-long frame gets an error frame with code `FRAME_TOO_LARGE`, and then the connection is closed. The server never buffers more than one frame of unread input.
- Every frame carries `"v": "orcel-app-api/1"`.

Request:

```json
{"v":"orcel-app-api/1","id":"r1","method":"status.get","params":{}}
```

- `id`: a number, a string of at most 128 characters, or absent or null. It is echoed back.
- `params`: an object, or absent or null.

Response:

```json
{"v":"orcel-app-api/1","id":"r1","ok":true,"result":{}}
{"v":"orcel-app-api/1","id":"r1","ok":false,"error":{"code":"UNKNOWN_METHOD","message":"..."}}
```

A connection may carry any number of requests, one at a time, until it subscribes. A connection idle for 60 seconds is closed.

## 4. Methods

| Method | Params | Result |
|---|---|---|
| `status.get` | none | `name`, `version`, `app_api`, `read_only: true`, `internal_protocol_version`, `os`, `arch`, `pid`, `mode`, `policy_revision`, `started_at_ms`, `uptime_ms`, `endpoint`, `endpoint_wait` (null, or `{since_ms, reason, attempts}` when this daemon found the endpoint held before taking it), `events {epoch, head_seq, oldest_seq, ring_capacity}`, `clients {active, max}`, and `peer {pid, source}` as the server identified the caller |
| `capabilities.get` | none | `os`, `read_only: true`, `methods`, `reserved_methods`, `capabilities: [{id, state: "available" \| "unavailable", reason}]` |
| `events.subscribe` | `after_seq` (integer ≥ 0, default 0), `epoch` (string; required when `after_seq` > 0, #375 item 4) | see section 5 |

The capability rows report what this build of `orceld` can serve on this OS. Rows for providers that are Windows-only in this build carry their reason. `approval.presence` reflects whether the broker found a platform presence surface at startup. Readiness beyond that is checked per request on the existing kernel path.

Reserved read-only methods `devices.list`, `task.get` and `task.list` answer `METHOD_UNAVAILABLE` in this revision. Every other name answers `UNKNOWN_METHOD`, including anything that would submit, approve, mint, stop or write.

Error codes: `INVALID_REQUEST`, `UNSUPPORTED_VERSION`, `UNKNOWN_METHOD`, `METHOD_UNAVAILABLE`, `FRAME_TOO_LARGE`, `BUSY`, `INTERNAL`.

## 5. Events

`orceld` publishes events into a bounded ring of 1,024 events. Each event has a sequence number `seq`, which grows by one per event within an `epoch`. The epoch names one daemon run, so `seq` restarts at 1 after a restart.

```json
{"seq":42,"epoch":"1a2b-17f...","run_id":null,"step_id":null,"kind":"request.completed","at_ms":1760000000000,"data":{}}
```

Kinds in this revision:

- `daemon.started` carries `{pid, mode}`.
- `request.completed` carries `{request_id, capability, operation, ok, failure_code}`. It records the shape and outcome of each request on `orceld`'s stdio channel, never its arguments or result.
- `app_api.endpoint_in_use` carries `{reason}`. This daemon found the endpoint held before it took it (section 1).
- `snapshot` is described below.

`data` larger than 16 KiB is replaced by `{"truncated": true, "bytes": n}`. `run_id` and `step_id` are reserved for the task journal (RJ-01) and are null for now.

**Subscribing.** A cursor names a position in one daemon run. So when `after_seq` > 0, the request must carry the `epoch` that cursor belongs to. Without it the request is refused with `INVALID_REQUEST`, and the connection stays open (#375 item 4). A subscription from the start (`after_seq: 0`) may omit it. After `events.subscribe`, the server first answers `{"ok":true,"result":{"epoch","head_seq","after_seq"}}`. It then streams, with the request's `id`:

- `{"v","id","event":{...}}` for every event with `seq > after_seq`, in order;
- `{"v","id","heartbeat":{"head_seq"}}` after 15 seconds without events.

From then on the connection only streams; client input is no longer read.

**Snapshot and resubscribe.** The server sends one `snapshot` event and then closes the connection when any of these holds:

- `after_seq` is older than the ring's oldest event (`reason: "gap"`);
- `after_seq` is ahead of this epoch's head (`reason: "gap"`);
- `epoch` is given and differs from the current one, for example after a daemon restart (`reason: "epoch"`);
- the subscriber falls behind while streaming (`reason: "gap"`).

The snapshot's `data` holds `reason`, `head_seq`, `oldest_seq`, a `status` object (as `status.get`, without `peer`) and `resubscribe: {after_seq, epoch}`. The client refreshes its view from the snapshot and status, then subscribes again with `resubscribe`. Silent gaps are not possible: either every event after the cursor arrives in order, or a snapshot says the cursor cannot be served.

## 6. Bounds and backpressure

| Bound | Value |
|---|---|
| frame | 65,536 bytes |
| concurrent clients | 8; the next one gets a `BUSY` error frame and is closed |
| event ring | 1,024 events, shared by all subscribers |
| events per subscriber | 1,000 per second |
| write timeout | 5 s; a client that does not read is disconnected |
| idle request connection | 60 s |

Publishing never waits for a client. It holds the ring lock only to append. Each subscriber reads the ring at its own cursor on its own thread. A slow subscriber's cursor falls behind the ring and gets a snapshot, or it hits the write timeout and is dropped. Neither the request loop nor other clients wait for it.

## 7. Client obligations

- On Windows, open the pipe with `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION`, so the server can identify the client but never act as it. The pipe name is predictable and the pipe namespace is shared, so a client that acts on what it reads should confirm that the server process runs as its own user (`GetNamedPipeServerProcessId`, then compare token users). On Unix the private directory already guarantees this.
- Never treat any field as an approval or authorization. A Control Room shows "waiting for approval on this device" and leaves the decision to the OS dialog.

## 8. Tests

`cargo test -p orceld app_api` runs on Windows, macOS and Linux in CI:

- **Contract over the OS transport.** Status, capabilities and refused methods round-trip. A frame at exactly 64 KiB is served and a larger one is refused. A subscription resumes from a cursor. A gap gets a snapshot, and so does a restart (another epoch, or a cursor past the head). A slow client is dropped while 20,000 events are published without waiting. A client over the limit gets `BUSY`.
- **Peer admission.** A peer that has exited before admission is refused: a re-executed helper process connects and exits. Other-uid, other-session, other-account, pid 0, `ProcessGone` and `linux-so-peercred` peers are refused through synthetic seams. Creating a real peer of another uid needs root.
- **Short location (#381).** These tests use a `HOME`, and on Linux an `XDG_STATE_HOME`, longer than a socket address. The location still comes from the runtime directory:
  - synthetic resolution cases;
  - a real bind, serve and removal at the production location on macOS (`confstr`) and Linux (`XDG_RUNTIME_DIR`);
  - the CR-02 suite, which starts the real `orceld` with a 120-byte home on both OSes and connects.
- **Single instance (#375 item 3).**
  - Six threads race, 40 times, to replace one stale socket. Exactly one binds, and the socket left is the winner's and answers. A late contender changes nothing. With the lock disabled, this test fails.
  - A second process (the test binary, re-executed) is told the endpoint is in use, and the live socket keeps its inode.
  - On every OS, the CR-02 suite starts a second real `orceld` for the same endpoint. It logs its reason once, and the first keeps serving across its retries. Once the first exits, the second takes over and reports `endpoint_wait`.
- **Unix location.** A symlinked socket path, a non-socket file, a directory others can reach, and a socket owned by another user (synthetic seam) are each refused and left in place. A stale socket of ours is replaced. A live socket is kept. The socket mode is 0600 and the directory mode is 0700.
- **Windows pipe.**
  - The pipe's DACL, read back with `GetSecurityInfo`, is protected and has exactly one ACE, for the current user's SID.
  - Its label, read back the same way, is the single ACE `(ML;;NWNR;;;ME)`.
  - A thread impersonating a Low-integrity copy of the test process's own token cannot open the pipe for reading, writing or both (`ERROR_ACCESS_DENIED`). The same opens from the process's own token succeed. This runs on the hosted runners.
  - A second server cannot take the name, and its reason names the holder as this account.
- **Endpoint wait, stream re-check, epoch.**
  - The first held attempt is noted once, and `endpoint_wait` reports it.
  - A subscription whose peer's start generation no longer matches ends at its first idle wake-up, without a heartbeat.
  - A cursor without its epoch gets `INVALID_REQUEST`.
  - `OpenProcess` failures map as in section 2.
- **Another user.** On the Linux and macOS CI legs, `ORCEL_APP_API_OTHER_USER_TEST=1` runs a connect as `nobody` through `sudo`. It must fail with EACCES, and the server must see no connection.

## 9. Reference client (CR-02)

`apps/orcel-control-room` is the headless Control Room client. Its protocol layer, client and conformance suite are adapted from Agent-Native AgentKit (`docs/orcel/control_room_agentkit_provenance.json`). It renders nothing, and the UI is CR-03.

- It sends only `status.get`, `capabilities.get` and `events.subscribe`, and refuses every other method name before writing.
- Every `events.subscribe` it sends carries `epoch`, so a cursor from an earlier daemon run always gets an `epoch` snapshot rather than the new run's events (#375 item 4). The server requires `epoch` when `after_seq` > 0, and the conformance suite checks that.
- It rejects any frame field this section does not define, and it rejects a sequence gap before advancing its cursor (AgentKit invariant 22).
- It finds the endpoint as section 1 describes (#381). On Unix, before connecting, it refuses an endpoint whose directory or socket is not this user's, or whose path is over 100 bytes.
- On Windows it refuses to connect by default: libuv cannot request `SECURITY_IDENTIFICATION` or read the server's account (section 7), so a pipe another account created first cannot be told apart. Only tests opt in, and the code enforces that (#381 item 2): `allowUnverifiedWindowsPipe` is refused unless `ORCEL_CONTROL_ROOM_UNVERIFIED_PIPE_TEST=1`, which only the package's `npm test` sets (`node --env-file=test.env`). The CR-03 Tauri bridge must open the pipe from Rust with `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION` and compare the token user of `GetNamedPipeServerProcessId` with its own.
- **Line queue (#381 item 3).** A consumer that lags never makes the client queue more than 256 frames. Bytes are decoded one line at a time, only while there is room. The socket stays paused while read bytes wait undecoded, and resumes once they are decoded and the queue is down to 64.
- `npm --prefix apps/orcel-control-room test` runs its contract tests and the conformance suite against the real `orceld` on all three OSes in CI.
