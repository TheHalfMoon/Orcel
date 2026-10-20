# SG-000053 Device Identity, Pairing, and Revocation Note

Status: IMPLEMENTATION FOR ORCEL-P15
SpecGrain: SG-000053
Base: `1aa23642ff877bc8cb2243673c34142950c1f120`
Date: 2026-10-02
Companions:
- `docs/security/RELAY_PROTOCOL_CONTRACT.md` (SG-000052, frozen)
- `docs/security/REMOTE_SESSION_AUTHORIZATION.md`
- `docs/security/REMOTE_PRINCIPAL_AUTH_MODEL.md`
- `docs/security/UNIVERSAL_CONNECTIVITY_THREAT_MODEL.md`
- `apps/orcel-mcp/src/device_identity.ts`
- `apps/orcel-mcp/src/device-identity.test.ts`

## 1. Purpose

SG-000053 implements device identity, one-time pairing, key rotation,
connection epochs, revocation, challenge and response authentication, and
device-verifiable authorization envelope verification against the frozen
SG-000052 relay contract. No OAuth, no device uplink networking, no public
edge, no relay deployment, no new MCP tool, no schema change, no capability
widening, and no approval change is introduced here.

## 2. Protected local device key

- Each device route holds one Ed25519 key pair generated locally with
  `node:crypto` `generateKeyPairSync("ed25519")`.
- The device identifier is an opaque tenant-scoped route string of the
  form `dev-` plus 32 lowercase hex characters (128-bit route entropy).
- The public device identity (`deviceId`, public JWK, creation time,
  epoch) is the only key shape that may leave the device.
- The private device key never leaves the device. It is never returned
  by any tool, never written to logs, never included in evidence, and
  never transmitted. `publicDeviceIdentity` and `redactedDeviceSummary`
  provably exclude it.
- The protected store location is `device/device_key.json` relative to
  the Orcel state root under the existing SG-000041 protected-state
  boundary. The store file requires owner-only permissions. Workspace
  admission continues to refuse any workspace overlapping protected
  state, so workspace-scoped providers cannot reach the key.
- Since XP-19 that file holds only the public identity. The private key
  lives in the OS secret store behind `orceld` (`secret` capability, name
  `device.key`): DPAPI on Windows, the user keychain on macOS, and the
  Secret Service on Linux. With no store available the key is unavailable,
  never written in plaintext. `orcel remote migrate-secrets` moves a key that
  an earlier version left in the file into the store, then removes the
  plaintext (SECURITY_INTEGRATION S-23).
- The remote provider cannot create or replace device identity. Identity
  creation and rotation are local operations.

## 3. Challenge and response

- A challenge binds `deviceId`, epoch, a 256-bit random nonce, creation
  time, and a 120-second expiry matching the frozen frame lifetime.
- The device signs the canonical `deviceId|epoch|nonce|expiresAt` bytes
  with its private key. Verification uses the recorded public key.
- Verification fails closed with `ROUTE_MISMATCH` on device remap,
  `REMOTE_AUTH_INVALID` on epoch mismatch, expiry, forgery, or malformed
  encoding, and `RELAY_REPLAY_DETECTED` on nonce mismatch.
- Challenge material is authentication input only. It creates no lease,
  no trust, and no approval.

## 4. One-time pairing

- Each pairing code carries 256-bit entropy, encoded as 64 lowercase hex
  characters. Only the SHA-256 hash is stored. The plain code is shown
  once to the local user and never persisted.
- Each code expires after 300 seconds, is single-use, and allows at most
  5 verification attempts, matching
  `RELAY_BOUNDS.maxPairingAttemptsPerCode`. The sixth failure state and
  any post-expiry, post-consumption, or post-invalidation attempt fails
  closed with `PAIRING_EXPIRED` or `PAIRING_DENIED`.
- Comparison uses constant-time equality over decoded bytes. Attempt
  counters increment on every failure, including malformed input, so an
  attacker cannot probe without consuming the budget.
- Pairing alone grants no workspace trust, no tool profile, and no
  approval. `verifyPairingAttempt` returns only acceptance plus the
  updated record. There is no workspace, trust, or approval field in the
  result.

## 5. Key rotation and epochs

- The route epoch starts at 1 and increments by exactly one on every key
  rotation. The new key uses the new epoch. The prior private key must be
  discarded by the holder.
- Signatures from a prior epoch fail verification against the new epoch.
  Envelopes carrying a stale epoch fail with `REMOTE_AUTH_INVALID`.
- Route and connection epochs from SG-000052 remain the binding used by
  the envelope. This grain does not change the frozen frame contract.

## 6. Revocation

Four revocation shapes exist:

- `hard_device`: invalidates one exact device route.
- `principal_wide`: invalidates every route for one remote principal.
- `all_route`: invalidates every route on this device.
- `emergency`: immediate device-wide invalidation for emergency stop.

Any applicable revocation fails closed with `DEVICE_REVOKED`. Revocation
invalidates active dispatch and refreshable sessions, not only UI state.
There is no refresh path that survives revocation in this module, and no
relay, provider, or remote caller can clear a revocation. Recovery
requires a new local pairing and, where a lease exists, a new STRONG
gated lease under `REMOTE_SESSION_AUTHORIZATION.md`.

## 7. Device-verifiable authorization envelope

`verifyAuthorizationEnvelope` checks the six frozen bindings in order:

1. All six fields are present with the correct primitive types.
2. The presented principal, connection, and device exactly match the
   expected route. Any remap, including principal A onto device B, fails
   with `ROUTE_MISMATCH` before any further check.
3. The presented SHA-256 request digest exactly matches the expected
   digest with constant-time comparison. Mismatch fails with
   `REMOTE_AUTH_INVALID`.
4. The presented epoch exactly matches the expected route epoch.
5. The presented session context exactly matches the expected session.
6. The route is checked against the revocation set. Any hit fails with
   `DEVICE_REVOKED`.

Envelope verification runs before workspace policy, lease, profile, and
approval checks in the dispatch order. Any denial wins. The function
uses only the frozen 17-code failure vocabulary and introduces no new
code.

## 8. Privacy and logging

- Logs and evidence carry route and result classes only: device identity
  strings, epochs, pairing code identities, and failure classes.
- Private keys, pairing codes, code hashes, challenge nonces, signatures,
  request payloads, results, file content, clipboard content, process
  output, screenshot bytes, secrets, and approval payloads never enter
  logs or evidence. `redactedPairingSummary` and `redactedDeviceSummary`
  enforce this shape.
- Secret comparison uses `timingSafeEqual`. Error strings carry failure
  classes only.

## 9. Non-goals of this grain

- No OAuth 2.1 authorization implementation (SG-000054).
- No device uplink networking beyond the frozen contract vocabulary
  (SG-000055). The relay device transport remains a fail-closed
  skeleton and does not import this module.
- No public edge implementation (SG-000056).
- No relay deployment (SG-000057).
- No new local MCP tool, no tool schema change, no capability widening,
  and no approval change. The canonical 20-tool catalog is unchanged.
- No P16 tool-surface widening and no provider submission, directory
  publication, or availability claim.

## 10. Qualification

`device-identity.test.ts` proves protected key separation, challenge
and response binding with remap, epoch, expiry, and forgery rejection,
pairing entropy, expiry, one-shot consumption, five-attempt rate
limiting, pairing grants no trust, rotation epoch advancement, hard,
principal-wide, all-route, and emergency revocation, exact envelope
binding with principal-A-to-device-B remap rejection, frozen vocabulary
conformance, no network, tool, or approval authority, a still
fail-closed relay skeleton, and this note as the canonical record.
All closed SG-000001 through SG-000052 regressions must pass unchanged.
