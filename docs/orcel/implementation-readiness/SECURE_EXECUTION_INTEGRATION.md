# SPACE → Orcel secure execution blueprint (with cua-vmm, Lume, and the multi-device boundary)

Status: PROPOSED (Fable, 2026-10-18). Donors: [perplexityai/SPACE](https://github.com/perplexityai/SPACE/tree/09e922efd23b3c0d109ab64de7e567a901bcc61e) `09e922ef` (2026-10-18), **Apache-2.0, Copyright 2026 Perplexity AI** (public license; the founder's separate permission is not needed for Apache terms); Cua `a802eaf2` (`libs/cua/crates/cua-vmm`, `libs/lume`, MIT). Rows: `T-SP-*`, `T-CUA-11/12`.

## 1. Principle

Sandboxes are an optional product capability for running untrusted code and disposable workspaces. They are **not** required for ordinary computer use, browser tasks or file work, and no microVM, GPU or paid service is required by Core.

## 2. SPACE inspected (VERIFIED SOURCE FACT)

SPACE is a datacenter platform: API with PostgreSQL desired state, cluster controller, Kubernetes or direct substrate, node manager, Firecracker runtime, data plane for command streams, object storage for templates and snapshots, E2B compatibility wrapper. Largest crates: `libs/api` 193,619 lines, `libs/sbx/mgr/server` 184,053, `libs/cluster/controller/server` 91,031, `libs/node/mgr/server` 59,812, `libs/spaced/guest/server` 26,776, `libs/node/runtime/core` 15,139. Toolchain 1.98.0, edition 2024.

Semantics worth adopting (from `docs/architecture.md`):
- **Paused** keeps VM memory resident (not durable); **suspended** writes a memory + runtime + rootfs snapshot and releases resources; wake waits for readiness.
- Lifecycle requests return an operation id; operation state ≠ sandbox state ≠ command exit status.
- A drained `Process.Start` that has not reported itself ends `unknown` "since the command may be running and a retried start would run it twice"; a streamed stdin returns 409 because some input may already be delivered.
- Execution-generation fencing: deadline mutations are fenced on the current execution generation obtained from the worker.
- Management tokens and attachment tokens are not interchangeable.

## 3. Decision per SPACE unit

| Unit | Verdict | Destination | Task |
|---|---|---|---|
| `crates/libs/node/runtime/core/src/fc_api*` (Firecracker API client) | COPY_ADAPT | `crates/orcel-sandbox/src/firecracker/` | SX-04 |
| `crates/libs/node/runtime/core/src/snapshot_files.rs` | COPY_ADAPT | `.../firecracker/snapshot.rs` | SX-04 |
| `crates/libs/spaced/guest/server/src/{process,idempotency,filesystem}.rs` | COPY_ADAPT, gRPC replaced by Orcel JSON-lines frames | `apps/orcel-guest-agent/` | SX-05 |
| `crates/libs/spaced/guest/server/src/cgroup.rs`, `process.rs` termination | REFERENCE for XP-13 process-group and cgroup cleanup | `crates/orcel-provider-process` | XP-13 |
| Lifecycle semantics, fencing, unknown start | PORT as rules | `crates/orcel-journal`, remote leases | RJ-02 |
| API, controllers, PostgreSQL, Kubernetes, node manager, net gateway, credential manager, object store, ECW, metrics, AWS | REJECT | local-first product; would add a second control plane | - |
| `credential/injection/store` | REFERENCE | secret injection is a later, separate grain; Orcel never exports credentials to a sandbox by default | - |

SPACE's Firecracker backend needs Linux with `/dev/kvm`. It is not a Windows or macOS engine and is not presented as one.

## 4. One secure-execution interface, OS-specific adapters

`crates/orcel-sandbox` exposes a subset of cua-vmm's `Runtime` trait (VERIFIED SOURCE FACT: `libs/cua/crates/cua-vmm/src/runtime.rs` declares `ensure_base, start, stop, suspend, resume, fork, checkpoint, delete_checkpoint, list, status, delete, endpoints, guest_tcp_listening, guest_exec`).

| Backend | Host OS | Isolation | Source | Task | Default |
|---|---|---|---|---|---|
| Rootless Podman + gVisor `runsc`, `--network=none` | Linux | user-space kernel | cua-vmm `container/` | SX-01 | first |
| QEMU with KVM / HVF / WHPX | Linux / macOS / Windows | hardware VM | cua-vmm `qemu/` | SX-02 | optional |
| Lume (Apple Virtualization) | macOS Apple silicon | hardware VM | Lume CLI wrapped | SX-03 | optional |
| Firecracker + jailer | Linux with KVM | microVM, fast snapshot/resume | SPACE `fc_api` | SX-04 | optional |
| Windows Sandbox (`.wsb`) | Windows Pro/Enterprise | hardware VM | none (REFERENCE) | not planned | - |

Guest access: the Orcel guest agent (SX-05) over vsock or virtio-serial; no published ports, no VNC by default, no SSH with default credentials (Lume's default `lume`/`lume` is replaced per VM).

Required removals from cua-vmm on import: `auto.rs` provisioning and `managed.rs` first-use downloads ("download the built-in Lume", "download the built-in Linux runtime"), "fetch QEMU when absent", the reqwest `lume serve` client. Every runtime binary is a user-installed prerequisite or a separately admitted, pinned, signature-checked artifact.

## 5. Relation to process confinement

Basic restricted execution stays in `orcel-provider-process`: Job Objects/AppContainer on Windows, Landlock + seccomp + cgroup v2 + pidfd on Linux, process groups + rlimits on macOS (XP-13). Sandboxes are the stronger, slower tier on top. Policy chooses the tier; a model cannot.

## 6. Multi-device and sandbox boundary

Multi-device stays as adopted (`MULTI_DEVICE_ARCHITECTURE.md`): existing device identity, OAuth, outbound relay, explicit per-target grants, no LAN/QUIC prerequisite. Cross-platform changes only the endpoints:

| Need | Plan | Source |
|---|---|---|
| Device keys on macOS/Linux | Keychain / Secret Service through `orceld` | XP-19 |
| Device registration on any OS | unchanged relay protocol (frozen `orcel-relay/1`) | existing |
| Remote execution | locally issued remote leases with generation fencing | existing + RJ-02 |
| Human takeover and visible indicator | Control Room indicator + emergency stop on each target | CR-03, existing |
| Virtual desktops / remote environments | sandboxes above, attached to a device as a resource | SX-* |
| Inventory and grouping ideas | MeshCentral (Apache-2.0) | REFERENCE |
| Agent install patterns | MeshAgent (README Apache-2.0, no root LICENSE) | REFERENCE; no SYSTEM agent |
| Direct device-to-device transport | cua-mesh (MIT, WireGuard via boringtun) | DEFER; only if relay latency is measured as the bottleneck |
| Desktop streaming, teleport, presence | Cua Spaces (FSL) | REJECT (FD-04) |

## 7. Cost

All backends run on hardware the user already has. No cloud sandbox, no warm pool, no GPU. A founder-hosted sandbox service is out of scope for this plan and would be its own infrastructure decision.
