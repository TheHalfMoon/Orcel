# SG-000132 slice 9: the Full Control MCP tools (`fc_*`)

Status: implemented and tested on branch `authority/fc-mcp-tools`; not installed. Nothing in this slice was installed or
run elevated, no UAC, Windows Hello or Orcel dialog was shown or answered, and no system, registry, firewall or ACL
setting changed. The MCP tests drive the tools against a scripted kernel; no test reaches a real orceld, service or
dialog. Earlier: [SG132_SLICE8.md](SG132_SLICE8.md) (the orceld request capabilities this slice exposes),
[SG132_SLICE1.md](SG132_SLICE1.md) to [SG132_SLICE7.md](SG132_SLICE7.md). Authority for the tool surface: the SG-000132
amendment "SG-000132 amendment: Full Control file writes covered by the lease, and the fc_* tool surface"
(`.specgrain/specs/SG-000132.json`, created 2026-11-19) and [FC_TOOL_SURFACE_OPTIONS.md](FC_TOOL_SURFACE_OPTIONS.md)
section 8.

**What this slice does:** option B's slice 2 (SG132_SLICE8.md next step 1). Fourteen local-only MCP tools, one per
orceld `fc-worker` operation plus `fc_status`, in the normal local tool list (`desktop_structured`) only.

## 1. The tools

`apps/orcel-mcp/src/full_control.ts`, patterned on `desktop.ts`. Each tool sends exactly one orceld request: the
capability and operation below, `arguments` = the worker operation (`{"op": <operation>, ...fields}`, every field
present, as orceld's `WorkerOp` requires), and no `target`. `workspace_id` is optional and only fills the envelope.

| Tool | orceld shape | Arguments (bounds as orceld's `WorkerOp::check_arguments`) | Approval |
| --- | --- | --- | --- |
| `fc_status` | `fc.status/get` | none | none (read-only; grants nothing) |
| `fc_fs_stat` | `fc.fs/stat` | `path` | none |
| `fc_fs_list` | `fc.fs/list` | `path`, `max_entries` 1..1000 (default 200) | none |
| `fc_fs_read` | `fc.fs/read_text` | `path`, `max_bytes` 1..262144 (default 65536) | none |
| `fc_fs_write` | `fc.fs/write_text` | `path`, `text` (at most 262144 UTF-8 bytes), `create_new` (default false) | none: covered by the lease (the amendment) |
| `fc_fs_mkdir` | `fc.fs/mkdir` | `path` | none: covered by the lease (the amendment) |
| `fc_process_run` | `fc.process/run` | `program` (absolute `.exe`), `args` (at most 64, each at most 8192 characters, no NUL), `cwd`, `timeout_ms` 1..50000 (default 30000), `max_output_bytes` 1..65536 (default 65536) | SOFT, every call |
| `fc_git_status` | `fc.git/git_status` | `repository` | none |
| `fc_git_diff` | `fc.git/git_diff` | `repository`, `staged` (default false) | none |
| `fc_git_log` | `fc.git/git_log` | `repository`, `max_count` 1..100 (default 20) | none |
| `fc_git_stage` | `fc.git/git_add` | `repository`, `paths` (1..128 distinct, at most 4096 bytes, no control data, no `:` magic) | SOFT, every call |
| `fc_git_unstage` | `fc.git/git_unstage` | as `fc_git_stage` | SOFT, every call |
| `fc_git_commit` | `fc.git/git_commit` | `repository`, `message` (not blank, at most 8192 bytes, no NUL) | SOFT, every call |
| `fc_git_branch_create` | `fc.git/git_branch_create` | `repository`, `branch` (1..255 bytes, no control data, not starting with `-`); creates the branch and switches to it | SOFT, every call |

Every path, program, working folder and repository is an absolute drive path of at most 1024 characters without control
characters (orceld's dispatch path check does the rest: alternate data streams, dot components, the lease's roots).
The schemas are a first filter only; orceld checks every bound again before the lease is used or the person is asked.

Descriptions say, for every tool, that it needs a Full Control lease from the Orcel authority service covering this
client (with `fc_status` for the reference), that it refuses otherwise (`LEASE_REQUIRED`, `CAPABILITY_DENIED`,
`PATH_ESCAPE`), and that it is local only;
which tools ask on every call; that file writes and folder creation are covered by the lease with no per-call
approval (founder decision, the SG-000132 amendment); and which need a lease that includes programs (shells).

## 2. Contract and profiles

- `apps/orcel-mcp/src/tool_contract.ts`: 14 entries, all `remote: "local_only"` (no OAuth scope; never in `core`). Reads
  are effect `read`, approval `none`. `fc_process_run` is `execute`, SOFT, destructive and open-world. The four Git
  changes are `write`, SOFT. `fc_fs_write` and `fc_fs_mkdir` use a new effect class, **`lease_write`**: a change with no
  per-call approval, allowed only on a local-only `fc.fs` tool (the contract test pins both). The Rust mirror
  (`orcel_contracts::tool::EffectClass`) and `docs/orcel/contracts/schema/tool_entry.schema.json` gain `lease_write`.
- `FULL_CONTROL_TOOLS` is a separate frozen list; `desktop_structured` is `DESKTOP_STRUCTURED_TOOLS` plus it. The
  browser profiles (`browser_structured`, `browser_full`) extend `DESKTOP_STRUCTURED_TOOLS` and so never list the
  `fc_*` tools, matching orceld, which refuses `fc.*` under any tool surface other than `desktop_structured`.
- Regenerated: [docs/p16/TOOL_CONTRACT.md](../../../p16/TOOL_CONTRACT.md) (`scripts/generate-tool-contract-doc.mjs`) and
  [docs/p16/CAPABILITY_PARITY.md](../../../p16/CAPABILITY_PARITY.md) (`scripts/generate-parity-doc.mjs`) from
  `docs/p16/capability_parity_inventory.json` (14 `implemented_exposed` entries). The catalog lists that pin the closed
  tool set (`CANONICAL_TOOL_NAMES` and the test lists), the Claude Desktop extension manifest, `inspector.sh` and the
  README table (now 59 tools) are updated together.

## 3. Protocol changes

None on the wire: the tools send the `fc.*` requests slice 8 added. **Older peers:** this MCP module against an
orceld before slice 8 gets `CAPABILITY_DENIED` (not in that orceld's policy) for every `fc_*` call, which passes
through to the client unchanged (fail closed). **Upgrade order:** the service, then orceld, then this MCP module.

## 4. Threat model additions

Test names: `apps/orcel-mcp/src/full-control.test.ts` unless stated.

| Attack | Claim | Evidence |
| --- | --- | --- |
| A remote client (relay, tunnel, ChatGPT) sees or calls an `fc_*` tool | Every entry is `local_only`: no OAuth scope, never in `core`, refused by `authorizeToolByScopes`; orceld refuses a remote `fc.*` request anyway (slice 8) | `fc: the contract lists the 14 tools, local only, with the decided approvals`; `tool-contract.test.ts` (`remote discovery lists only the core profile`, `the contract's remote scopes equal the orceld remote-session scope table`) |
| A browser profile serves the Full Control tools | Only `desktop_structured` lists them | `fc: listed in desktop_structured only, never in a browser or remote profile`; `fc: a browser profile does not list the Full Control tools` (discovery); `browser-exposure.test.ts` |
| The contract advertises the wrong approval (a write that silently asks nothing beyond the amendment, or a run without SOFT) | Run and the four Git changes are SOFT; only `fc_fs_write` and `fc_fs_mkdir` are `lease_write` with `none`; reads are `read`/`none`; the consistency test allows `none` on a change only for a local-only `fc.fs` `lease_write` | `fc: the contract lists...`; `tool-contract.test.ts` (`annotations, effect classes, and approval classes are mutually consistent`) |
| A tool sends another shape, a target, or free arguments | Each tool forwards exactly its `fc.*` shape and its worker operation with every field, no target | `fc: each tool forwards exactly one worker operation and orceld's refusal passes through` (all 14); `parity-inventory.test.ts` |
| A refusal is rewritten, hidden or retried at the edge | orceld's error envelope (`LEASE_REQUIRED` here) reaches the client unchanged through `projectKernelResult` | `fc: each tool forwards...` |
| A malformed request reaches orceld | The schemas refuse out-of-bound arguments before any kernel call (orceld checks again) | `fc: schemas repeat orceld's bounds`; `fc: each tool forwards...` (an out-of-range timeout is not forwarded) |
| The MCP module grants, renews or approves anything | It only forwards requests; no grant or approval path exists | `surface.test.ts` (no lifecycle, trust or approval surface in tool sources) |

## 5. Residuals

1. **Models may pick a Safe tool where a Full Control one was meant, or the reverse.** The descriptions say which
   needs a lease; orceld refuses whichever is not admitted.
2. **The tools are listed before any lease exists** (founder decision 3) and refuse with `LEASE_REQUIRED` until one does.
3. **The client reference changes when the MCP server restarts** (slice 6 residual 2, slice 8 residual 5). `fc_status`
   shows the current one.
4. **A forwarded loopback port makes local-only tools remotely reachable.** The loopback HTTP transport serves
   `desktop_structured` behind its bearer token and Host and Origin checks. Anyone who forwards that port through a
   third-party tunnel (or shares the loopback token) turns every local-only tool into a remote one that orceld sees as
   local, and `fc_fs_write` and `fc_fs_mkdir` then run without a prompt inside a granted lease's roots (the other
   changes still raise the Windows dialog on this computer). The loopback token must never be shared and the port must
   never be forwarded; Orcel's own remote path (the relay and tunnel) serves only `core` and is refused by orceld for
   `fc.*`.
5. Slice 8's residuals stand unchanged (lease-covered writes without undo, Git changes without `expected_head`, the
   approval asked before `Authorize`, the handle re-check's small windows, the founder runs).

## 6. Not done; next steps

1. Founder runs (slice 8 next step 2), now through a real MCP client: `fc_status`, then a lease granted to its
   reference (`orcel full-control grant --client <client_ref> --executors filesystem,shell_process --root <folder>
   --shells`), a write without a prompt, a program run and a Git commit with the Windows dialog.
2. Slice 8's remaining steps (slice 6 steps). The `mkdir` re-check relative to the parent handle is done in the
   slice 8 follow-up (branch `authority/fc-mkdir-relative`; [SG132_SLICE8.md](SG132_SLICE8.md) residual 7).

## Tests

At head (Windows, unelevated):

- `npm run build --workspace @orcel/mcp`, then every `apps/orcel-mcp/dist/*.test.js` except the clipboard tests (they
  touch the live clipboard; CI runs them): all pass, including the 5 new `fc:` tests.
- `node scripts/generate-tool-contract-doc.mjs` and `node scripts/generate-parity-doc.mjs`: regenerated, pinned by
  `tool-contract.test.ts` and `parity-inventory.test.ts`.
- `cargo test -p orcel-contracts`: pass (the schema with `lease_write`).
