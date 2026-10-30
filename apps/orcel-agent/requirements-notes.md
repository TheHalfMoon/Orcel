# Orcel Agent dependency lock: notes

SG-000129 slice 1. The lock files are generated, so this file records how
they were made and every deliberate version move.

## How the lock is made

- `requirements.in` names the admitted packages at the versions DeerFlow's
  pin `81e1ab8` resolves in `backend/uv.lock`.
- Every transitive package is constrained to the pin's resolved version too.
  The constraints come from that `uv.lock`, minus any package moved below.
- The lock is resolved universally for Python 3.12, wheels only, with
  hashes:

  ```bash
  uv pip compile requirements.in --universal --python-version 3.12 \
    --generate-hashes --only-binary :all: --no-header \
    -c <constraints from the pin's uv.lock> -o requirements.lock
  ```

  It has no platform markers, so the same 37 distributions install on
  Windows, macOS and Linux.
- Install exactly as CI does:

  ```bash
  pip install --require-hashes --only-binary :all: --no-deps -r requirements.lock
  ```
- `audit/requirements.lock` pins the advisory auditor (`pip-audit` 2.10.1)
  the same way, in its own environment.

## Version moves

| Package | Pin resolves | Locked | Why |
|---|---|---|---|
| langgraph-sdk | 0.4.4 | 0.4.6 | GHSA-3fx2-cqw9-xr3c (CVE-2026-118667): unencoded `thread_id`/`assistant_id` in v3 streaming request paths, affecting 0.4.0–0.4.5. The agent never uses the SDK's HTTP client or `RemoteGraph`; it is moved anyway because the audit must report nothing unaddressed. `langgraph` 1.2.9 requires `>=0.4.2,<0.5.0`. |

## Not admitted, and why

- `mcp`, `langchain-mcp-adapters`: the M1 stdlib client is the only edge
  session (SG-000129 decision "Who holds the MCP session").
- `tiktoken` and provider SDKs: no model and no download in M2–M3.

## Present, never loaded

- `sqlite-vec` 0.1.9 is required by `langgraph-checkpoint-sqlite`. Only
  LangGraph's vector store (`langgraph.store.sqlite`) loads it. The agent
  uses the checkpoint saver, never the store. `langgraph.store` is on the
  source-scan denylist, and the egress test refuses the `sqlite3` audit
  events `enable_load_extension` and `load_extension`.

## License exceptions

These are recorded in the spec and reviewed, not allowlisted:
- `certifi` (MPL-2.0);
- `orjson` (MPL-2.0 AND (Apache-2.0 OR MIT)).

Both are used unmodified. See `tools/licenses.py`.
