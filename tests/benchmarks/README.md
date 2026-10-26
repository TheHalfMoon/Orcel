# Task benchmark runner (BM-02)

Test-only tooling for backlog BM-02. It runs fixed task sets and writes an
`orcel-benchmark-report/1` file
([schema](../../docs/orcel/implementation-readiness/protocol/BENCHMARK_REPORT_1.schema.json)),
which `scripts/check-benchmark-report.mjs` validates. Python is used here
only, never in the product, and only its standard library.

## What exists so far

- **Task format:** `orcel_bench/task.py`, from cua-bench. A task directory has a `main.py` that defines four functions:
  - `tasks_config` returns the variants;
  - `setup_task` prepares the workspace;
  - `solve_task` is the oracle;
  - `evaluate_task` returns a reward from the final state.
- **Session:** `orcel_bench/session.py`. Each episode gets a fresh temporary workspace, which is removed afterwards.
  - It supports file operations only. Nothing runs a shell.
  - Only plain relative names are accepted. Absolute paths, `..`, drives, streams, Windows device names, and links that lead outside the workspace are refused.
- **Runner:** `orcel_bench/runner.py` and `python3 -m orcel_bench oracle`. It runs each variant with the oracle and writes one report row per variant.
  - A row's `status` is `pass`, `fail` or `error`.
  - Its `observed` value is a fixed code, never task text or an error message: `solved`, `unsolved`, `<phase>-error` or `timeout`.
  - With `--repeat N`, latency is reported as P50/P95.
  - Each phase runs on its own thread with a 30 s deadline, so it times out even when it blocks without awaiting. A `TimeoutError` the task raises itself is reported as a phase error, not a timeout.
    A phase past its deadline is abandoned, not killed: its thread keeps running until the process exits. Its session has ended, so session calls fail and nothing recreates the workspace. A task that writes through plain file APIs is outside the session's guard; tasks are trusted, Orcel-owned code, and the session guards against mistakes, not against a hostile task.
  - Rewards are strict: a reward must be a number in [0, 1] or a non-empty list of them. Any missing or bad value means the variant is unsolved.
  - Case ids are `<group>/<task>/<variant>`. Every part is checked, ids are unique, and an id is at most 200 characters.
  - The report never records the CPU model or memory, and never runs in a cloud.
- **Tasks:** `tasks/orcel/` holds Orcel-owned tasks:
  - `hello-file` writes a word into a file;
  - `report-rename` moves the latest dated report to its canonical name and leaves the others unchanged.
- **Tests:** `tests/test_runner.py` is the oracle-only dry run, the backlog's positive test. The CI Governance job runs it.

Not yet done:
- driving tasks through Orcel with a deterministic planner or a pinned MCP client;
- the cua-driver-bench taskpack (FSL-1.1-MIT, authorized by FD-04), which needs per-file provenance;
- a first report of 20 tasks per OS.

## Run

```bash
python3 -m unittest discover -s tests/benchmarks/tests -t tests/benchmarks -v
(cd tests/benchmarks && python3 -m orcel_bench oracle --commit "$(git rev-parse HEAD)" --out /tmp/oracle.report.json --repeat 5)
node scripts/check-benchmark-report.mjs /tmp/oracle.report.json
```

## Provenance

The donor is trycua/cua at commit `a802eaf26ca97616a6bf0de6a29729a9346fbb1f`, `libs/cua-bench` (MIT, Copyright (c) 2024-2025 TryCua). The licence is in [LICENSE-cua-bench.txt](LICENSE-cua-bench.txt), which is the text of blob `98422212` with LF line endings.

| Orcel file | Donor file (blob) | Method |
| --- | --- | --- |
| `orcel_bench/task.py` | `cua_bench/core.py` (`ab33166e`) and `cua_bench/decorators.py` (`b7095f05`) | COPY_ADAPT: the `Task` dataclass and the four decorators |
| `orcel_bench/runner.py` | `cua_bench/runner/episode.py` (`02e1d1ab`) | COPY_ADAPT: the phase order and `reward_of` |
| `tasks/orcel/hello-file/main.py` | `example_tasks/hello_file_env/main.py` (`8d56e2f3`) | Modelled on it, with no shell commands |

`orcel_bench/session.py`, `__main__.py`, `tasks/orcel/report-rename` and the tests are Orcel-owned.
