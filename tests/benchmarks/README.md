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
- **Pinned taskpack:** `taskpacks/cua-driver-bench.lock.json` pins the cua-driver-bench taskpack (trycua/cua `a802eaf`, FSL-1.1-MIT, authorized by FD-04). It records all 123 files, each with its donor path, git blob id, sha256 and size. The taskpack is not copied into Orcel: its binary workbooks and an empty fixture could not pass the exact-diff review gate, and a lock keeps the repository small.
  - `python3 -m orcel_bench fetch-taskpack cua-driver-bench --into DIR [--from URL_OR_CLONE]` checks out exactly that subtree, with no line-ending conversion.
  - It refuses the result unless the files are exactly the locked ones, byte for byte. A Windows checkout's CRLF conversion once looked like 'stale digests'; the lock now catches that as a mismatch instead.
  - `tests/test_taskpack.py` fetches it, then runs each task's own digest check, its Python suite and its Electron store tests. The CI Governance job runs these on Linux.
  - Known residuals:
    - `cdb-s02`'s repository-schema test needs `cb.schemas` from Cua's private harness, so it always skips.
    - The symlink tests skip on Windows without the symlink privilege and run on Linux.
    - LibreOffice and GnuCash are needed only to *perform* the tasks, not by their evaluators' tests.

- **Orcel-driven runs, Tier A** (`ORCEL_EXECUTION_PLAN.md`): `python3 -m orcel_bench orcel --orceld <orceld binary> ...` solves the read-only Orcel task set (`orcel-tasks/orcel-read/`: 7 tasks, 20 variants) **through the real orceld**.
  - `orcel_bench/orcel.py` starts orceld on each episode's workspace with private state, speaks its stdio protocol, and traces every call (capability, operation, outcome, error code, latency). A crash, hang or protocol break is typed.
  - `orcel_bench/orcel_runner.py` runs setup, then the task's deterministic `orcel_plan`, then a byte-for-byte workspace check (read-only tasks must change nothing), then `evaluate_task`. It writes report rows (planner `orcel-fs-planner`) and a JSON-lines trace.
  - The tasks cover listing, reading, finding, stat, ranged reads, and Orcel's own `PATH_ESCAPE` refusal of reads outside the workspace.
  - `crates/orceld/tests/bm02_orcel_benchmark.rs` runs the set through this build's orceld in every OS's Rust CI job and prints `BM02-EVIDENCE` lines. `tests/test_orcel_runner.py` checks the runner's own failure classification with stand-in programs.
  - orceld refuses state that another account can reach, so `--temp-root` must be a private folder.

Not yet done:
- mutating tasks through Orcel (Tier B: orceld's real broker with its test builds' scripted consent) and the GUI taskpack in an isolated environment (Tier C);
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
