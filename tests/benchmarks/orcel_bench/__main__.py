"""BM-02: ``python -m orcel_bench oracle`` runs every task with the oracle.

Usage (from tests/benchmarks):

    python3 -m orcel_bench oracle --commit <40-hex> --out <file.report.json> [--repeat N] [TASK_DIR ...]

With no task directories, every directory under tasks/<group>/ that has a
main.py runs. The report is checked by scripts/check-benchmark-report.mjs.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .runner import report, run_oracle

HERE = Path(__file__).resolve().parent.parent


def all_tasks() -> list[Path]:
    return sorted(path.parent for path in (HERE / "tasks").glob("*/*/main.py"))


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="orcel_bench")
    sub = parser.add_subparsers(dest="command", required=True)
    oracle = sub.add_parser("oracle", help="run tasks with the oracle (a dry run of the benchmark)")
    oracle.add_argument("--commit", required=True, help="the Orcel commit under test (40 hex)")
    oracle.add_argument("--out", required=True, type=Path, help="where to write the report")
    oracle.add_argument("--repeat", type=int, default=1, help="episodes per variant (latency)")
    oracle.add_argument("tasks", nargs="*", type=Path)
    args = parser.parse_args(argv)
    tasks = [path.resolve() for path in args.tasks] or all_tasks()
    if not tasks:
        parser.error("no tasks found")
    rows = run_oracle(tasks, repeat=args.repeat)
    args.out.write_text(json.dumps(report(args.commit, rows), indent=2) + "\n", encoding="utf-8")
    failed = [row["case"] for row in rows if row["status"] != "pass"]
    print(f"orcel_bench: {len(rows) - len(failed)}/{len(rows)} variants solved by the oracle -> {args.out}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
