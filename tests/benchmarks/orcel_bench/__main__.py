"""BM-02: ``python -m orcel_bench oracle`` runs every task with the oracle.

Usage (from tests/benchmarks):

    python3 -m orcel_bench oracle --commit <40-hex> --out <file.report.json> [--repeat N] [TASK_DIR ...]
    python3 -m orcel_bench fetch-taskpack <name> --into <new dir> [--from <git URL or local clone>]
    python3 -m orcel_bench tierc-noop --pack <verified taskpack> --commit <40-hex> --out <file.report.json>
    python3 -m orcel_bench orcel --orceld <orceld binary> --commit <40-hex> --out <file.report.json> [--trace <file.jsonl>] [--repeat N] [--temp-root DIR] [TASK_DIR ...]

`orcel` solves the Orcel tasks under orcel-tasks/<group>/ through the real
orceld (ORCEL_EXECUTION_PLAN.md, Tier A).

With no task directories, every directory under tasks/<group>/ that has a
main.py runs. The report is checked by scripts/check-benchmark-report.mjs.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .orcel_runner import PLANNER as ORCEL_PLANNER
from .orcel_runner import run_orcel
from .runner import report, run_oracle
from .taskpack import TaskpackError, fetch, load_lock

HERE = Path(__file__).resolve().parent.parent


def all_tasks() -> list[Path]:
    return sorted(path.parent for path in (HERE / "tasks").glob("*/*/main.py"))


def all_orcel_tasks() -> list[Path]:
    return sorted(path.parent for path in (HERE / "orcel-tasks").glob("*/*/main.py"))


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="orcel_bench")
    sub = parser.add_subparsers(dest="command", required=True)
    oracle = sub.add_parser("oracle", help="run tasks with the oracle (a dry run of the benchmark)")
    oracle.add_argument("--commit", required=True, help="the Orcel commit under test (40 hex)")
    oracle.add_argument("--out", required=True, type=Path, help="where to write the report")
    oracle.add_argument("--repeat", type=int, default=1, help="episodes per variant (latency)")
    oracle.add_argument("tasks", nargs="*", type=Path)
    pack = sub.add_parser("fetch-taskpack", help="check out a pinned taskpack and verify every file")
    pack.add_argument("name")
    pack.add_argument("--into", required=True, type=Path, help="a directory that does not exist yet")
    pack.add_argument("--from", dest="source", help="the donor repository (default: the lock's URL)")
    orcel = sub.add_parser("orcel", help="solve the Orcel tasks through the real orceld")
    orcel.add_argument("--orceld", required=True, type=Path, help="the orceld binary under test")
    orcel.add_argument("--commit", required=True, help="the Orcel commit under test (40 hex)")
    orcel.add_argument("--out", required=True, type=Path, help="where to write the report")
    orcel.add_argument("--trace", type=Path, help="where to write the per-episode trace (JSON lines)")
    orcel.add_argument("--repeat", type=int, default=1, help="episodes per variant (latency)")
    orcel.add_argument(
        "--temp-root",
        type=Path,
        help="where episode workspaces and orceld state go (default: the system temp); "
        "orceld refuses state any other account can reach, so it must be private",
    )
    orcel.add_argument("tasks", nargs="*", type=Path)
    tierc = sub.add_parser("tierc-noop", help="Tier C C1: the no-op baseline over a verified taskpack")
    tierc.add_argument("--pack", required=True, type=Path, help="a taskpack fetched by fetch-taskpack (verified again before it runs)")
    tierc.add_argument("--commit", required=True, help="the Orcel commit under test (40 hex)")
    tierc.add_argument("--out", required=True, type=Path, help="where to write the report")
    observe = sub.add_parser("tierc-observe", help="Tier C C2a: launch a task's apps and observe them through orceld (CI only)")
    observe.add_argument("--pack", required=True, type=Path)
    observe.add_argument("--orceld", required=True, type=Path)
    observe.add_argument("--task", required=True)
    observe.add_argument("--commit", required=True)
    observe.add_argument("--out", required=True, type=Path)
    act = sub.add_parser("tierc-act", help="Tier C C2b: a scripted plan acting through orceld's test build (CI only)")
    act.add_argument("--pack", required=True, type=Path)
    act.add_argument("--orceld", required=True, type=Path)
    act.add_argument("--act-test", required=True, type=Path, help="orceld's test binary (cargo test --no-run)")
    act.add_argument("--plan", required=True, type=Path)
    act.add_argument("--commit", required=True)
    act.add_argument("--out", required=True, type=Path)
    args = parser.parse_args(argv)
    if args.command == "tierc-act":
        from .tierc import TierCError
        from .tierc_gui import run_act_episode

        try:
            rows = run_act_episode(args.pack.resolve(), load_lock("cua-driver-bench"), args.plan.resolve(),
                                   args.orceld.resolve(), args.act_test.resolve())
        except TierCError as error:
            print(f"orcel_bench: {error}", file=sys.stderr)
            return 1
        planner = {"kind": "deterministic", "name": "tierc-scripted-plan", "version": "1-scripted-consent"}
        args.out.write_text(json.dumps(report(args.commit, rows, planner), indent=2) + "\n", encoding="utf-8")
        for row in rows:
            print(f"TIERC-ACT-EVIDENCE {row['case']} {row['status']} {row['observed']} steps={row['steps']} {row['latency_ms']['p50']}ms")
        return 0 if all(row["status"] == "pass" for row in rows) else 1
    if args.command == "tierc-observe":
        from .tierc import TierCError
        from .tierc_gui import PLANNER as OBSERVE_PLANNER
        from .tierc_gui import run_observe_episode

        try:
            rows = run_observe_episode(args.pack.resolve(), load_lock("cua-driver-bench"), args.task, args.orceld.resolve())
        except TierCError as error:
            print(f"orcel_bench: {error}", file=sys.stderr)
            return 1
        args.out.write_text(json.dumps(report(args.commit, rows, OBSERVE_PLANNER), indent=2) + "\n", encoding="utf-8")
        for row in rows:
            print(f"TIERC-GUI-EVIDENCE {row['case']} {row['status']} {row['observed']} steps={row['steps']} {row['latency_ms']['p50']}ms")
        return 0 if all(row["status"] == "pass" for row in rows) else 1
    if args.command == "tierc-noop":
        from .tierc import PLANNER as TIERC_PLANNER
        from .tierc import TierCError, run_noop

        try:
            rows = run_noop(args.pack.resolve(), load_lock("cua-driver-bench"))
        except TierCError as error:
            print(f"orcel_bench: {error}", file=sys.stderr)
            return 1
        args.out.write_text(json.dumps(report(args.commit, rows, TIERC_PLANNER), indent=2) + "\n", encoding="utf-8")
        failed = [row["case"] for row in rows if row["status"] != "pass"]
        print(f"orcel_bench: {len(rows) - len(failed)}/{len(rows)} Tier C no-op baselines rejected -> {args.out}")
        return 1 if failed else 0
    if args.command == "orcel":
        if args.temp_root is not None:
            import tempfile

            args.temp_root.mkdir(parents=True, exist_ok=True)
            tempfile.tempdir = str(args.temp_root.resolve())
        tasks = [path.resolve() for path in args.tasks] or all_orcel_tasks()
        rows = run_orcel(tasks, args.orceld.resolve(), repeat=args.repeat, trace=args.trace)
        args.out.write_text(json.dumps(report(args.commit, rows, ORCEL_PLANNER), indent=2) + "\n", encoding="utf-8")
        failed = [row["case"] for row in rows if row["status"] != "pass"]
        print(f"orcel_bench: {len(rows) - len(failed)}/{len(rows)} variants solved through orceld -> {args.out}")
        for case in failed:
            print(f"orcel_bench: not solved: {case}", file=sys.stderr)
        return 1 if failed else 0
    if args.command == "fetch-taskpack":
        try:
            root = fetch(args.name, args.into.resolve(), args.source)
        except TaskpackError as error:
            print(f"orcel_bench: {error}", file=sys.stderr)
            return 1
        print(f"orcel_bench: {args.name} verified at {root}")
        return 0
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
