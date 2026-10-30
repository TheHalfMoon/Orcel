"""SG-000129: Tier A parity between two Orcel Agent benchmark reports.

    python compare_agent_reports.py <m1.report.json> <other.report.json>

Exits non-zero unless both reports cover the same cases with identical rows,
ignoring only latency (and the planner label, which must differ honestly).
"""

from __future__ import annotations

import json
import sys

#: Row fields that may differ between two runs of the same plans.
IGNORED = {"latency_ms"}


def rows(path: str) -> tuple[dict, dict]:
    with open(path, encoding="utf-8") as handle:
        report = json.load(handle)
    return report["planner"], {row["case"]: {k: v for k, v in row.items() if k not in IGNORED} for row in report["rows"]}


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    (base_label, base), (other_label, other) = rows(argv[0]), rows(argv[1])
    problems = []
    if base_label == other_label:
        problems.append(f"both reports carry the planner label {base_label}")
    if sorted(base) != sorted(other):
        problems.append(f"cases differ: {sorted(set(base) ^ set(other))}")
    for case in sorted(set(base) & set(other)):
        if base[case] != other[case]:
            problems.append(f"{case}: {base[case]} != {other[case]}")
    for problem in problems:
        print(f"parity: {problem}", file=sys.stderr)
    if not problems:
        print(f"parity: {len(base)} rows identical ({base_label['name']} vs {other_label['name']}), latency ignored")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
