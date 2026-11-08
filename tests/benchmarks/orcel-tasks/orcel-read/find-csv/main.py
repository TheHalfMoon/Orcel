"""Orcel task (BM-02 Tier A, read-only): find every CSV file in the tree through Orcel's find.

Orcel-owned. The planner observes only through Orcel (`orcel.call`); the
workspace must be unchanged afterwards.
"""

import orcel_bench as ob

VARIANTS = {
    "flat": ["a.csv", "b.csv", "notes.txt"],
    "nested": ["data/q1.csv", "data/2026/q2.csv", "data/2026/readme.md", "archive/old.csv"],
    "none": ["readme.md", "data/plan.txt"],
}


@ob.tasks_config
def load():
    return [ob.Task(description="List every .csv file.", task_id=name, metadata={"files": files}) for name, files in VARIANTS.items()]


@ob.setup_task
async def setup(task, session):
    for name in task.metadata["files"]:
        await session.write_file(name, "x\n")


@ob.orcel_plan
def plan(task, orcel):
    found = orcel.call("fs.find", "find", ".", {"pattern": "*.csv", "max_results": 100, "max_depth": 8})
    return sorted(match["path"] for match in found["matches"] if match["kind"] == "file")


@ob.evaluate_task
async def evaluate(task, session):
    return session.answer == sorted(name for name in task.metadata["files"] if name.endswith(".csv"))
