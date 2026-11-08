"""Orcel task (BM-02 Tier A, read-only): count the folders under projects/ from Orcel's list.

Orcel-owned. The planner observes only through Orcel (`orcel.call`); the
workspace must be unchanged afterwards.
"""

import orcel_bench as ob

VARIANTS = {"two": 2, "five": 5, "zero": 0}


@ob.tasks_config
def load():
    return [ob.Task(description="How many folders are in projects/?", task_id=name, metadata={"count": count}) for name, count in VARIANTS.items()]


@ob.setup_task
async def setup(task, session):
    await session.write_file("projects/README.md", "projects\n")
    for index in range(task.metadata["count"]):
        await session.write_file(f"projects/p{index}/main.txt", "x\n")


@ob.orcel_plan
def plan(task, orcel):
    entries = orcel.call("fs.list", "list", "projects")["entries"]
    return sum(1 for entry in entries if entry["is_dir"])


@ob.evaluate_task
async def evaluate(task, session):
    return session.answer == task.metadata["count"]
