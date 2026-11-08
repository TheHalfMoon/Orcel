"""Orcel task (BM-02 Tier A, read-only): name the largest file in data/ from Orcel's list and stat.

Orcel-owned. The planner observes only through Orcel (`orcel.call`); the
workspace must be unchanged afterwards.
"""

import orcel_bench as ob

VARIANTS = {"small": [3, 9, 5], "tie-free": [120, 4096, 2048, 64], "single": [42]}


@ob.tasks_config
def load():
    return [ob.Task(description="Which file in data/ is largest?", task_id=name, metadata={"sizes": sizes}) for name, sizes in VARIANTS.items()]


@ob.setup_task
async def setup(task, session):
    for index, size in enumerate(task.metadata["sizes"]):
        await session.write_file(f"data/file-{index}.bin", "z" * size)


@ob.orcel_plan
def plan(task, orcel):
    entries = orcel.call("fs.list", "list", "data")["entries"]
    sizes = {entry["name"]: orcel.call("fs.stat", "stat", f"data/{entry['name']}")["size"] for entry in entries if entry["is_file"]}
    return max(sizes, key=sizes.get)


@ob.evaluate_task
async def evaluate(task, session):
    sizes = task.metadata["sizes"]
    return session.answer == f"file-{sizes.index(max(sizes))}.bin"
