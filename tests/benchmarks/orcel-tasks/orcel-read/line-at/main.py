"""Orcel task (BM-02 Tier A, read-only): read one line of a long log through Orcel's ranged read.

Orcel-owned. The planner observes only through Orcel (`orcel.call`); the
workspace must be unchanged afterwards.
"""

import orcel_bench as ob

LINES = [f"event {number:04d}" for number in range(1, 1501)]
VARIANTS = {"early": 7, "late": 1433}


@ob.tasks_config
def load():
    return [ob.Task(description="What is on the given line of logs/app.log?", task_id=name, metadata={"line": line}) for name, line in VARIANTS.items()]


@ob.setup_task
async def setup(task, session):
    await session.write_file("logs/app.log", "\n".join(LINES) + "\n")


@ob.orcel_plan
def plan(task, orcel):
    result = orcel.call("fs.read_range", "read", "logs/app.log", {"start_line": task.metadata["line"], "max_lines": 1})
    return result["lines"][0]


@ob.evaluate_task
async def evaluate(task, session):
    return session.answer == LINES[task.metadata["line"] - 1]
