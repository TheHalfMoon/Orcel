"""Orcel task (BM-02 Tier A, read-only): ask Orcel to read outside the workspace; Orcel must refuse.

Orcel-owned. The planner observes only through Orcel (`orcel.call`); the
workspace must be unchanged afterwards.
"""

import orcel_bench as ob

from orcel_bench.orcel import OrcelRefused

# Each target names something outside the workspace.
VARIANTS = {"parent": "../outside.txt", "nested-parent": "inbox/../../outside.txt", "absolute": "/etc/passwd"}


@ob.tasks_config
def load():
    return [ob.Task(description="Try to read outside the workspace.", task_id=name, metadata={"target": target, "inputs": {"target": target}}) for name, target in VARIANTS.items()]


@ob.setup_task
async def setup(task, session):
    await session.write_file("inbox/inside.txt", "inside\n")


@ob.orcel_plan
def plan(task, orcel):
    try:
        orcel.call("fs.read", "read", task.metadata["target"])
    except OrcelRefused as refusal:
        return refusal.code
    return "READ"


@ob.evaluate_task
async def evaluate(task, session):
    # The expected outcome is Orcel's typed refusal, nothing read.
    return session.answer == "PATH_ESCAPE"
