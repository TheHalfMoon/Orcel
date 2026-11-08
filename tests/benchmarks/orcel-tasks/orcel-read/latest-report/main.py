"""Orcel task (BM-02 Tier A, read-only): find the latest dated report in inbox/ by listing it through Orcel.

Orcel-owned. The planner observes only through Orcel (`orcel.call`); the
workspace must be unchanged afterwards.
"""

import orcel_bench as ob

VARIANTS = {
    "three": ["2026-07-31", "2026-09-30", "2026-08-31"],
    "one": ["2026-10-15"],
    "five": ["2025-12-31", "2026-03-31", "2026-06-30", "2026-01-31", "2026-02-28"],
}


@ob.tasks_config
def load():
    return [
        ob.Task(description="Name the latest dated report in inbox/.", task_id=name, metadata={"dates": dates})
        for name, dates in VARIANTS.items()
    ]


@ob.setup_task
async def setup(task, session):
    for date in task.metadata["dates"]:
        await session.write_file(f"inbox/report-{date}.txt", f"report for {date}\n")
    await session.write_file("inbox/notes.txt", "not a report\n")


@ob.orcel_plan
def plan(task, orcel):
    listing = orcel.call("fs.list", "list", "inbox")
    names = [entry["name"] for entry in listing["entries"] if entry["is_file"] and entry["name"].startswith("report-")]
    return max(names)


@ob.evaluate_task
async def evaluate(task, session):
    return session.answer == f"report-{max(task.metadata['dates'])}.txt"
