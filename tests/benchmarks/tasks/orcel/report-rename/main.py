"""Orcel task: file the latest dated report under its canonical name.

Orcel-owned. The workspace holds several dated reports in inbox/; the
latest one must end up as reports/latest.txt, byte for byte, with the
others left where they are. This mirrors the shape of Orcel's own report
journey (find the latest, move it, change nothing else) on plain files.
"""

import orcel_bench as ob

VARIANTS = {
    "three": ["2026-07-31", "2026-09-30", "2026-08-31"],
    "one": ["2026-10-15"],
}


@ob.tasks_config
def load():
    return [
        ob.Task(
            description="Move the latest dated report in inbox/ to reports/latest.txt.",
            task_id=name,
            metadata={"dates": dates},
        )
        for name, dates in VARIANTS.items()
    ]


@ob.setup_task
async def setup(task, session):
    for date in task.metadata["dates"]:
        await session.write_file(f"inbox/report-{date}.txt", f"report for {date}\n")


@ob.solve_task
async def solve(task, session):
    latest = max(name for name in await session.list_files() if name.startswith("inbox/report-"))
    await session.rename(latest, "reports/latest.txt")


@ob.evaluate_task
async def evaluate(task, session):
    dates = sorted(task.metadata["dates"])
    expected = {f"inbox/report-{date}.txt" for date in dates[:-1]} | {"reports/latest.txt"}
    if set(await session.list_files()) != expected:
        return [0.0]
    content = await session.read_file("reports/latest.txt")
    return [1.0 if content == f"report for {dates[-1]}\n" else 0.0]
