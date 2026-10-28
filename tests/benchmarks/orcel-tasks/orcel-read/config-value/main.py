"""Orcel task (BM-02 Tier A, read-only): read one key from a settings file through Orcel.

Orcel-owned. The planner observes only through Orcel (`orcel.call`); the
workspace must be unchanged afterwards.
"""

import orcel_bench as ob

SETTINGS = "# app settings\nport = 8417\nmode = offline\nowner = ops-team\n"
VARIANTS = {"port": "8417", "mode": "offline", "owner": "ops-team"}


@ob.tasks_config
def load():
    return [ob.Task(description=f"What is {key} in config/app.ini?", task_id=key, metadata={"key": key}) for key in VARIANTS]


@ob.setup_task
async def setup(task, session):
    await session.write_file("config/app.ini", SETTINGS)


@ob.orcel_plan
def plan(task, orcel):
    text = orcel.call("fs.read", "read", "config/app.ini")["text"]
    for line in text.splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            key, value = (part.strip() for part in line.split("=", 1))
            if key == task.metadata["key"]:
                return value
    return None


@ob.evaluate_task
async def evaluate(task, session):
    return session.answer == VARIANTS[task.metadata["key"]]
