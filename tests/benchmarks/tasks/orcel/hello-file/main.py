"""Orcel task: write a given word into answer.txt.

Orcel-owned, modelled on cua-bench's `example_tasks/hello_file_env` (MIT;
see ../../../LICENSE-cua-bench.txt) without its shell commands.
"""

import orcel_bench as ob

WORDS = ["hello", "bench"]


@ob.tasks_config
def load():
    return [
        ob.Task(
            description=f"Write the word '{word}' into answer.txt.",
            task_id=word,
            metadata={"word": word},
        )
        for word in WORDS
    ]


@ob.setup_task
async def setup(task, session):
    await session.remove("answer.txt")
    await session.write_file("goal.txt", task.metadata["word"])


@ob.solve_task
async def solve(task, session):
    await session.write_file("answer.txt", await session.read_file("goal.txt"))


@ob.evaluate_task
async def evaluate(task, session):
    if not await session.file_exists("answer.txt"):
        return [0.0]
    answer = (await session.read_file("answer.txt")).strip()
    return [1.0 if answer == task.metadata["word"] else 0.0]
