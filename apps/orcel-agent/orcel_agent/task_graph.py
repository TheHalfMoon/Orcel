"""Task decomposition structure for the Orcel orchestrator (W2-02).

Adapted from simular-ai/Agent-S at commit
0fff0e634869dab72027435b4586e62300185d41 (Apache-2.0, Copyright Simular AI;
see docs/orcel/notices/agent-s-Apache-2.0.txt and
docs/orcel/agent_s_provenance.json):
- gui_agents/s2/utils/common_utils.py: `Node`, `Dag` and `parse_dag` (the
  <json>...</json> extraction with the ```json fence fallback).
- gui_agents/s2/agents/manager.py: `_topological_sort` (depth-first) and
  `format_subtask_list`, and the three planner messages (initial plan,
  revision after a completed subtask, re-plan after a failed subtask).
- gui_agents/s2/memory/procedural_memory.py: DAG_TRANSLATOR_PROMPT, renamed
  for Orcel; its JSON shape is unchanged.

Modifications for Orcel: standard library dataclasses instead of pydantic;
`parse_dag` returns None instead of printing, and bounds the graph (at most
MAX_NODES nodes, names and info capped); the topological sort refuses a
cycle, a duplicate name or an edge to an unknown node instead of raising
KeyError or silently accepting it; cost and token accounting, logging and
retrieval are removed. A plan is the model's proposal, built from untrusted
observations: it authorizes nothing, and every action it leads to is still
dispatched through orceld.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Optional, Sequence

#: Orcel bounds on a model-written graph.
MAX_NODES = 16
MAX_NAME_CHARS = 120
MAX_INFO_CHARS = 1000


@dataclass(frozen=True)
class Node:
    """One subtask: a short name and the detail needed to carry it out."""

    name: str
    info: str


@dataclass(frozen=True)
class Dag:
    nodes: tuple[Node, ...]
    edges: tuple[tuple[Node, Node], ...]


# Agent-S DAG_TRANSLATOR_PROMPT, renamed for Orcel (the JSON shape is
# unchanged; guideline 1 of the original names a "plan" field that its own
# schema does not have and is dropped).
DAG_TRANSLATOR_PROMPT = """You are a plan to Dependency Graph conversion agent for Orcel. Your task is to analyze a given plan and generate a structured JSON output representing the plan and its corresponding directed acyclic graph (DAG).

The output should be a valid JSON object wrapped in <json></json> tags, with the following structure:

<json>
{
  "dag": {
    "nodes": [
      {
        "name": "Short name or brief description of the step",
        "info": "Detailed information about executing this step"
      }
    ],
    "edges": [
      [
        {"name": "Name of the source node", "info": "Info of the source node"},
        {"name": "Name of the target node", "info": "Info of the target node"}
      ]
    ]
  }
}
</json>

Important guidelines you must follow:
1. In the "dag" object:
   a. Each node in the "nodes" array should contain 'name' and 'info' fields.
   b. 'name' should be a concise, one-line description of the subtask.
   c. 'info' should contain all available information about executing that subtask from the original plan. Do not remove or edit any information from the 'info' field.
2. The "edges" array should represent the connections between nodes, showing the order and dependencies of the steps.
3. If the plan only has one subtask, you MUST construct a graph with a SINGLE node. The "nodes" array should have that single subtask as a node, and the "edges" array should be empty.
4. The graph must be a directed acyclic graph (DAG) and must be connected.
5. Do not include completed subtasks in the graph. A completed subtask must not be included in a node or an edge.
6. Do not include repeated or optional steps in the graph. Any extra information should be incorporated into the 'info' field of the relevant node.
7. It is okay for the graph to have a single node and no edges, if the provided plan only has one subtask.

Analyze the given plan and provide the output in this JSON format within the <json></json> tags. Ensure the JSON is valid and properly escaped.
"""


def _extract(pattern: str, text: str) -> Optional[str]:
    match = re.search(pattern, text, re.DOTALL)
    return match.group(1).strip() if match else None


def _node(raw: Any) -> Optional[Node]:
    if not isinstance(raw, dict):
        return None
    name, info = raw.get("name"), raw.get("info", "")
    if not isinstance(name, str) or not isinstance(info, str) or not name.strip():
        return None
    return Node(name.strip()[:MAX_NAME_CHARS], info.strip()[:MAX_INFO_CHARS])


def parse_dag(text: str) -> Optional[Dag]:
    """Agent-S `parse_dag`: JSON from <json>...</json> first, else from a
    ```json fence. Returns None for anything malformed or over the bounds;
    an empty graph (no nodes) is valid and means "nothing left to do", which
    the orchestrator treats as a completion claim to verify."""
    if not isinstance(text, str):
        return None
    json_str = _extract(r"<json>(.*?)</json>", text)
    if json_str is None:
        json_str = _extract(r"```json\s*(.*?)\s*```", text)
    if json_str is None:
        return None
    try:
        payload = json.loads(json_str)
    except (json.JSONDecodeError, RecursionError):
        return None
    dag = payload.get("dag") if isinstance(payload, dict) else None
    if not isinstance(dag, dict):
        return None
    raw_nodes, raw_edges = dag.get("nodes", []), dag.get("edges", [])
    if not isinstance(raw_nodes, list) or not isinstance(raw_edges, list) or len(raw_nodes) > MAX_NODES:
        return None
    nodes = [_node(raw) for raw in raw_nodes]
    if any(node is None for node in nodes):
        return None
    edges: list[tuple[Node, Node]] = []
    for raw in raw_edges:
        if not isinstance(raw, list) or len(raw) != 2:
            return None
        source, target = _node(raw[0]), _node(raw[1])
        if source is None or target is None:
            return None
        edges.append((source, target))
    return Dag(tuple(n for n in nodes if n is not None), tuple(edges))


class GraphError(ValueError):
    """The model's graph is not a usable DAG."""


def topological_sort(dag: Dag) -> list[Node]:
    """Agent-S `Manager._topological_sort` (depth-first, reverse post-order),
    with Orcel's refusals: duplicate node names, edges naming an unknown
    node and cycles raise GraphError. Edges are matched by node name, as in
    the original."""
    names = [node.name for node in dag.nodes]
    if len(set(names)) != len(names):
        raise GraphError("duplicate subtask names")
    adjacency: dict[str, list[str]] = {name: [] for name in names}
    for source, target in dag.edges:
        if source.name not in adjacency or target.name not in adjacency:
            raise GraphError("an edge names an unknown subtask")
        adjacency[source.name].append(target.name)

    WHITE, GREY, BLACK = 0, 1, 2
    colour = {name: WHITE for name in names}
    stack: list[str] = []

    def dfs(name: str) -> None:
        colour[name] = GREY
        for neighbour in adjacency[name]:
            if colour[neighbour] == GREY:
                raise GraphError("the plan has a cycle")
            if colour[neighbour] == WHITE:
                dfs(neighbour)
        colour[name] = BLACK
        stack.append(name)

    for name in names:
        if colour[name] == WHITE:
            dfs(name)
    by_name = {node.name: node for node in dag.nodes}
    return [by_name[name] for name in reversed(stack)]


def format_subtask_list(subtasks: Sequence[Node]) -> str:
    """Agent-S `format_subtask_list`: a numbered list, one bullet per
    sentence of each subtask's info."""
    res = ""
    for idx, node in enumerate(subtasks):
        res += f"{idx + 1}. **{node.name}**:\n"
        for bullet in re.split(r"(?<=[.!?;]) +", node.info):
            res += f"   - {bullet}\n"
        res += "\n"
    return res


def planner_message(failed: Optional[Node], completed: Sequence[Node], remaining: Sequence[Node]) -> str:
    """Agent-S `Manager._generate_step_by_step_plan`'s three cases, in its
    order: re-plan after a failure, revise after progress, initial plan."""
    if failed is not None:
        return (
            f"The subtask {failed.name} cannot be completed. Please generate a new plan for the remainder of the trajectory.\n\n"
            f"Successfully Completed Subtasks:\n{format_subtask_list(completed)}\n"
        )
    if len(completed) + len(remaining) > 0:
        return (
            "The current trajectory and desktop state is provided. Please revise the plan for the following trajectory.\n\n"
            f"Successfully Completed Subtasks:\n{format_subtask_list(completed)}\n"
            f"Future Remaining Subtasks:\n{format_subtask_list(remaining)}\n"
        )
    return "Please generate the initial plan for the task.\n"
