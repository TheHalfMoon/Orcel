"""SG-000129 slice 2: the one way to build an agent for a chat-model planner.

The `Agent` class takes any allowlist, so its unit tests can exercise
mutating tools against a fake edge. A chat model may propose anything, so
an agent built for one must keep the M1 read-only allowlist or a subset of
it: until a read-only lease-state signal exists, a mutating tool could act
unattended under a Full User lease (SG-000129 packet, T6).
"""

from __future__ import annotations

from typing import Optional

from .agent import READ_ONLY_TOOLS, Agent, ToolSource
from .events import EventLog
from .journal import DispatchJournal
from .store import RunStore


class AllowlistTooWide(ValueError):
    """An allowlist names a tool outside the M1 read-only set."""


def chat_agent(edge: ToolSource, journal: DispatchJournal, events: EventLog, store: Optional[RunStore] = None,
               allowlist: frozenset[str] = READ_ONLY_TOOLS, *, keep_store: bool = False, max_steps: int = 32,
               max_approval_requests: int = 3) -> Agent:
    """Only the listed options; no pass-through. The agent it returns is
    read-only in its gate as well (`_read_only_only`), and ChatModelPlanner
    refuses any non-read-only tool on its own."""
    extra = set(allowlist) - READ_ONLY_TOOLS
    if extra:
        raise AllowlistTooWide(f"not read-only: {sorted(extra)}")
    return Agent(edge, journal, events, store=store, keep_store=keep_store, allowlist=frozenset(allowlist),
                 max_steps=max_steps, max_approval_requests=max_approval_requests, _read_only_only=True)
