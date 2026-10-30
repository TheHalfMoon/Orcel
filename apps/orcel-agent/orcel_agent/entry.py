"""SG-000129 slice 2: the one way to build an agent for a chat-model planner.

The `Agent` class takes any allowlist, so its unit tests can exercise
mutating tools against a fake edge. A chat model may propose anything, so
an agent built for one must keep the M1 read-only allowlist or a subset of
it: until a read-only lease-state signal exists, a mutating tool could act
unattended under a Full User lease (SG-000129 packet, T6).
"""

from __future__ import annotations

from typing import Any, Optional

from .agent import READ_ONLY_TOOLS, Agent, ToolSource
from .events import EventLog
from .journal import DispatchJournal
from .store import RunStore


class AllowlistTooWide(ValueError):
    """An allowlist names a tool outside the M1 read-only set."""


def chat_agent(edge: ToolSource, journal: DispatchJournal, events: EventLog, store: Optional[RunStore] = None,
               allowlist: frozenset[str] = READ_ONLY_TOOLS, **options: Any) -> Agent:
    extra = set(allowlist) - READ_ONLY_TOOLS
    if extra:
        raise AllowlistTooWide(f"not read-only: {sorted(extra)}")
    return Agent(edge, journal, events, store=store, allowlist=frozenset(allowlist), **options)
