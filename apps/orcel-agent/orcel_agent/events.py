"""Run and step events shaped like the adopted CR-02 AgentKit contract
(`AGENT_RUNTIME_INTEGRATION.md` section 3.1): `{seq, run_id, step_id, kind,
at, data}`, append-only, with contiguous sequence numbers. Events describe
what happened; they never carry or answer an approval, and never carry file
content or tool results (only tool names, outcomes and error codes).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class EventLog:
    run_id: str
    events: list[dict[str, Any]] = field(default_factory=list)

    def emit(self, kind: str, step_id: Optional[str] = None, **data: Any) -> None:
        self.events.append(
            {
                "seq": len(self.events) + 1,
                "run_id": self.run_id,
                "step_id": step_id,
                "kind": kind,
                "at": round(time.time(), 3),
                "data": data,
            }
        )
