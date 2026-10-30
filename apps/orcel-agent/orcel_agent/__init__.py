"""Orcel Agent: a planner package that is an MCP client of the Orcel edge
only. See `docs/orcel/implementation-readiness/prep/DEERFLOW_ORCEL_AGENT_MASTER_PLAN.md`
and, for M2 and M3, `prep/SG-000129.md`.

The agent's own modules import the standard library only. SG-000129 slice 1
admits a hash-locked LangChain and LangGraph set (`requirements.lock`) that
later slices import by name; tracing is switched off here, before any of it
can be imported.
"""

from .quiet import silence_tracing

silence_tracing()
