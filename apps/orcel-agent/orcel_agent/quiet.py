"""SG-000129 slice 1: tracing and telemetry off before any LangChain import.

`langchain-core` imports `langsmith`, which traces to a remote endpoint when
its environment asks it to, and OpenTelemetry exporters read `OTEL_*`. The
agent opens no socket (orceld and the edge are its only peers), so every
variable in those namespaces is removed and the off switches are set, whatever
the caller's environment says. `orcel_agent/__init__.py` calls this first, so
importing the package is enough. The egress tests, not this module, are the
guard: they deny connections and name lookups at the interpreter.
"""

from __future__ import annotations

import os
import sys

#: Every variable in these namespaces is removed: endpoints, keys, projects,
#: profiles, sampling and the tracing switches themselves.
CLEARED_PREFIXES = ("LANGSMITH_", "LANGCHAIN_", "OTEL_")

#: Then the off switches, in every spelling `langsmith` and OpenTelemetry read.
TRACING_OFF = {
    "LANGSMITH_TRACING": "false",
    "LANGSMITH_TRACING_V2": "false",
    "LANGCHAIN_TRACING": "false",
    "LANGCHAIN_TRACING_V2": "false",
    "LANGSMITH_OTEL_ENABLED": "false",
    "LANGSMITH_TEST_TRACKING": "false",
    "OTEL_SDK_DISABLED": "true",
    "OTEL_TRACES_EXPORTER": "none",
    "OTEL_METRICS_EXPORTER": "none",
    "OTEL_LOGS_EXPORTER": "none",
}


class TracingAlreadyImported(RuntimeError):
    """langsmith was imported first; it caches its environment, so switching
    tracing off now would have no effect."""


def silence_tracing() -> None:
    """Remove every tracing variable, then set the off switches. Refuses if
    langsmith is already imported, since it would keep its cached settings."""
    if "langsmith" in sys.modules:
        raise TracingAlreadyImported("import orcel_agent before anything that imports langsmith")
    for name in list(os.environ):
        if name.upper().startswith(CLEARED_PREFIXES):
            del os.environ[name]
    os.environ.update(TRACING_OFF)
