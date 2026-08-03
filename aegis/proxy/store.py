"""In-memory trace store.

Deliberately not Postgres yet. Phase 2 will show what the attribution engine actually needs
to read, and designing the schema before that is guessing. The interface here is the one
a Postgres-backed implementation will satisfy.
"""

from __future__ import annotations

from collections import OrderedDict

from aegis.provenance.models import ContextTrace


class TraceStore:
    """Bounded, insertion-ordered store of context traces."""

    def __init__(self, max_traces: int = 1000) -> None:
        self._traces: OrderedDict[str, ContextTrace] = OrderedDict()
        self._max = max_traces

    def put(self, trace: ContextTrace) -> None:
        self._traces[trace.trace_id] = trace
        while len(self._traces) > self._max:
            self._traces.popitem(last=False)

    def get(self, trace_id: str) -> ContextTrace | None:
        return self._traces.get(trace_id)

    def recent(self, limit: int = 20) -> list[ContextTrace]:
        return list(reversed(list(self._traces.values())[-limit:]))

    def __len__(self) -> int:
        return len(self._traces)
