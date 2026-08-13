"""A run: one trip through the pipeline, recorded stage by stage.

Every stage the runner completes appends an event *and* stores its full output. The two
are not redundant. Events are ordered and cheap, and are what Phase 5b streams over SSE
so a visitor watches counterfactuals being tested rather than a spinner; the stored
stage outputs are what the console reads back when it needs the whole object. Building
both now means the streaming transport is a transport, not a redesign.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections import OrderedDict
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from aegis.api.scenarios import Scenario

if TYPE_CHECKING:
    from aegis.attribution.models import AttributionResult
    from aegis.log.log import Receipt
    from aegis.provenance.models import ContextTrace

RunStatus = str  # "running" | "complete" | "failed"


@dataclass
class RunEvent:
    seq: int
    type: str
    at: str
    data: dict


@dataclass
class Evidence:
    """The live objects a run produced, kept because two consumers re-derive from them.

    ``stages`` already holds a *serialized* view of all of this, and that view is what the
    console reads. It is deliberately not what these consumers get. Attacks re-issue a
    warrant over the same measurement, and replay re-runs the measurement itself, so both
    need the objects the issuer and the engine actually accept -- reconstructing an
    ``AttributionResult`` by parsing its own summary back out of JSON would mean the attack
    path and the honest path no longer share a representation, which is exactly the drift
    ``runner`` exists to prevent.

    Retained per run, so the ceiling is ``max_sessions x max_runs_per_session``. A trace and
    an attribution result are small next to the event log those same bounds already permit
    (see ``config.session_model_call_budget``), so this widens an existing bound rather than
    introducing a new one.
    """

    body: dict
    trace: ContextTrace
    attribution: AttributionResult
    arguments: dict
    receipt: Receipt | None = None
    """Present once the warrant reached the log. Absent runs cannot be attacked."""


@dataclass
class Run:
    run_id: str
    session_id: str
    scenario: Scenario
    created_at: str
    status: RunStatus = "running"
    error: str | None = None
    events: list[RunEvent] = field(default_factory=list)
    stages: dict[str, Any] = field(default_factory=dict)

    leaf_index: int | None = None
    """Where this run's warrant landed in the shared log, once it was published."""

    artifacts: dict | None = None
    """The auditor bundle, pinned on first request. See ``app.artifact_bundle``."""

    evidence: Evidence | None = None
    """What the attack and replay endpoints re-derive from. Absent until attribution ran."""

    task: asyncio.Task | None = None
    """The background task executing this run, held so the event loop cannot collect it."""

    model_calls: int = 0
    """Ablations issued so far, counted live rather than read off the final result.

    The session budget needs a number that exists *during* a run, not only after one.
    """

    _waiters: list[asyncio.Event] = field(default_factory=list, repr=False)

    def emit(self, type_: str, data: dict) -> RunEvent:
        event = RunEvent(
            seq=len(self.events),
            type=type_,
            at=datetime.now(UTC).isoformat(),
            data=data,
        )
        self.events.append(event)
        for waiter in self._waiters:
            waiter.set()
        return event

    @contextlib.contextmanager
    def subscribe(self) -> Iterator[asyncio.Event]:
        """One private wake-up flag per stream, removed when the stream ends.

        Per subscriber rather than one shared ``Event`` because a shared flag has to be
        cleared before waiting, and whichever consumer clears it can swallow a
        notification another consumer had not yet seen. Two people watching the same run
        is not an edge case here -- it is a second browser tab.
        """
        waiter = asyncio.Event()
        self._waiters.append(waiter)
        try:
            yield waiter
        finally:
            self._waiters.remove(waiter)

    def stage(self, name: str, payload: Any) -> None:
        self.stages[name] = payload

    def summary(self) -> dict:
        return {
            "run_id": self.run_id,
            "session_id": self.session_id,
            "scenario": self.scenario.name,
            "labelled": self.scenario.labelled,
            "created_at": self.created_at,
            "status": self.status,
            "error": self.error,
            "events": len(self.events),
            "stages": sorted(self.stages),
            "leaf_index": self.leaf_index,
            "model_calls": self.model_calls,
        }

    def as_dict(self) -> dict:
        return {
            **self.summary(),
            "event_log": [
                {"seq": e.seq, "type": e.type, "at": e.at, "data": e.data} for e in self.events
            ],
        }


class RunStore:
    """Per-session, bounded, oldest-evicted.

    A run holds a full context trace and an attribution result, so this is the largest
    thing a visitor can cause the process to retain. The cap is per session rather than
    global so one visitor cannot evict another's history.
    """

    def __init__(self, limit: int) -> None:
        self.limit = limit
        self._runs: OrderedDict[str, Run] = OrderedDict()

    def __len__(self) -> int:
        return len(self._runs)

    def add(self, run: Run) -> None:
        self._runs[run.run_id] = run
        while len(self._runs) > self.limit:
            self._runs.popitem(last=False)

    def get(self, run_id: str) -> Run | None:
        return self._runs.get(run_id)

    def recent(self) -> list[Run]:
        return list(reversed(self._runs.values()))
