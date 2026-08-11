"""The controls that opening this to strangers requires.

Opening the API to the public re-instantiates **threat T12** from our own threat model:
denial of service via attribution cost. Ablation is O(segments) model calls, so submitted
context is a cost amplifier and a visitor is a cost amplifier they brought themselves.

Two rules govern everything here.

**Use the control the design already specifies.** The per-attribution ceiling is control
C-18, which lives in ``AttributionEngine.max_model_calls`` and predates this API. What is
added is the aggregate above it -- a per-session budget and a per-IP arrival rate -- not a
second, parallel notion of "too much" invented for the web tier.

**Say which control refused.** A limit that names itself is a demonstration of the threat
model; a bare 429 is a workaround for it. Every refusal below carries the control's
identifier into the response body, and the console is expected to show it.

The limiter is itself keyed on attacker-controlled input, which makes it an exhaustion
primitive if left unbounded -- so the client table is capped and evicted oldest-first. A
rate limiter that can be made to run the host out of memory has not limited anything.
"""

from __future__ import annotations

import time
from collections import OrderedDict, deque
from dataclasses import dataclass

from fastapi import HTTPException, Request

from aegis.api.config import ApiSettings


@dataclass(frozen=True)
class Control:
    """One named limit, so a refusal can point at the thing that refused."""

    id: str
    name: str
    origin: str
    """Where the control comes from: the threat model, or this API's deployment."""


C18 = Control(
    id="C-18",
    name="attribution call ceiling",
    origin="docs/THREAT_MODEL.md, mitigating T12; enforced in AttributionEngine",
)
SESSION_BUDGET = Control(
    id="C-18/session",
    name="per-session attribution budget",
    origin="aggregate of C-18 across one visitor, added for the public API",
)
ARRIVAL_RATE = Control(
    id="API-RATE",
    name="per-client arrival rate",
    origin="added for the public API",
)
REQUEST_SIZE = Control(
    id="API-SIZE",
    name="request body ceiling",
    origin="added for the public API",
)
CONTEXT_SIZE = Control(
    id="API-CONTEXT",
    name="submitted context ceiling",
    origin="added for the public API; bounds the segments C-18 then has to ablate",
)
CONCURRENCY = Control(
    id="API-CONC",
    name="concurrent attribution ceiling",
    origin="added for the public API",
)
STREAMS = Control(
    id="API-STREAMS",
    name="concurrent event streams per session",
    origin="added for the public API",
)


def refuse(control: Control, status: int, detail: str) -> HTTPException:
    """Build a refusal that names the control doing the refusing."""
    return HTTPException(
        status_code=status,
        detail={
            "control": control.id,
            "control_name": control.name,
            "origin": control.origin,
            "detail": detail,
            "threat": (
                "T12 — denial of service via attribution cost. Ablation is O(segments) "
                "model calls per action, so this limit is the design working, not a "
                "workaround for it."
            ),
        },
    )


def client_key(request: Request, settings: ApiSettings) -> str:
    """Identify the caller for rate limiting.

    ``X-Forwarded-For`` is honoured **only** when the deployment says it is behind a proxy
    it trusts. Reading it unconditionally would let any caller pick their own rate-limit
    bucket by sending a header, which is worse than having no limiter: it looks like one.
    """
    if settings.trust_forwarded_for:
        forwarded = request.headers.get("x-forwarded-for", "")
        first = forwarded.split(",")[0].strip()
        if first:
            return first
    return request.client.host if request.client else "unknown"


class ArrivalLimiter:
    """Sliding-window arrival rate per client, over a bounded client table."""

    def __init__(self, settings: ApiSettings) -> None:
        self.settings = settings
        self._windows: OrderedDict[str, deque[float]] = OrderedDict()

    def __len__(self) -> int:
        return len(self._windows)

    def window_size(self, key: str) -> int:
        """Arrivals currently counted against ``key``. Exposed so tests can assert that a
        rejected attempt did not push the window forward."""
        return len(self._windows.get(key, ()))

    def check(self, key: str, limit: int, window_seconds: float = 60.0) -> int:
        """Record an arrival and return remaining allowance, or raise.

        Raises before recording, so a client that is already over the limit does not push
        its own window forward with every rejected attempt and extend its own penalty
        indefinitely.
        """
        now = time.monotonic()
        window = self._windows.get(key)
        if window is None:
            window = deque()
            self._windows[key] = window

        self._windows.move_to_end(key)
        while window and now - window[0] > window_seconds:
            window.popleft()

        if len(window) >= limit:
            retry_after = int(window_seconds - (now - window[0])) + 1
            raise refuse(
                ARRIVAL_RATE,
                429,
                f"{limit} per {int(window_seconds)}s exceeded; retry in {retry_after}s",
            )

        window.append(now)
        self._evict()
        return limit - len(window)

    def _evict(self) -> None:
        while len(self._windows) > self.settings.max_tracked_clients:
            self._windows.popitem(last=False)


def check_session_budget(spent: int, settings: ApiSettings) -> None:
    """Refuse a new run once the visitor has spent their attribution budget.

    Checked at admission rather than mid-run. The overshoot is therefore bounded by one
    run's worth of C-18 -- which is the honest description, and better than the
    alternative of aborting an attribution halfway and issuing a warrant over partial
    evidence.
    """
    if spent >= settings.session_model_call_budget:
        raise refuse(
            SESSION_BUDGET,
            429,
            (
                f"this session has spent {spent} model calls of "
                f"{settings.session_model_call_budget}. Start a new session for a fresh "
                "budget; each run costs one call per context segment ablated."
            ),
        )
