"""aegis-api — the HTTP surface that makes the whole pipeline drivable.

Phase 5a: sessions, scenarios, runs, the shared transparency log, and the three files an
auditor needs. Phase 5b adds the SSE transport over the events every run already records,
plus the abuse controls that opening this to strangers requires.

**Sessions travel in a header, not a cookie.** ``X-Aegis-Session`` is read by the client
and sent deliberately, so there is no ambient authority for another origin to ride: this
service has no CSRF surface because it has nothing a browser will attach automatically.

**Nothing here renders a mock.** Every field a caller receives is produced by ``aegis``
executing -- classification by the classifier, attribution by the engine, signatures by
the issuer, proofs by the log. Where a stage did not run, the response says so and the
field is absent. On a project about verifiable evidence, a plausible placeholder is not
a placeholder, it is a counterexample.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

from aegis import __version__
from aegis.api import attacks, runner
from aegis.api.config import ApiSettings
from aegis.api.config import settings as default_settings
from aegis.api.limits import (
    CONTEXT_SIZE,
    REQUEST_SIZE,
    STREAMS,
    ArrivalLimiter,
    check_session_budget,
    client_key,
    refuse,
)
from aegis.api.runs import Run, RunEvent
from aegis.api.scenarios import Scenario, catalogue, custom_scenario
from aegis.api.session import Session, SessionStore
from aegis.attribution.client import InProcessMockClient
from aegis.audit.replay import replay_attribution
from aegis.common.ids import prefixed_id
from aegis.evaluation.harness import FLAG_THRESHOLD, run_evaluation
from aegis.log.log import Receipt, TransparencyLog, encode_hash
from aegis.log.storage import SqliteLogStorage
from aegis.warrant.keys import SigningKey

SESSION_HEADER = "X-Aegis-Session"

ARTIFACT_FILES = ("warrant", "receipt", "trust_anchors")


class RunRequest(BaseModel):
    scenario: str = Field(default="injection_via_conduit_tool")
    """A preset name, or ``custom`` to run the document in ``injection``."""

    injection: str = ""
    """Visitor-authored text for the conduit tool's document. Only read for ``custom``."""


def create_app(
    config: ApiSettings | None = None,
    log: TransparencyLog | None = None,
) -> FastAPI:
    """Build the API.

    ``log`` is injectable so tests can hand in a log with a known backing rather than
    reaching into app state, and so a deployment can supply a durable one.
    """
    config = config or default_settings
    app = FastAPI(title="aegis-api", version=__version__)
    app.state.settings = config
    # ``is None``, never ``or``. TransparencyLog defines __len__, so an empty log is
    # falsy -- and an empty log is exactly what a cold start hands in. Written as
    # ``log or _build_log(config)`` this discarded the durable log on every restart and
    # served an in-memory one, which is the single failure a durable log exists to prevent.
    app.state.log = _build_log(config) if log is None else log
    app.state.log_lock = asyncio.Lock()
    app.state.sessions = SessionStore(config)
    app.state.arrivals = ArrivalLimiter(config)
    app.state.attribution_slots = asyncio.Semaphore(config.max_concurrent_attributions)
    app.middleware("http")(_limit_request_size)
    _add_cors(app, config)
    app.include_router(_router())
    return app


def _add_cors(app: FastAPI, config: ApiSettings) -> None:
    """Let the console's origin call this API, and nothing else.

    Added *after* the size middleware so it sits outside it. Order matters twice: a
    preflight carries no body and must not be size-checked, and a 413 that comes back
    without CORS headers is opaque to the browser -- the console would show a network
    error where the whole point of that refusal is to name the control that refused.

    ``allow_credentials`` stays False. Sessions travel in ``X-Aegis-Session`` because the
    caller chooses to send them, which is what leaves this service with no CSRF surface
    rather than a defended one; enabling credentials here would quietly hand that back.
    """
    origins = config.cors_origin_list
    if not origins:
        return
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=[SESSION_HEADER, "Content-Type", "Last-Event-ID"],
        # The console offers the auditor files as downloads and names them from this
        # header; without exposing it, fetch() can read the body but not the filename.
        expose_headers=["Content-Disposition"],
    )


async def _limit_request_size(request: Request, call_next):
    """Refuse oversized bodies before anything reads them.

    Checked at the middleware rather than per route because the field-level cap in
    ``_resolve_scenario`` only sees a body FastAPI has already parsed -- by which point a
    50MB JSON document has been received and deserialized. The two are not redundant: this
    one bounds what the process ingests, that one bounds what the engine is asked to ablate.

    ``Content-Length`` is advisory and a hostile client can lie or omit it. The starlette
    stack still bounds an unlabelled body by what it will buffer, and the field-level cap
    is what actually decides whether work happens -- so this is the cheap first gate, not
    the only one.
    """
    config: ApiSettings = request.app.state.settings
    declared = request.headers.get("content-length")
    if declared is not None and declared.isdigit() and int(declared) > config.max_request_bytes:
        exc = refuse(
            REQUEST_SIZE,
            413,
            f"body is {declared} bytes; the limit is {config.max_request_bytes}",
        )
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
    return await call_next(request)


def _build_log(config: ApiSettings) -> TransparencyLog:
    storage = SqliteLogStorage(config.log_database) if config.log_database else None
    return TransparencyLog(
        log_id=config.log_id,
        signing_key=SigningKey.from_seed(config.log_seed),
        storage=storage,
    )


# --------------------------------------------------------------------------- helpers


def _require_session(request: Request, session_id: str | None) -> Session:
    session = request.app.state.sessions.get(session_id)
    if session is None:
        # 401 rather than 404: the caller has no session, which is a thing they can fix by
        # asking for one. Saying "unknown session" would also confirm which ids exist.
        raise HTTPException(
            status_code=401,
            detail=f"no live session; POST /v1/sessions and send {SESSION_HEADER}",
        )
    return session


def _require_run(session: Session, run_id: str) -> Run:
    run = session.runs.get(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="run not found in this session")
    return run


def _require_stage(run: Run, name: str) -> Any:
    if name not in run.stages:
        raise HTTPException(
            status_code=409,
            detail=(
                f"this run has no {name} stage (status={run.status}"
                + (f", error={run.error}" if run.error else "")
                + "). Stages are absent when they did not run; none are fabricated."
            ),
        )
    return run.stages[name]


def _resolve_scenario(body: RunRequest, config: ApiSettings) -> Scenario:
    if body.scenario == "custom":
        injection = body.injection.strip()
        if not injection:
            raise HTTPException(
                status_code=400, detail="scenario=custom requires non-empty `injection`"
            )
        if len(injection) > config.max_injection_chars:
            # Distinct from the body ceiling in the middleware: that one bounds what the
            # process ingests, this one bounds what the engine is asked to ablate. A body
            # well under 64KB can still be a context that costs hundreds of model calls.
            raise refuse(
                CONTEXT_SIZE,
                413,
                f"injection is {len(injection)} characters; the limit is "
                f"{config.max_injection_chars}. Attribution costs one model call per "
                "segment ablated, so context length is a cost amplifier.",
            )
        return custom_scenario(injection)

    presets = catalogue()
    if body.scenario not in presets:
        raise HTTPException(
            status_code=404,
            detail=f"unknown scenario; known: {sorted(presets)} or 'custom'",
        )
    return presets[body.scenario]


async def artifact_bundle(
    run: Run, session: Session, log: TransparencyLog, log_lock: asyncio.Lock
) -> dict:
    """The three files ``tools/verify_warrant.py`` consumes, pinned as one snapshot.

    Two things have to be true together for an offline verifier to reach 6/6: the
    receipt's tree size must equal the size the witness accepted, and the inclusion proof
    must be the one for that size. The shared log grows while a visitor reads the page,
    so a receipt fetched at one moment and anchors fetched at another would describe
    different trees and fail a check that is doing its job.

    So the bundle is built once, under the log lock that also guards appends, and cached
    on the run. Every later request returns the identical bytes -- a snapshot at a stated
    tree size, which is what an auditor's evidence is supposed to be.
    """
    if run.artifacts is not None:
        return run.artifacts
    if run.leaf_index is None:
        raise HTTPException(
            status_code=409,
            detail="this run published no warrant, so there is nothing for an auditor to check",
        )

    async with log_lock:
        # Bring the witness up to the log's current head before deriving the receipt, so
        # the root in trust_anchors is one the witness genuinely accepted rather than one
        # copied off the operator's own receipt. Under the same lock as ``append``,
        # because a tree that grows between the head and the receipt yields a proof for a
        # size nobody witnessed.
        previous = session.witness.tree_size
        head = log.signed_tree_head()
        if head.tree_size > previous:
            session.witness.observe(head, log.consistency_proof(previous) if previous else None)

        receipt: Receipt = log.receipt_for(run.leaf_index)
        root = session.witness.current_root()

    if root is None:
        raise HTTPException(
            status_code=409,
            detail="the witness holds no root: it has seen a fork and will not vouch for this log",
        )

    run.artifacts = {
        "warrant": run.stages["warrant"],
        "receipt": receipt.model_dump(mode="json"),
        "trust_anchors": {
            "issuer_verification_method": session.verification_method,
            "issuer_public_key_multibase": session.issuer_key.public.to_multibase(),
            "log_id": log.log_id,
            "log_public_key_multibase": log.signing_key.public.to_multibase(),
            "witnessed_root": encode_hash(root),
            "witnessed_tree_size": session.witness.tree_size,
        },
    }
    return run.artifacts


# ---------------------------------------------------------------------------- routes


def _router() -> APIRouter:  # noqa: C901 - one function per route, kept together
    router = APIRouter()

    @router.get("/health")
    async def health(request: Request) -> dict:
        log: TransparencyLog = request.app.state.log
        return {
            "status": "ok",
            "service": "aegis-api",
            "version": __version__,
            "model": runner.MODEL_LABEL,
            "log_tree_size": log.tree_size,
            "log_durable": _durable(log),
            "sessions": len(request.app.state.sessions),
        }

    @router.get("/v1/scenarios")
    async def scenarios() -> dict:
        presets = catalogue()
        return {
            "model": runner.MODEL_LABEL,
            "count": len(presets),
            "scenarios": [presets[name].as_dict() for name in sorted(presets)],
            "custom": {
                "name": "custom",
                "title": "Your own document",
                "summary": (
                    "Supply `injection` and it becomes the invoice reader's document. "
                    "Runs are marked unlabelled: we have no ground truth for text we did "
                    "not construct, and unlabelled runs never enter a scored metric."
                ),
            },
        }

    @router.post("/v1/sessions", status_code=201)
    async def create_session(request: Request) -> dict:
        config: ApiSettings = request.app.state.settings
        request.app.state.arrivals.check(
            f"session:{client_key(request, config)}", config.sessions_per_minute
        )
        session = request.app.state.sessions.create(request.app.state.log)
        return {
            **session.as_dict(),
            "header": SESSION_HEADER,
            "note": (
                "Your own issuer key, policy and enforcement point. The transparency log "
                "is shared with every other visitor on purpose -- an append-only log you "
                "grew alone proves nothing about append-only."
            ),
        }

    @router.get("/v1/sessions/me")
    async def whoami(request: Request, x_aegis_session: str | None = Header(default=None)) -> dict:
        return _require_session(request, x_aegis_session).as_dict()

    @router.post("/v1/runs", status_code=202)
    async def create_run(
        request: Request,
        body: RunRequest,
        x_aegis_session: str | None = Header(default=None),
    ) -> dict:
        session = _require_session(request, x_aegis_session)
        config: ApiSettings = request.app.state.settings

        # Order matters: arrival rate, then budget, then the scenario. Parsing the
        # scenario first would let a client over its rate limit still drive the
        # classifier, which is cheap but not free, and is the wrong shape of answer.
        request.app.state.arrivals.check(
            f"run:{client_key(request, config)}", config.runs_per_minute
        )
        check_session_budget(session.model_calls_spent, config)
        scenario = _resolve_scenario(body, config)

        run = Run(
            run_id=prefixed_id("run"),
            session_id=session.session_id,
            scenario=scenario,
            created_at=datetime.now(UTC).isoformat(),
        )
        session.runs.add(run)

        # 202 and a background task rather than a blocking call. Attribution issues tens
        # of model calls; the events it records are the interesting part, and Phase 5b
        # streams them from exactly here without changing this contract.
        #
        # The task is held on the run. An unreferenced task is only weakly held by the
        # event loop and may be collected mid-flight, which would present as a run that
        # stops advancing for no visible reason under load and never under test.
        run.task = asyncio.create_task(
            runner.execute(
                run,
                session,
                request.app.state.log,
                request.app.state.log_lock,
                config,
                request.app.state.attribution_slots,
            )
        )
        return {
            **run.summary(),
            "model": runner.MODEL_LABEL,
            "events": f"/v1/runs/{run.run_id}/events",
        }

    @router.get("/v1/runs")
    async def list_runs(
        request: Request, x_aegis_session: str | None = Header(default=None)
    ) -> dict:
        session = _require_session(request, x_aegis_session)
        return {"count": len(session.runs), "runs": [r.summary() for r in session.runs.recent()]}

    @router.get("/v1/runs/{run_id}")
    async def get_run(
        run_id: str, request: Request, x_aegis_session: str | None = Header(default=None)
    ) -> dict:
        session = _require_session(request, x_aegis_session)
        return _require_run(session, run_id).as_dict()

    @router.get("/v1/runs/{run_id}/events")
    async def stream_events(
        run_id: str,
        request: Request,
        x_aegis_session: str | None = Header(default=None),
        last_event_id: str | None = Header(default=None),
        after: int = -1,
    ) -> StreamingResponse:
        """Server-sent events: every stage boundary, and every ablation as it completes.

        Attribution issues tens of model calls and takes seconds. Streaming turns that
        dead time into the most informative screen on the site -- the visitor watches
        counterfactuals being tested rather than a spinner that tells them nothing.

        Resumable: ``Last-Event-ID`` (sent automatically by ``EventSource`` on reconnect)
        or ``?after=`` replays from a sequence number. The event log is retained on the
        run, so a reconnect is a replay rather than a gap.
        """
        session = _require_session(request, x_aegis_session)
        run = _require_run(session, run_id)
        config: ApiSettings = request.app.state.settings

        if session.open_streams >= config.max_streams_per_session:
            raise refuse(
                STREAMS,
                429,
                f"{config.max_streams_per_session} concurrent streams already open",
            )

        cursor = _resume_point(last_event_id, after)
        return StreamingResponse(
            _event_stream(run, session, cursor, config),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                # nginx and friends buffer proxied responses by default, which turns a
                # live stream into one delivery at the end -- the exact failure this
                # endpoint exists to avoid.
                "X-Accel-Buffering": "no",
            },
        )

    # Registered before the ``/{stage}`` catch-all below. Route matching is by
    # registration order, so declaring these later would let ``{stage}`` swallow
    # ``GET .../attacks`` and answer a real endpoint with "this run has no attacks stage".
    @router.get("/v1/runs/{run_id}/attacks")
    async def list_attacks(
        run_id: str, request: Request, x_aegis_session: str | None = Header(default=None)
    ) -> dict:
        session = _require_session(request, x_aegis_session)
        run = _require_run(session, run_id)
        return {
            "run_id": run.run_id,
            "attacks": attacks.catalogue(),
            "note": (
                "Each one runs the real defence against a real mutation. `defended` "
                "reports whether the attacker lost; it is a measurement, not a promise."
            ),
        }

    @router.post("/v1/runs/{run_id}/attacks/{name}")
    async def run_attack(
        run_id: str,
        name: str,
        request: Request,
        x_aegis_session: str | None = Header(default=None),
    ) -> dict:
        session = _require_session(request, x_aegis_session)
        config: ApiSettings = request.app.state.settings
        request.app.state.arrivals.check(
            f"attack:{client_key(request, config)}", config.runs_per_minute
        )
        run = _require_run(session, run_id)
        return await attacks.execute(
            name, run, session, request.app.state.log, request.app.state.log_lock
        )

    @router.post("/v1/runs/{run_id}/replay")
    async def replay(
        run_id: str, request: Request, x_aegis_session: str | None = Header(default=None)
    ) -> dict:
        """Re-measure the attribution this warrant asserts, and report every disagreement.

        This is the only endpoint that makes a *second* attribution's worth of model
        calls, which makes it the cheapest denial-of-service on the surface if left
        unbudgeted. It therefore passes the same three gates a run does -- arrival rate,
        session budget, concurrency -- and the calls it spends are counted against the
        visitor rather than being free because they happen under a different route name.

        The client is wrapped rather than the engine instrumented: ``replay_attribution``
        builds its engine from the warrant's own ``replay_ref``, and letting this endpoint
        pass in a pre-built engine would mean the auditor replays under settings the API
        chose instead of the ones the issuer committed to.
        """
        session = _require_session(request, x_aegis_session)
        config: ApiSettings = request.app.state.settings
        request.app.state.arrivals.check(
            f"replay:{client_key(request, config)}", config.runs_per_minute
        )
        check_session_budget(session.model_calls_spent, config)

        run = _require_run(session, run_id)
        document = _require_stage(run, "warrant")
        if run.evidence is None:
            raise HTTPException(
                status_code=409,
                detail="this run recorded no trace, so there is nothing to replay against",
            )

        counter = _CountingClient(InProcessMockClient())
        try:
            async with request.app.state.attribution_slots:
                report = await replay_attribution(
                    document, run.evidence.body, run.evidence.trace, counter
                )
        finally:
            # In the ``finally`` so an attribution that raises halfway still bills for the
            # calls it made. A failure path that resets the meter is a free retry loop.
            session.model_calls_spent += counter.calls

        return {
            "run_id": run.run_id,
            "model": runner.MODEL_LABEL,
            "model_calls": counter.calls,
            **report.as_dict(),
            "note": (
                "Replay checks whether the issuer's numbers are reproducible, which is a "
                "different question from whether the warrant is authentic. A contradiction "
                "is evidence the claim does not reproduce; it is not proof of intent, and "
                "honest causes exist. Here the auditor and the issuer share one bundled "
                "model, so a reproducible result is weaker evidence than it would be "
                "against an auditor holding their own key to a hosted model."
            ),
        }

    @router.get("/v1/runs/{run_id}/{stage}")
    async def get_stage(
        run_id: str,
        stage: str,
        request: Request,
        x_aegis_session: str | None = Header(default=None),
    ) -> Any:
        session = _require_session(request, x_aegis_session)
        run = _require_run(session, run_id)
        if stage == "artifacts":
            return await artifact_bundle(
                run, session, request.app.state.log, request.app.state.log_lock
            )
        return _require_stage(run, stage)

    @router.get("/v1/runs/{run_id}/artifacts/{name}.json")
    async def get_artifact(
        run_id: str,
        name: str,
        request: Request,
        x_aegis_session: str | None = Header(default=None),
    ) -> JSONResponse:
        if name not in ARTIFACT_FILES:
            raise HTTPException(status_code=404, detail=f"expected one of {list(ARTIFACT_FILES)}")
        session = _require_session(request, x_aegis_session)
        run = _require_run(session, run_id)
        bundle = await artifact_bundle(
            run, session, request.app.state.log, request.app.state.log_lock
        )
        return JSONResponse(
            content=bundle[name],
            headers={"Content-Disposition": f'attachment; filename="{name}.json"'},
        )

    @router.post("/v1/evaluation")
    async def evaluation(
        request: Request, x_aegis_session: str | None = Header(default=None)
    ) -> dict:
        """Score the whole labelled case set and return every case beside its outcome.

        A single run proves nothing on its own. A detector that flags everything scores
        perfectly on the four poisoned cases and is worthless; the three clean ones are
        what make the poisoned ones mean something. This endpoint is the comparison —
        precision and recall over the same cases, with the clean rows visible.

        Served as one request rather than seven runs driven from the browser, and that is
        a control decision rather than a convenience: the arrival limiter allows six runs
        a minute, so a client looping over seven scenarios would be refused on the last
        one. One arrival, one rate-limit slot, and the cost billed to the session.

        This calls ``run_evaluation`` — the same function ``demo/phase2_eval.py`` calls —
        so the grid on the website and the numbers in ``results/phase2_evaluation.json``
        cannot drift apart.
        """
        session = _require_session(request, x_aegis_session)
        config: ApiSettings = request.app.state.settings
        request.app.state.arrivals.check(
            f"eval:{client_key(request, config)}", config.evaluations_per_minute
        )
        check_session_budget(session.model_calls_spent, config)

        async with request.app.state.attribution_slots:
            report = await run_evaluation()

        spent = sum(outcome.model_calls for outcome in report.outcomes)
        session.model_calls_spent += spent

        return {
            **report.as_dict(),
            "model": runner.MODEL_LABEL,
            "model_calls": spent,
            "flag_threshold": FLAG_THRESHOLD,
            "note": (
                "Seven hand-built cases against a deterministic mock. They prove the engine "
                "is wired correctly and catch regressions in seconds; they are not a "
                "generalization claim. The clean cases are the ones that decide whether a "
                "control is deployable — an injection that failed is an easy negative, "
                "ordinary work with no adversary is the hard one."
            ),
        }

    @router.get("/v1/log")
    async def log_state(request: Request) -> dict:
        log: TransparencyLog = request.app.state.log
        head = log.signed_tree_head()
        return {
            "log_id": log.log_id,
            "tree_size": log.tree_size,
            "signed_tree_head": head.model_dump(mode="json"),
            "log_public_key_multibase": log.signing_key.public.to_multibase(),
            "durable": _durable(log),
            "note": (
                "Shared by every visitor. Entries are warrant documents, which carry "
                "excerpt hashes rather than excerpt text -- no submitted document is "
                "stored here or served to anyone else."
            ),
        }

    @router.get("/v1/log/consistency")
    async def consistency(request: Request, first: int) -> dict:
        log: TransparencyLog = request.app.state.log
        if first < 1 or first > log.tree_size:
            # There is no consistency proof from the empty tree: every tree extends it, so
            # the proof would assert nothing. RFC 6962 requires 0 < first <= n and the
            # boundary is repeated here so the caller gets a reason rather than a 500.
            raise HTTPException(
                status_code=400,
                detail=(
                    f"first must be between 1 and {log.tree_size}; a proof from the empty "
                    "tree would assert nothing, because every tree extends it"
                ),
            )
        return {
            "first": first,
            "second": log.tree_size,
            "proof": log.consistency_proof(first),
            "signed_tree_head": log.signed_tree_head().model_dump(mode="json"),
        }

    @router.get("/v1/log/entries/{index}")
    async def log_entry(index: int, request: Request) -> JSONResponse:
        log: TransparencyLog = request.app.state.log
        if index < 0 or index >= log.tree_size:
            raise HTTPException(status_code=404, detail="no such leaf")
        return JSONResponse(content=_json_entry(log, index))

    @router.get("/v1/witness")
    async def witness_state(
        request: Request, x_aegis_session: str | None = Header(default=None)
    ) -> dict:
        session = _require_session(request, x_aegis_session)
        head = session.witness.head
        root = session.witness.current_root()
        return {
            "log_id": session.witness.log_id,
            "tree_size": session.witness.tree_size,
            "head": head.model_dump(mode="json") if head else None,
            "root": encode_hash(root) if root else None,
            "note": (
                "An observer in a different trust domain than the issuer. Inclusion is "
                "checked against this root, never against the one the operator supplied "
                "with the receipt."
            ),
        }

    return router


class _CountingClient:
    """Wraps a model client to bill the session for what a replay actually spent.

    The engine's own counter lives on the ``AttributionResult``, which a replay never
    returns -- ``replay_attribution`` hands back a comparison, not a measurement. Counting
    at the client is the one place the number is observable without reaching inside a
    function whose whole purpose is to rebuild the engine from the issuer's commitment.
    """

    def __init__(self, inner) -> None:
        self.inner = inner
        self.calls = 0

    async def complete(self, body: dict) -> dict:
        self.calls += 1
        return await self.inner.complete(body)


def _resume_point(last_event_id: str | None, after: int) -> int:
    """Where to start replaying. ``Last-Event-ID`` wins; both are advisory.

    A malformed header is treated as "from the beginning" rather than as an error: it
    arrives from a browser's automatic reconnect, where there is nobody to show a 400 to,
    and replaying too much is recoverable while skipping events is not.
    """
    if last_event_id is not None:
        try:
            return int(last_event_id) + 1
        except ValueError:
            return 0
    return after + 1 if after >= 0 else 0


def _sse(event: RunEvent) -> str:
    payload = json.dumps(event.data, separators=(",", ":"))
    return f"id: {event.seq}\nevent: {event.type}\ndata: {payload}\n\n"


async def _event_stream(
    run: Run, session: Session, cursor: int, config: ApiSettings
) -> AsyncIterator[str]:
    """Drain, wait, drain again, until the run reaches a terminal state.

    The ordering is what makes this correct: the waiter is registered *before* the first
    drain, so an event emitted while we are yielding cannot be missed -- it sets a flag
    that is already listening. Checking the run's status only after a full drain is what
    guarantees a subscriber never sees "complete" while events remain unread.
    """
    session.open_streams += 1
    try:
        with run.subscribe() as updated:
            while True:
                while cursor < len(run.events):
                    yield _sse(run.events[cursor])
                    cursor += 1

                if run.status != "running":
                    return

                updated.clear()
                if cursor < len(run.events):
                    # Emitted between the drain and the clear. Without this re-check that
                    # event waits for the next one to arrive, and on the last event of a
                    # run there is no next one.
                    continue
                try:
                    await asyncio.wait_for(updated.wait(), timeout=config.stream_heartbeat_seconds)
                except TimeoutError:
                    # A comment frame. Keeps proxies and load balancers from reaping an
                    # idle connection, and costs one line.
                    yield ": keepalive\n\n"
    finally:
        session.open_streams -= 1


def _durable(log: TransparencyLog) -> bool:
    return isinstance(log.storage, SqliteLogStorage)


def _json_entry(log: TransparencyLog, index: int) -> dict:
    return json.loads(log.entry(index).decode("utf-8"))


app = create_app()
