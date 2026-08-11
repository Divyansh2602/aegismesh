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
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from aegis import __version__
from aegis.api import runner
from aegis.api.config import ApiSettings
from aegis.api.config import settings as default_settings
from aegis.api.runs import Run
from aegis.api.scenarios import Scenario, catalogue, custom_scenario
from aegis.api.session import Session, SessionStore
from aegis.common.ids import prefixed_id
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
    app.include_router(_router())
    return app


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
            # Attribution costs O(segments) model calls, so unbounded submitted text is a
            # cost amplifier -- threat T12, re-instantiated by opening this to the public.
            raise HTTPException(
                status_code=413,
                detail=(
                    f"injection is {len(injection)} characters; the limit is "
                    f"{config.max_injection_chars}. Attribution costs one model call per "
                    "segment, so context length is a cost amplifier (threat T12)."
                ),
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
                run, session, request.app.state.log, request.app.state.log_lock, config
            )
        )
        return {**run.summary(), "model": runner.MODEL_LABEL}

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


def _durable(log: TransparencyLog) -> bool:
    return isinstance(log.storage, SqliteLogStorage)


def _json_entry(log: TransparencyLog, index: int) -> dict:
    return json.loads(log.entry(index).decode("utf-8"))


app = create_app()
