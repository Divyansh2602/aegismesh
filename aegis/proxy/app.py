"""aegis-proxy — OpenAI-compatible interception with provenance tagging.

Drop-in: point an existing agent's base URL at this service and it keeps working. That
zero-code-change property is the adoption story, so the passthrough must stay faithful --
the proxy observes and classifies, it does not rewrite the request.

Mandate declaration is out-of-band, via headers, so that declaring human intent does not
require changing the request body an agent framework builds:

    X-Aegis-Mandate-Id      identifier of the authenticated mandate
    X-Aegis-Principal       DID of the human principal
    X-Aegis-Instruction     the verbatim instruction the principal gave

Without those headers nothing is classified P0, and every user-role token is untrusted.
That is the intended failure mode: an unintegrated caller gets no trust, not full trust.
"""

from __future__ import annotations

import base64
import binascii

import httpx
from fastapi import APIRouter, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse

from aegis import __version__
from aegis.provenance.classifier import ContextClassifier
from aegis.provenance.models import ContextTrace
from aegis.provenance.registry import MandateContext, ToolRegistry
from aegis.proxy.config import ProxySettings, settings
from aegis.proxy.store import TraceStore

TRACE_HEADER = "X-Aegis-Trace-Id"


def create_app(
    config: ProxySettings | None = None,
    registry: ToolRegistry | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> FastAPI:
    """Build the proxy app.

    ``transport`` lets tests route upstream calls straight into the mock model's ASGI app
    instead of over a socket, so the integration test exercises the real forwarding path
    without needing two live servers.
    """
    config = config or settings
    app = FastAPI(title="aegis-proxy", version=__version__)
    app.state.settings = config
    app.state.registry = registry or ToolRegistry()
    app.state.store = TraceStore(max_traces=config.max_traces)
    app.state.transport = transport
    app.include_router(_router())
    return app


def _router() -> APIRouter:
    router = APIRouter()

    @router.get("/health")
    async def health() -> dict:
        return {"status": "ok", "service": "aegis-proxy", "version": __version__}

    @router.post("/v1/intercept/chat/completions")
    async def chat_completions(
        request: Request,
        x_aegis_mandate_id: str | None = Header(default=None),
        x_aegis_principal: str | None = Header(default=None),
        x_aegis_instruction: str | None = Header(default=None),
        x_aegis_instruction_b64: str | None = Header(default=None),
    ) -> JSONResponse:
        body = await request.json()
        if not isinstance(body, dict):
            raise HTTPException(status_code=400, detail="request body must be a JSON object")

        mandate = _build_mandate(
            x_aegis_mandate_id,
            x_aegis_principal,
            x_aegis_instruction,
            x_aegis_instruction_b64,
        )

        classifier = ContextClassifier(registry=request.app.state.registry, mandate=mandate)
        trace = classifier.classify(body)

        if not request.app.state.settings.retain_context:
            trace.assembled_context = ""
            for segment in trace.segments:
                segment.text = ""

        upstream = await _forward(
            body, request.app.state.settings, request.app.state.transport
        )
        trace.upstream_response = upstream
        request.app.state.store.put(trace)

        return JSONResponse(content=upstream, headers={TRACE_HEADER: trace.trace_id})

    @router.get("/v1/traces/{trace_id}")
    async def get_trace(trace_id: str, request: Request) -> dict:
        trace = request.app.state.store.get(trace_id)
        if trace is None:
            raise HTTPException(status_code=404, detail="trace not found")
        return _trace_view(trace)

    @router.get("/v1/traces")
    async def list_traces(request: Request, limit: int = 20) -> dict:
        traces = request.app.state.store.recent(limit)
        return {
            "count": len(traces),
            "traces": [
                {
                    "trace_id": t.trace_id,
                    "created_at": t.created_at.isoformat(),
                    "model": t.model,
                    "mandate_id": t.mandate_id,
                    "segments": len(t.segments),
                    "bytes_by_class": {k.value: v for k, v in t.bytes_by_class().items()},
                }
                for t in traces
            ],
        }

    @router.get("/v1/registry/drift")
    async def registry_drift(request: Request) -> dict:
        drift = request.app.state.registry.drift
        return {"count": len(drift), "events": [d.model_dump() for d in drift]}

    return router


def _build_mandate(
    mandate_id: str | None,
    principal: str | None,
    instruction: str | None,
    instruction_b64: str | None,
) -> MandateContext | None:
    """Assemble the mandate from headers, or return None if not fully declared.

    A partially declared mandate is rejected rather than partially honoured. Accepting
    ``principal`` without ``instruction`` would let a caller claim authority without
    stating what was authorised, which is precisely the property the system exists to
    prevent.
    """
    if instruction is None and instruction_b64:
        try:
            instruction = base64.b64decode(instruction_b64, validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError) as exc:
            raise HTTPException(
                status_code=400, detail="X-Aegis-Instruction-B64 is not valid base64 UTF-8"
            ) from exc

    if not (mandate_id and principal and instruction):
        return None

    return MandateContext(
        mandate_id=mandate_id,
        principal=principal,
        instruction=instruction,
    )


async def _forward(
    body: dict,
    config: ProxySettings,
    transport: httpx.AsyncBaseTransport | None = None,
) -> dict:
    headers = {"Content-Type": "application/json"}
    if config.upstream_api_key:
        headers["Authorization"] = f"Bearer {config.upstream_api_key}"

    url = config.upstream_base_url.rstrip("/") + "/chat/completions"
    try:
        async with httpx.AsyncClient(
            timeout=config.request_timeout_seconds, transport=transport
        ) as client:
            response = await client.post(url, json=body, headers=headers)
    except httpx.RequestError as exc:
        raise HTTPException(status_code=502, detail=f"upstream unreachable: {exc}") from exc

    if response.status_code >= 400:
        raise HTTPException(status_code=response.status_code, detail=response.text)
    return response.json()


def _trace_view(trace: ContextTrace) -> dict:
    """Auditor-facing view: classification with hashes, not raw document text."""
    return {
        "trace_id": trace.trace_id,
        "created_at": trace.created_at.isoformat(),
        "model": trace.model,
        "mandate_id": trace.mandate_id,
        "principal": trace.principal,
        "bytes_by_class": {k.value: v for k, v in trace.bytes_by_class().items()},
        "segments": [s.redacted() for s in trace.segments],
    }


app = create_app()
