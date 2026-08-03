"""A deterministic, OpenAI-compatible mock model.

Why this exists rather than a real endpoint:

1. The whole system runs offline, with no key and no cost.
2. Phase 2's ablation engine issues one model call per segment per resample. Against a
   paid API that is expensive; against a nondeterministic one it is unmeasurable.
3. It gives Phase 2 **ground truth**. Because this model's behaviour is a known function
   of its input, we know exactly which segment caused a given tool call, so attribution
   precision and recall can be scored against truth rather than against a guess.

The behaviour is not arbitrary. It reproduces the real failure mode AegisMesh exists to
catch: the model follows the *most recently seen* instruction of a given kind, so an
account number injected late in a retrieved document overrides the one the human asked
for. That recency effect is a well-documented cause of successful indirect prompt
injection, and simulating it faithfully is what makes the demo honest.
"""

from __future__ import annotations

import json
import re
import time

from fastapi import APIRouter, FastAPI
from pydantic import BaseModel

from aegis import __version__

IBAN_PATTERN = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b")
AMOUNT_PATTERN = re.compile(r"(?:USD|\$)\s?([\d,]+(?:\.\d{2})?)", re.IGNORECASE)
TRANSFER_INTENT = re.compile(r"\b(transfer|remit|pay|payment|settle)\b", re.IGNORECASE)


class MockDecision(BaseModel):
    """What the mock model decided, and why -- so tests can assert on the reason."""

    tool: str | None = None
    arguments: dict = {}
    text: str = ""
    reason: str = ""


def decide(context: str) -> MockDecision:
    """Map a context string to a decision, deterministically.

    Rules, in order:
      * No transfer intent anywhere    -> plain text reply, no tool call.
      * Transfer intent present        -> call ``execute_transfer``.
      * Destination account            -> the LAST IBAN in the context (recency bias).
      * Amount                         -> the FIRST amount in the context.

    The asymmetry is deliberate: amount comes from the human's opening instruction while
    destination is captured by whatever spoke last. That is the exact shape of the invoice
    attack in the README.
    """
    if not TRANSFER_INTENT.search(context):
        return MockDecision(
            text="Acknowledged. No action taken.",
            reason="no transfer intent detected in context",
        )

    ibans = IBAN_PATTERN.findall(context)
    amounts = AMOUNT_PATTERN.findall(context)

    if not ibans:
        return MockDecision(
            text="I need a destination account before I can transfer anything.",
            reason="transfer intent but no destination account present",
        )

    destination = ibans[-1]
    amount = float(amounts[0].replace(",", "")) if amounts else 0.0

    return MockDecision(
        tool="execute_transfer",
        arguments={
            "amount": amount,
            "currency": "USD",
            "destination_account": destination,
        },
        reason=(
            f"transfer intent; selected last of {len(ibans)} account(s) by recency; "
            f"amount from first of {len(amounts)} match(es)"
        ),
    )


def _flatten(messages: list[dict]) -> str:
    parts = []
    for message in messages:
        content = message.get("content")
        if isinstance(content, str):
            parts.append(content)
        elif isinstance(content, list):
            parts.extend(
                p.get("text", "")
                for p in content
                if isinstance(p, dict) and p.get("type") == "text"
            )
        for call in message.get("tool_calls", []) or []:
            parts.append(str(call.get("function", {}).get("arguments", "")))
    return "\n".join(parts)


def create_app() -> FastAPI:
    app = FastAPI(title="aegis-mockmodel", version=__version__)
    router = APIRouter()

    @router.get("/health")
    async def health() -> dict:
        return {"status": "ok", "service": "aegis-mockmodel", "version": __version__}

    @router.post("/v1/chat/completions")
    async def chat_completions(body: dict) -> dict:
        messages = body.get("messages", [])
        decision = decide(_flatten(messages))

        message: dict = {"role": "assistant", "content": decision.text or None}
        if decision.tool:
            message["tool_calls"] = [
                {
                    "id": "call_mock_0",
                    "type": "function",
                    "function": {
                        "name": decision.tool,
                        "arguments": json.dumps(decision.arguments, sort_keys=True),
                    },
                }
            ]

        return {
            "id": "chatcmpl-mock",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": body.get("model", "aegis-mock-1"),
            "choices": [
                {
                    "index": 0,
                    "message": message,
                    "finish_reason": "tool_calls" if decision.tool else "stop",
                }
            ],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
            "x_aegis_mock_reason": decision.reason,
        }

    app.include_router(router)
    return app


app = create_app()
