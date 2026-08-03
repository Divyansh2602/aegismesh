"""Model clients for the attribution engine.

The engine only needs ``complete(body) -> response``. Keeping that surface tiny is what
lets the same engine run against the offline mock, an in-process ASGI app, or a real
provider without changing a line of attribution logic.
"""

from __future__ import annotations

import httpx

from aegis.mockmodel.app import decide


class InProcessMockClient:
    """Calls the mock model's decision function directly.

    No HTTP, no event loop overhead: the evaluation harness issues thousands of ablation
    calls, and a socket round-trip per call would dominate the runtime while measuring
    nothing interesting.
    """

    def __init__(self) -> None:
        self.calls = 0

    async def complete(self, body: dict) -> dict:
        self.calls += 1
        context = _flatten(body.get("messages", []))
        decision = decide(context)

        message: dict = {"role": "assistant", "content": decision.text or None}
        if decision.tool:
            import json

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
        return {"choices": [{"index": 0, "message": message}]}


class HttpModelClient:
    """Calls any OpenAI-compatible endpoint."""

    def __init__(
        self,
        base_url: str,
        api_key: str = "",
        transport: httpx.AsyncBaseTransport | None = None,
        timeout: float = 60.0,
    ) -> None:
        self.url = base_url.rstrip("/") + "/chat/completions"
        self.headers = {"Content-Type": "application/json"}
        if api_key:
            self.headers["Authorization"] = f"Bearer {api_key}"
        self.transport = transport
        self.timeout = timeout
        self.calls = 0

    async def complete(self, body: dict) -> dict:
        self.calls += 1
        async with httpx.AsyncClient(timeout=self.timeout, transport=self.transport) as client:
            response = await client.post(self.url, json=body, headers=self.headers)
        response.raise_for_status()
        return response.json()


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
