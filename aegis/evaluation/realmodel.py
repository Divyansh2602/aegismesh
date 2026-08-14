"""Driving a real model, locally, for the measurement open question 9 asks for.

Every number in ``results/`` was measured against a surrogate whose susceptibility was
written down rather than discovered. That is the correct choice for a metric -- it buys
exact ground truth -- and it establishes nothing about how a transformer behaves. The
adapter has always run against ``HttpModelClient``; what was missing was a client that
pins the settings a *measurement* needs, and a ground truth that survives the model having
no rule to replay (``evaluation/groundtruth.py``).

**Local first, and not only because it is free.** Ollama, llama.cpp and vLLM all expose an
OpenAI-compatible ``/v1/chat/completions``, so this needs no provider-specific code. A local
model also removes the two things that make a hosted endpoint a poor instrument: a rate
limit that turns 9 000 ablation calls into a day of backoff, and a per-token bill that
quietly discourages re-running a measurement you did not like.

    ollama serve
    ollama pull qwen2.5:7b-instruct        # tool calling is required, not optional

Determinism is the part that is easy to get wrong and fatal to the method. Attribution
infers causation by removing an input and comparing the output; against a sampling model a
difference may be noise, and every influence score becomes an unfalsifiable number. So
``temperature`` and ``seed`` are pinned here rather than left to the caller, and
:meth:`RealModelClient.noise_floor` exists to *measure* whether pinning them worked --
because it frequently does not. Batching, KV-cache reuse and non-associative float
reductions all make identical requests return different text on real serving stacks. A
measured noise floor is a precondition for believing anything downstream, not a footnote.
"""

from __future__ import annotations

import copy
from typing import Any

import httpx

from aegis.attribution.client import HttpModelClient

OLLAMA_BASE_URL = "http://localhost:11434/v1"

DEFAULT_MODEL = "llama3.1:8b"
"""Chosen for native tool calling, which the adapter requires rather than prefers.

A model that answers in prose about making a transfer produces no ``tool_calls``, so the
consequential-action gate never fires, nothing is attributed and the sweep reports an empty
result that looks like a finding. Llama 3.1 8B emits them and fits an 8GB card at Q4.
Override with ``AEGIS_OLLAMA_MODEL``; check tool support before substituting, because the
failure is silent.
"""


class RealModelClient:
    """An OpenAI-compatible endpoint, pinned so that ablation means something.

    Wraps ``HttpModelClient`` rather than replacing it: that class already speaks the
    protocol and is exercised elsewhere. What this adds is the per-request rewriting a
    measurement needs -- the model name the *endpoint* serves rather than the one the case
    fixture names, and sampling turned off.
    """

    def __init__(
        self,
        base_url: str = OLLAMA_BASE_URL,
        model: str = DEFAULT_MODEL,
        api_key: str = "",
        temperature: float = 0.0,
        seed: int | None = 0,
        transport: httpx.AsyncBaseTransport | None = None,
        timeout: float = 120.0,
    ) -> None:
        self._http = HttpModelClient(
            base_url=base_url, api_key=api_key, transport=transport, timeout=timeout
        )
        self.model = model
        self.temperature = temperature
        self.seed = seed

    @property
    def calls(self) -> int:
        """Delegated so cost accounting stays in one place and cannot drift."""
        return self._http.calls

    def request_body(self, body: dict) -> dict:
        """The body as actually sent.

        A copy, because the sweep reuses one case body across hundreds of ablations and
        mutating it in place would leave the previous run's overrides on the next one --
        the sort of bug that changes a measurement without failing anything.
        """
        out = copy.deepcopy(body)
        out["model"] = self.model
        out["temperature"] = self.temperature
        if self.seed is not None:
            out["seed"] = self.seed
        return out

    async def complete(self, body: dict) -> dict:
        return await self._http.complete(self.request_body(body))

    async def noise_floor(self, body: dict, samples: int = 5) -> dict[str, Any]:
        """Send the same request repeatedly and report whether the answer moved.

        Run this **before** trusting any attribution against a new model or endpoint. If
        identical inputs give different tool calls, then a counterfactual that differs from
        the baseline has not necessarily been caused by the segment that was removed, and
        every influence score is measuring the sampler as well as the context.

        Returns the distinct signatures rather than a boolean, because *how* it varies is
        the useful part: a model that varies only in free-text fields is still usable for
        attributing structured arguments, which is what this system scores.
        """
        from aegis.attribution.models import ActionSignature

        seen: list[str] = []
        for _ in range(max(1, samples)):
            response = await self.complete(body)
            call = ActionSignature.from_response(response)
            seen.append(_canonical(call))

        distinct = sorted(set(seen))
        return {
            "samples": len(seen),
            "distinct": len(distinct),
            "deterministic": len(distinct) == 1,
            "signatures": distinct,
        }


def _canonical(call: Any) -> str:
    import json

    return json.dumps({"tool": call.tool, "arguments": call.arguments}, sort_keys=True)


async def probe(base_url: str = OLLAMA_BASE_URL, timeout: float = 5.0) -> dict[str, Any]:
    """Is anything listening, and what does it serve?

    Called before a sweep so the failure mode is one clear message rather than several
    thousand connection errors, each of which has already cost an ablation.
    """
    url = base_url.rstrip("/").removesuffix("/v1") + "/api/tags"
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(url)
            response.raise_for_status()
            models = [m.get("name") for m in response.json().get("models", [])]
            return {"reachable": True, "models": models}
    except Exception as exc:  # noqa: BLE001 - a probe reports, it does not raise
        return {"reachable": False, "error": f"{type(exc).__name__}: {exc}"}
