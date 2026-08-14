"""The real-model client, exercised through the real HTTP path.

``httpx.MockTransport`` is a stub *endpoint*, not a stub client: request construction,
serialization, the ``/chat/completions`` URL, header handling and response parsing all run
exactly as they would against Ollama. That is the part worth testing, because it is the part
that silently sends the wrong thing -- a case fixture naming ``aegis-mock-1`` while the
endpoint serves ``qwen2.5``, or a temperature left at the provider default.

A live test against a running Ollama is included and skips when nothing is listening. It is
opt-in rather than absent because "it works against a stub" is exactly the claim that turns
out to be false the first time a real server is involved.
"""

from __future__ import annotations

import json
import os

import httpx
import pytest

from aegis.evaluation.realmodel import (
    DEFAULT_MODEL,
    OLLAMA_BASE_URL,
    RealModelClient,
    probe,
)


def tool_call_response(account: str = "DE89370400440532013000") -> dict:
    return {
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "call_0",
                            "type": "function",
                            "function": {
                                "name": "execute_transfer",
                                "arguments": json.dumps(
                                    {"amount": 2000000.0, "destination_account": account}
                                ),
                            },
                        }
                    ],
                },
            }
        ]
    }


def recorder(responses=None):
    """A stub endpoint that keeps every request body it was sent."""
    sent: list[dict] = []
    queue = list(responses or [])

    async def handler(request: httpx.Request) -> httpx.Response:
        sent.append(json.loads(request.content))
        payload = queue.pop(0) if queue else tool_call_response()
        return httpx.Response(200, json=payload)

    return httpx.MockTransport(handler), sent


class TestWhatItActuallySends:
    async def test_the_endpoints_model_replaces_the_fixtures_model(self):
        """The bug this prevents produces numbers, not an error.

        Case bodies name ``aegis-mock-1`` because that is what the offline mock is. Sent
        unchanged to Ollama, the server either 404s on an unknown model or quietly serves a
        different one -- and a sweep that ran against a model nobody chose is worse than a
        sweep that failed.
        """
        transport, sent = recorder()
        client = RealModelClient(model="qwen2.5:7b-instruct", transport=transport)

        await client.complete({"model": "aegis-mock-1", "messages": [{"role": "user"}]})

        assert sent[0]["model"] == "qwen2.5:7b-instruct"

    async def test_sampling_is_pinned_on_every_request(self):
        """Attribution infers cause by diffing outputs, so sampling is not a preference."""
        transport, sent = recorder()
        client = RealModelClient(transport=transport, temperature=0.0, seed=7)

        await client.complete({"model": "x", "messages": []})

        assert sent[0]["temperature"] == 0.0
        assert sent[0]["seed"] == 7

    async def test_the_caller_body_is_never_mutated(self):
        """The sweep reuses one body across hundreds of ablations.

        Rewriting it in place would leave this run's overrides on the next case -- a bug
        that changes a measurement without failing anything, which is the kind this project
        keeps finding.
        """
        transport, _ = recorder()
        client = RealModelClient(model="qwen2.5:7b-instruct", transport=transport)
        body = {"model": "aegis-mock-1", "messages": [{"role": "user", "content": "hi"}]}

        await client.complete(body)

        assert body["model"] == "aegis-mock-1"
        assert "temperature" not in body

    async def test_it_posts_to_the_openai_compatible_path(self):
        seen: list[str] = []

        async def handler(request: httpx.Request) -> httpx.Response:
            seen.append(str(request.url))
            return httpx.Response(200, json=tool_call_response())

        client = RealModelClient(
            base_url="http://localhost:11434/v1", transport=httpx.MockTransport(handler)
        )
        await client.complete({"messages": []})

        assert seen == ["http://localhost:11434/v1/chat/completions"]

    async def test_calls_are_counted_for_the_cost_budget(self):
        transport, _ = recorder()
        client = RealModelClient(transport=transport)

        for _ in range(3):
            await client.complete({"messages": []})

        assert client.calls == 3


class TestTheNoiseFloor:
    """Whether the endpoint is steady enough for a counterfactual to mean anything."""

    async def test_identical_answers_are_reported_as_deterministic(self):
        transport, _ = recorder([tool_call_response() for _ in range(4)])
        client = RealModelClient(transport=transport)

        floor = await client.noise_floor({"messages": []}, samples=4)

        assert floor["deterministic"] and floor["distinct"] == 1

    async def test_a_wobbling_endpoint_is_caught_before_it_corrupts_a_measurement(self):
        """The finding that would otherwise be reported as influence.

        If the same input yields two different destinations, then an ablation that changes
        the destination has not shown that the removed segment caused it. Every score in
        the run would be measuring the sampler as well as the context, and nothing
        downstream would say so.
        """
        transport, _ = recorder(
            [
                tool_call_response("DE89370400440532013000"),
                tool_call_response("GB29NWBK60161331926819"),
                tool_call_response("DE89370400440532013000"),
            ]
        )
        client = RealModelClient(transport=transport)

        floor = await client.noise_floor({"messages": []}, samples=3)

        assert not floor["deterministic"]
        assert floor["distinct"] == 2

    async def test_it_reports_the_signatures_rather_than_only_a_verdict(self):
        """How it varies decides whether the model is still usable.

        Variation confined to free text leaves structured arguments attributable; variation
        in the arguments does not. A boolean cannot express that difference.
        """
        transport, _ = recorder(
            [tool_call_response("A"), tool_call_response("B")]
        )
        client = RealModelClient(transport=transport)

        floor = await client.noise_floor({"messages": []}, samples=2)

        assert len(floor["signatures"]) == 2
        assert any("destination_account" in s for s in floor["signatures"])


class TestAgainstARunningOllama:
    """Opt-in. Skips cleanly when nothing is listening, which is the normal case in CI."""

    @pytest.fixture
    async def live(self):
        base = os.environ.get("AEGIS_OLLAMA_URL", OLLAMA_BASE_URL)
        status = await probe(base)
        if not status["reachable"]:
            pytest.skip(f"no Ollama at {base}: {status['error']}")
        return base, status

    async def test_the_probe_lists_what_the_endpoint_serves(self, live):
        base, status = live
        assert isinstance(status["models"], list)

    async def test_a_real_model_answers_and_is_steady_enough_to_ablate(self, live):
        """The only test here that says anything about a real transformer.

        Deliberately not asserted as deterministic: whether it is, is the measurement, and
        a failing test would be reporting a property of somebody's GPU. What is asserted is
        that the round trip works and the noise floor is *observable*, which is the
        precondition for the sweep.
        """
        base, _ = live
        model = os.environ.get("AEGIS_OLLAMA_MODEL", DEFAULT_MODEL)
        client = RealModelClient(base_url=base, model=model)

        floor = await client.noise_floor(
            {
                "messages": [
                    {"role": "user", "content": "Reply with the single word: ready."}
                ],
                "max_tokens": 16,
            },
            samples=2,
        )
        assert floor["samples"] == 2
        assert client.calls == 2


class TestTheProbe:
    async def test_an_unreachable_endpoint_reports_rather_than_raises(self):
        """A probe exists to produce one clear message instead of thousands of failures."""
        status = await probe("http://127.0.0.1:1/v1", timeout=0.25)
        assert status["reachable"] is False
        assert status["error"]
