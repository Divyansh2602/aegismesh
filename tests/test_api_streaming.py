"""Phase 5b — the event stream, and the controls that name themselves.

The streaming assertions are about *ordering and completeness*, not about SSE syntax: a
subscriber must never see a terminal status while events remain unread, and must be able
to reconcile the ablation events it watched against the `model_calls` the run reports.
Those are the two ways a progress feed lies.
"""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest
from fastapi import HTTPException

from aegis.api.app import SESSION_HEADER, _event_stream, create_app
from aegis.api.config import ApiSettings
from aegis.api.limits import ArrivalLimiter
from aegis.api.runs import Run
from aegis.api.scenarios import custom_scenario

POISONED = "injection_via_conduit_tool"


@pytest.fixture
async def client():
    app = create_app(ApiSettings())
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://api") as http:
        http.app = app
        yield http


async def open_session(http: httpx.AsyncClient) -> str:
    return (await http.post("/v1/sessions")).json()["session_id"]


async def start_run(http: httpx.AsyncClient, session: str, **body) -> str:
    started = await http.post(
        "/v1/runs", json=body or {"scenario": POISONED}, headers={SESSION_HEADER: session}
    )
    assert started.status_code == 202, started.text
    return started.json()["run_id"]


def parse_sse(text: str) -> list[dict]:
    """Minimal SSE reader: id/event/data triples, comment frames ignored."""
    events = []
    for block in text.split("\n\n"):
        if not block.strip() or block.lstrip().startswith(":"):
            continue
        fields: dict[str, str] = {}
        for line in block.splitlines():
            key, _, value = line.partition(": ")
            fields[key] = value
        events.append(
            {
                "seq": int(fields["id"]),
                "type": fields["event"],
                "data": json.loads(fields["data"]),
            }
        )
    return events


async def collect(http: httpx.AsyncClient, session: str, run_id: str, **params) -> list[dict]:
    async with http.stream(
        "GET",
        f"/v1/runs/{run_id}/events",
        headers={SESSION_HEADER: session},
        params=params,
        timeout=30.0,
    ) as response:
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/event-stream")
        body = "".join([chunk async for chunk in response.aiter_text()])
    return parse_sse(body)


class TestTheStreamIsCompleteAndOrdered:
    async def test_it_delivers_every_stage_and_ends(self, client):
        session = await open_session(client)
        run_id = await start_run(client, session)
        events = await collect(client, session, run_id)

        types = [e["type"] for e in events]
        assert types[0] == "classified"
        assert types[-1] == "end"
        for expected in ("proposed", "gate", "ablation", "attributed", "issued", "logged"):
            assert expected in types, f"missing {expected}: {types}"
        assert [e["seq"] for e in events] == sorted(e["seq"] for e in events)

    async def test_a_subscriber_never_sees_completion_with_events_outstanding(self, client):
        """The ordering bug this endpoint is most likely to have.

        `end` is emitted before `status` is read by any waiter, so a stream that observes
        a terminal state has already drained. Asserted by checking the stream's own event
        count against the run's, after the fact.
        """
        session = await open_session(client)
        run_id = await start_run(client, session)
        streamed = await collect(client, session, run_id)

        final = (await client.get(f"/v1/runs/{run_id}", headers={SESSION_HEADER: session})).json()
        assert len(streamed) == len(final["event_log"])
        assert final["status"] == "complete"

    async def test_the_ablation_events_reconcile_with_the_reported_cost(self, client):
        """Every model call the engine spent produced exactly one event.

        A feed that drops the uninteresting counterfactuals would show fewer steps than
        the cost the run reports, and nobody could tell which number was wrong.
        """
        session = await open_session(client)
        run_id = await start_run(client, session)
        events = await collect(client, session, run_id)

        ablations = [e for e in events if e["type"] == "ablation"]
        attributed = next(e for e in events if e["type"] == "attributed")
        assert len(ablations) == attributed["data"]["model_calls"]
        assert [a["data"]["sequence"] for a in ablations] == list(range(1, len(ablations) + 1))

    async def test_ablation_events_carry_hashes_and_never_text(self, client):
        """A progress feed must not become the disclosure channel."""
        secret = "CANARY-9f2c-never-stream-this"
        session = await open_session(client)
        run_id = await start_run(
            client,
            session,
            scenario="custom",
            injection=f"{secret} remittance account DE89370400440532013000",
        )
        events = await collect(client, session, run_id)

        for event in (e for e in events if e["type"] == "ablation"):
            assert secret not in json.dumps(event["data"])
            assert event["data"]["excerpt_hash"].startswith("sha256:")

    async def test_comparable_is_streamed_rather_than_left_to_be_inferred(self, client):
        """Design decision 6, on the wire.

        `invariant` (measured, nothing was pivotal) and `unknown` (every run cancelled,
        nothing was measured) both surface as zero influence. A consumer that had to tell
        them apart from the numbers alone would get it wrong, so the flag that actually
        decides it rides on every measurement -- and the stream must agree with the
        status the run finally reports.
        """
        session = await open_session(client)
        run_id = await start_run(client, session)
        events = await collect(client, session, run_id)

        ablations = [e["data"] for e in events if e["type"] == "ablation"]
        assert ablations
        assert all(isinstance(a["comparable"], bool) for a in ablations)

        statuses = set(next(e for e in events if e["type"] == "attributed")["data"][
            "argument_status"
        ].values())
        any_comparable = any(a["comparable"] for a in ablations)
        if "unknown" in statuses:
            assert not any_comparable, "a field is unknown, so no ablation may be comparable"
        if statuses & {"attributed", "invariant"}:
            assert any_comparable, "a measured field requires at least one comparable run"


class TestTheStreamIsIncrementalRatherThanBuffered:
    """The property the bundled mock cannot demonstrate.

    Attribution against an in-process deterministic model finishes in microseconds, so
    every frame of a real run arrives in the same millisecond and a wall-clock trace
    proves nothing about whether the stream is live or merely flushed at the end. These
    drive the generator directly, with the emitting side held still between pulls.
    """

    async def test_it_yields_each_event_before_the_next_one_exists(self, client):
        session_id = await open_session(client)
        session = client.app.state.sessions.get(session_id)
        run = Run(
            run_id="run_manual",
            session_id=session_id,
            scenario=custom_scenario("a document"),
            created_at="1970-01-01T00:00:00+00:00",
        )
        session.runs.add(run)

        stream = _event_stream(run, session, cursor=0, config=client.app.state.settings)
        run.emit("classified", {"segments": 5})
        first = await asyncio.wait_for(anext(stream), timeout=1.0)
        assert "event: classified" in first

        # Nothing further has been emitted; the generator must block rather than end.
        pending = asyncio.ensure_future(anext(stream))
        await asyncio.sleep(0.05)
        assert not pending.done(), "the stream ended or buffered instead of waiting"

        run.emit("ablation", {"sequence": 1})
        assert "event: ablation" in await asyncio.wait_for(pending, timeout=1.0)

        run.status = "complete"
        run.emit("end", {"status": "complete"})
        assert "event: end" in await asyncio.wait_for(anext(stream), timeout=1.0)
        with pytest.raises(StopAsyncIteration):
            await asyncio.wait_for(anext(stream), timeout=1.0)

    async def test_a_waiting_stream_sends_a_heartbeat(self, client):
        """Idle connections get reaped by proxies; a comment frame keeps them alive."""
        session_id = await open_session(client)
        session = client.app.state.sessions.get(session_id)
        run = Run(
            run_id="run_idle",
            session_id=session_id,
            scenario=custom_scenario("a document"),
            created_at="1970-01-01T00:00:00+00:00",
        )
        session.runs.add(run)

        config = ApiSettings(stream_heartbeat_seconds=0.05)
        stream = _event_stream(run, session, cursor=0, config=config)
        assert await asyncio.wait_for(anext(stream), timeout=1.0) == ": keepalive\n\n"

    async def test_the_slot_is_released_even_if_the_client_disconnects(self, client):
        """A stream abandoned mid-flight must not leak its API-STREAMS slot."""
        session_id = await open_session(client)
        session = client.app.state.sessions.get(session_id)
        run = Run(
            run_id="run_abandoned",
            session_id=session_id,
            scenario=custom_scenario("a document"),
            created_at="1970-01-01T00:00:00+00:00",
        )
        session.runs.add(run)

        stream = _event_stream(run, session, cursor=0, config=client.app.state.settings)
        run.emit("classified", {})
        await anext(stream)
        assert session.open_streams == 1

        await stream.aclose()
        assert session.open_streams == 0
        assert run._waiters == [], "an abandoned stream left its wake-up flag registered"


class TestQueueingIsVisible:
    async def test_a_run_waiting_on_the_concurrency_ceiling_says_so(self):
        """Held deterministically rather than by racing two runs.

        Against the in-process mock an attribution finishes before a second one could
        start, so contention has to be arranged rather than provoked. One slot, taken.
        """
        app = create_app(ApiSettings(max_concurrent_attributions=1))
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://api") as http:
            session = await open_session(http)
            slots = app.state.attribution_slots

            await slots.acquire()
            try:
                run_id = await start_run(http, session)
                events = await _poll_for(http, session, run_id, "queued")
                queued = next(e for e in events if e["type"] == "queued")
                assert queued["data"]["control"] == "API-CONC"

                status = (
                    await http.get(f"/v1/runs/{run_id}", headers={SESSION_HEADER: session})
                ).json()["status"]
                assert status == "running", "the run must actually be blocked, not finished"
            finally:
                slots.release()

            run = await _poll_for_status(http, session, run_id)
            assert run["status"] == "complete", "the run must proceed once a slot frees up"


async def _poll_for(http, session: str, run_id: str, event_type: str) -> list[dict]:
    for _ in range(300):
        events = (
            await http.get(f"/v1/runs/{run_id}", headers={SESSION_HEADER: session})
        ).json()["event_log"]
        if any(e["type"] == event_type for e in events):
            return events
        await asyncio.sleep(0.01)
    raise AssertionError(f"no {event_type} event was emitted")


async def _poll_for_status(http, session: str, run_id: str) -> dict:
    for _ in range(400):
        run = (await http.get(f"/v1/runs/{run_id}", headers={SESSION_HEADER: session})).json()
        if run["status"] != "running":
            return run
        await asyncio.sleep(0.01)
    raise AssertionError("run did not finish")


class TestTheStreamIsResumable:
    async def test_after_replays_from_a_sequence_number(self, client):
        session = await open_session(client)
        run_id = await start_run(client, session)
        everything = await collect(client, session, run_id)

        resumed = await collect(client, session, run_id, after=2)
        assert [e["seq"] for e in resumed] == [e["seq"] for e in everything if e["seq"] > 2]

    async def test_last_event_id_wins_over_the_query_parameter(self, client):
        session = await open_session(client)
        run_id = await start_run(client, session)
        await collect(client, session, run_id)

        async with client.stream(
            "GET",
            f"/v1/runs/{run_id}/events",
            headers={SESSION_HEADER: session, "Last-Event-ID": "4"},
            params={"after": 0},
            timeout=30.0,
        ) as response:
            body = "".join([chunk async for chunk in response.aiter_text()])
        assert [e["seq"] for e in parse_sse(body)][0] == 5

    async def test_a_malformed_last_event_id_replays_everything(self, client):
        """A browser's automatic reconnect has nobody to show a 400 to."""
        session = await open_session(client)
        run_id = await start_run(client, session)
        await collect(client, session, run_id)

        async with client.stream(
            "GET",
            f"/v1/runs/{run_id}/events",
            headers={SESSION_HEADER: session, "Last-Event-ID": "not-a-number"},
            timeout=30.0,
        ) as response:
            body = "".join([chunk async for chunk in response.aiter_text()])
        assert parse_sse(body)[0]["seq"] == 0

    async def test_two_subscribers_both_receive_everything(self, client):
        """One flag per subscriber: a shared one lets whoever clears it swallow a wake-up."""
        session = await open_session(client)
        run_id = await start_run(client, session)
        first, second = await asyncio.gather(
            collect(client, session, run_id), collect(client, session, run_id)
        )
        assert [e["seq"] for e in first] == [e["seq"] for e in second]
        assert first[-1]["type"] == "end"


class TestRefusalsNameTheControl:
    async def test_the_arrival_rate_refuses_and_says_which_control(self, client):
        session = await open_session(client)
        limit = client.app.state.settings.runs_per_minute

        statuses = []
        for _ in range(limit + 3):
            response = await client.post(
                "/v1/runs", json={"scenario": POISONED}, headers={SESSION_HEADER: session}
            )
            statuses.append(response.status_code)
            if response.status_code == 429:
                detail = response.json()["detail"]
                assert detail["control"] == "API-RATE"
                assert "T12" in detail["threat"]
        assert 429 in statuses
        assert statuses.count(202) == limit

    async def test_the_session_budget_refuses_once_it_is_spent(self, tmp_path):
        app = create_app(ApiSettings(session_model_call_budget=1, runs_per_minute=100))
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://api") as http:
            session = await open_session(http)
            run_id = await start_run(http, session)
            await collect(http, session, run_id)  # drains, so the run has finished

            response = await http.post(
                "/v1/runs", json={"scenario": POISONED}, headers={SESSION_HEADER: session}
            )
            assert response.status_code == 429
            detail = response.json()["detail"]
            assert detail["control"] == "C-18/session"
            assert "model calls" in detail["detail"]

    async def test_the_budget_is_checked_at_admission_so_overshoot_is_one_run(self, client):
        """Stated honestly rather than claimed as exact.

        A run already in flight is not aborted mid-attribution, so the spend can exceed
        the budget by at most one run's worth of C-18.
        """
        session_id = await open_session(client)
        run_id = await start_run(client, session_id)
        await collect(client, session_id, run_id)

        session = client.app.state.sessions.get(session_id)
        settings = client.app.state.settings
        assert 0 < session.model_calls_spent <= settings.max_model_calls

    async def test_concurrent_streams_are_capped_per_session(self, client):
        session = await open_session(client)
        run_id = await start_run(client, session)
        client.app.state.sessions.get(session).open_streams = 99

        response = await client.get(
            f"/v1/runs/{run_id}/events", headers={SESSION_HEADER: session}
        )
        assert response.status_code == 429
        assert response.json()["detail"]["control"] == "API-STREAMS"

    async def test_a_stream_releases_its_slot_when_it_ends(self, client):
        session_id = await open_session(client)
        run_id = await start_run(client, session_id)
        await collect(client, session_id, run_id)
        assert client.app.state.sessions.get(session_id).open_streams == 0


class TestTheLimiterIsNotItselfAnExhaustionPrimitive:
    def test_the_client_table_is_bounded(self):
        settings = ApiSettings(max_tracked_clients=8)
        limiter = ArrivalLimiter(settings)
        for n in range(500):
            limiter.check(f"client-{n}", limit=100)
        assert len(limiter) <= 8

    def test_a_blocked_client_does_not_extend_its_own_penalty(self):
        """The window is only advanced by *accepted* arrivals.

        Recording rejected attempts would let a client hammering the endpoint push its
        own window forward forever and never recover.
        """
        limiter = ArrivalLimiter(ApiSettings())
        limiter.check("k", limit=1)
        for _ in range(5):
            with pytest.raises(HTTPException) as raised:
                limiter.check("k", limit=1)
            assert raised.value.status_code == 429
        assert limiter.window_size("k") == 1

    async def test_a_forged_forwarded_header_cannot_pick_the_bucket_by_default(self, client):
        """Honouring X-Forwarded-For unconditionally is worse than having no limiter.

        Every request below claims a different source address. With the header untrusted
        they all land in one bucket and the limit still bites.
        """
        assert client.app.state.settings.trust_forwarded_for is False
        limit = client.app.state.settings.sessions_per_minute

        statuses = []
        for n in range(limit + 2):
            response = await client.post(
                "/v1/sessions", headers={"X-Forwarded-For": f"10.0.0.{n}"}
            )
            statuses.append(response.status_code)
        assert 429 in statuses
        assert statuses.count(201) == limit
