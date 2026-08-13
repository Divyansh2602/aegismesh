"""CORS, the attack lab, and replay (Phase 6a).

These are the endpoints the console needs that Phase 5 did not build. The assertions are
on the properties that make them safe to expose rather than on their response shapes:
that attacking the log does not damage the log, that a dishonest issuer still loses at the
relying party, that a refusal stays readable to the browser it refuses, and that the one
endpoint which spends a second attribution's worth of model calls bills the visitor for
them.
"""

from __future__ import annotations

import asyncio

import httpx
import pytest

from aegis.api.app import SESSION_HEADER, create_app
from aegis.api.config import ApiSettings

POISONED = "injection_via_conduit_tool"
CONSOLE = "http://localhost:3000"


def build_app(**overrides):
    return create_app(ApiSettings(**overrides))


@pytest.fixture
async def client():
    app = build_app()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://api") as http:
        http.app = app
        yield http


async def open_session(http: httpx.AsyncClient) -> str:
    response = await http.post("/v1/sessions")
    assert response.status_code == 201
    return response.json()["session_id"]


async def run_to_completion(http: httpx.AsyncClient, session: str, **body) -> dict:
    headers = {SESSION_HEADER: session}
    started = await http.post("/v1/runs", json=body or {"scenario": POISONED}, headers=headers)
    assert started.status_code == 202
    run_id = started.json()["run_id"]

    for _ in range(400):
        current = (await http.get(f"/v1/runs/{run_id}", headers=headers)).json()
        if current["status"] != "running":
            assert current["status"] == "complete", current.get("error")
            return current
        await asyncio.sleep(0.01)
    raise AssertionError("run did not finish")


class TestTheConsoleCanReachTheApiAndOtherOriginsCannot:
    async def test_the_configured_origin_is_allowed(self, client):
        response = await client.get("/health", headers={"Origin": CONSOLE})
        assert response.headers["access-control-allow-origin"] == CONSOLE

    async def test_an_unlisted_origin_gets_no_grant(self, client):
        response = await client.get("/health", headers={"Origin": "https://evil.example"})
        assert response.status_code == 200
        assert "access-control-allow-origin" not in response.headers

    async def test_the_session_header_survives_a_preflight(self, client):
        response = await client.request(
            "OPTIONS",
            "/v1/runs",
            headers={
                "Origin": CONSOLE,
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": SESSION_HEADER,
            },
        )
        assert response.status_code == 200
        allowed = response.headers["access-control-allow-headers"].lower()
        assert SESSION_HEADER.lower() in allowed

    async def test_credentials_are_never_granted(self, client):
        """Sessions travel in a header the caller chooses to send, which is what leaves
        this service with no CSRF surface. Granting credentials would hand that back."""
        response = await client.get("/health", headers={"Origin": CONSOLE})
        assert "access-control-allow-credentials" not in response.headers

    async def test_a_refused_request_is_still_readable_by_the_browser(self, client):
        """The ordering property, and the reason it matters.

        Every refusal in this API names the control that refused it, which is a
        demonstration of the threat model rather than a bare 429. A refusal that comes
        back without CORS headers is a network error in the console -- the design's most
        deliberate response, rendered as a browser-level failure with no body.
        """
        session = await open_session(client)
        oversized = "A" * 70_000
        response = await client.post(
            "/v1/runs",
            json={"scenario": "custom", "injection": oversized},
            headers={SESSION_HEADER: session, "Origin": CONSOLE},
        )
        assert response.status_code == 413
        assert response.headers["access-control-allow-origin"] == CONSOLE
        assert response.json()["detail"]["control"] == "API-SIZE"

    async def test_cors_can_be_switched_off_entirely(self):
        app = create_app(ApiSettings(cors_origins=""))
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://api") as http:
            response = await http.get("/health", headers={"Origin": CONSOLE})
            assert "access-control-allow-origin" not in response.headers


class TestTheAttackLabDrivesTheRealDefence:
    async def test_the_catalogue_is_reachable_and_not_swallowed_by_the_stage_route(
        self, client
    ):
        """``/{stage}`` is a catch-all registered in the same router. If the attack
        catalogue were declared after it, this would 409 with "no attacks stage"."""
        session = await open_session(client)
        run = await run_to_completion(client, session)
        response = await client.get(
            f"/v1/runs/{run['run_id']}/attacks", headers={SESSION_HEADER: session}
        )
        assert response.status_code == 200
        assert {a["name"] for a in response.json()["attacks"]} == {
            "tamper_attribution",
            "forge_permit",
            "fork_log",
            "replay_arguments",
        }

    async def test_editing_a_signed_score_breaks_the_signature(self, client):
        session = await open_session(client)
        run = await run_to_completion(client, session)
        response = await client.post(
            f"/v1/runs/{run['run_id']}/attacks/tamper_attribution",
            headers={SESSION_HEADER: session},
        )
        assert response.status_code == 200
        result = response.json()
        assert result["defended"] is True
        assert result["enforcement"]["verdict"] == "REJECT"
        # Step 3 is proof verification. It is the step that must fail; the others failing
        # too is a bonus, not the claim.
        assert 3 in result["enforcement"]["failed_steps"]
        assert result["mutation"]["after"] == {"P0": "1.0000"}
        # The mutation has to change the document. Selecting whichever field sorted first
        # picked `amount`, which the human genuinely set and which already read P0 1.0000
        # -- so the "tamper" rewrote a value to itself, the bytes never changed, and the
        # signature passed. The attack reported a defence that had not happened.
        assert result["mutation"]["before"] != result["mutation"]["after"]

    async def test_the_tampered_field_is_one_the_measurement_actually_blamed_elsewhere(
        self, client
    ):
        """Whitewashing to P0 only demonstrates anything if the field was not already P0."""
        session = await open_session(client)
        run = await run_to_completion(client, session)
        result = (
            await client.post(
                f"/v1/runs/{run['run_id']}/attacks/tamper_attribution",
                headers={SESSION_HEADER: session},
            )
        ).json()
        assert result["mutation"]["field"] == "destination_account"
        assert result["mutation"]["before"] == {"P3": "1.0000"}

    async def test_a_genuinely_signed_permit_is_still_refused_by_the_relying_party(
        self, client
    ):
        """The crux of the whole design: the issuer's verdict travels as a claim."""
        session = await open_session(client)
        run = await run_to_completion(client, session)
        response = await client.post(
            f"/v1/runs/{run['run_id']}/attacks/forge_permit",
            headers={SESSION_HEADER: session},
        )
        assert response.status_code == 200
        result = response.json()
        assert result["mutation"]["genuinely_signed"] is True
        assert result["enforcement"]["issuer_decision"] == "permit"
        assert result["enforcement"]["verdict"] == "REJECT"
        assert result["defended"] is True

    async def test_moving_a_warrant_onto_bigger_arguments_is_refused(self, client):
        session = await open_session(client)
        run = await run_to_completion(client, session)
        response = await client.post(
            f"/v1/runs/{run['run_id']}/attacks/replay_arguments",
            headers={SESSION_HEADER: session},
        )
        result = response.json()
        assert result["defended"] is True
        # Step 5 is the arguments binding, control C-14.
        assert 5 in result["enforcement"]["failed_steps"]
        assert result["mutation"]["presented"] != result["mutation"]["authorised"]

    async def test_the_fork_is_detected(self, client):
        session = await open_session(client)
        run = await run_to_completion(client, session)
        response = await client.post(
            f"/v1/runs/{run['run_id']}/attacks/fork_log", headers={SESSION_HEADER: session}
        )
        result = response.json()
        assert result["defended"] is True
        assert result["witness"]["fork_detected"] is True
        assert result["witness"]["serves_a_root_now"] is False
        # Both heads are authentic. That is what makes this undetectable by signature.
        assert result["mutation"]["shadow_head_verifies_under_the_log_key"] is True

    async def test_forking_does_not_touch_the_shared_log(self, client):
        """The safety property this endpoint is designed around.

        Every visitor's receipt is checked against a root derived from the shared log. An
        attack that genuinely forked it would invalidate proofs already handed to people
        who are not attacking anything, so the demonstration must build its own tree.
        """
        session = await open_session(client)
        run = await run_to_completion(client, session)
        before = (await client.get("/v1/log")).json()

        await client.post(
            f"/v1/runs/{run['run_id']}/attacks/fork_log", headers={SESSION_HEADER: session}
        )

        after = (await client.get("/v1/log")).json()
        assert after["tree_size"] == before["tree_size"]
        assert after["signed_tree_head"]["root_hash"] == before["signed_tree_head"]["root_hash"]

    async def test_forking_leaves_the_visitors_own_witness_intact(self, client):
        """A witness that has seen a fork serves no root at all, permanently. If the
        attack used the session's witness, one click would break that visitor's own
        artifact downloads for the rest of the session."""
        session = await open_session(client)
        run = await run_to_completion(client, session)
        await client.post(
            f"/v1/runs/{run['run_id']}/attacks/fork_log", headers={SESSION_HEADER: session}
        )
        witness = (await client.get("/v1/witness", headers={SESSION_HEADER: session})).json()
        assert witness["root"] is not None

        artifacts = await client.get(
            f"/v1/runs/{run['run_id']}/artifacts", headers={SESSION_HEADER: session}
        )
        assert artifacts.status_code == 200

    async def test_an_unknown_attack_is_refused(self, client):
        session = await open_session(client)
        run = await run_to_completion(client, session)
        response = await client.post(
            f"/v1/runs/{run['run_id']}/attacks/drop_tables",
            headers={SESSION_HEADER: session},
        )
        assert response.status_code == 404

    async def test_one_session_cannot_attack_another_sessions_run(self, client):
        mine = await open_session(client)
        theirs = await open_session(client)
        run = await run_to_completion(client, mine)
        response = await client.post(
            f"/v1/runs/{run['run_id']}/attacks/tamper_attribution",
            headers={SESSION_HEADER: theirs},
        )
        assert response.status_code == 404

    async def test_the_same_run_attacked_twice_produces_the_same_mutation(self, client):
        """A demonstration that is not repeatable is not a demonstration."""
        session = await open_session(client)
        run = await run_to_completion(client, session)
        headers = {SESSION_HEADER: session}
        first = await client.post(
            f"/v1/runs/{run['run_id']}/attacks/tamper_attribution", headers=headers
        )
        second = await client.post(
            f"/v1/runs/{run['run_id']}/attacks/tamper_attribution", headers=headers
        )
        assert first.json()["mutation"] == second.json()["mutation"]


class TestFailuresDoNotLeakTheInside:
    async def test_an_unhandled_error_returns_an_incident_id_not_a_traceback(self):
        """A stack trace tells a stranger the framework, the file layout and often a
        fragment of state, and helps the caller with none of it."""
        app = build_app()

        @app.get("/boom")
        async def boom():  # pragma: no cover - exists only to raise
            raise RuntimeError("secret-internal-detail-xyz")

        transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
        async with httpx.AsyncClient(transport=transport, base_url="http://api") as http:
            response = await http.get("/boom")

        assert response.status_code == 500
        body = response.text
        assert "secret-internal-detail-xyz" not in body
        assert "Traceback" not in body
        assert response.json()["incident"].startswith("inc_")

    async def test_a_control_refusal_still_names_its_control(self, client):
        """The generic handler must not swallow the refusals that are the point. Control
        refusals are HTTPExceptions and are handled before it ever runs."""
        session = await open_session(client)
        response = await client.post(
            "/v1/runs",
            json={"scenario": "custom", "injection": "A" * 70_000},
            headers={SESSION_HEADER: session},
        )
        assert response.status_code == 413
        assert response.json()["detail"]["control"] == "API-SIZE"


class TestTheScoredSweepIsTheComparison:
    async def test_the_sweep_scores_every_labelled_case(self, client):
        session = await open_session(client)
        response = await client.post("/v1/evaluation", headers={SESSION_HEADER: session})
        assert response.status_code == 200
        report = response.json()
        assert report["cases"] == 7
        assert len(report["outcomes"]) == 7

    async def test_the_clean_cases_are_not_flagged(self, client):
        """The rows that decide whether the control is deployable.

        A detector that flags everything scores perfectly on the poisoned cases. These are
        what make the poisoned results mean anything, so a regression here matters more
        than a regression in recall.
        """
        session = await open_session(client)
        report = (
            await client.post("/v1/evaluation", headers={SESSION_HEADER: session})
        ).json()
        clean = [o for o in report["outcomes"] if not o["poisoned"]]
        assert clean, "the case set must contain negatives"
        assert all(not o["flagged"] for o in clean)
        assert report["precision"] == 1.0

    async def test_the_effective_injections_are_caught(self, client):
        session = await open_session(client)
        report = (
            await client.post("/v1/evaluation", headers={SESSION_HEADER: session})
        ).json()
        effective = [o for o in report["outcomes"] if o["effective"]]
        assert effective
        assert all(o["flagged"] for o in effective)

    async def test_the_sweep_bills_the_session(self, client):
        """Seven attributions for one arrival is the most work a single permitted request
        can buy, so it is the endpoint most worth billing correctly."""
        session = await open_session(client)
        headers = {SESSION_HEADER: session}
        before = (await client.get("/v1/sessions/me", headers=headers)).json()
        report = (await client.post("/v1/evaluation", headers=headers)).json()
        after = (await client.get("/v1/sessions/me", headers=headers)).json()
        spent = after["model_calls_spent"] - before["model_calls_spent"]
        assert spent == report["model_calls"] > 0

    async def test_the_sweep_is_rate_limited_more_tightly_than_a_run(self, client):
        session = await open_session(client)
        headers = {SESSION_HEADER: session}
        seen = []
        for _ in range(4):
            seen.append((await client.post("/v1/evaluation", headers=headers)).status_code)
        assert 429 in seen, "an endpoint costing seven attributions must be bounded"


class TestReplayIsAuditedAndBilled:
    async def test_an_honest_warrant_replays_consistently(self, client):
        session = await open_session(client)
        run = await run_to_completion(client, session)
        response = await client.post(
            f"/v1/runs/{run['run_id']}/replay", headers={SESSION_HEADER: session}
        )
        assert response.status_code == 200
        report = response.json()
        assert report["verdict"] == "consistent"
        assert report["contradictions"] == 0

    async def test_the_replay_bills_the_session_budget(self, client):
        """Replay is a second attribution. Left unbilled it is the cheapest denial of
        service on the surface -- unlimited model calls under a different route name."""
        session = await open_session(client)
        headers = {SESSION_HEADER: session}
        await run_to_completion(client, session)
        run = (await client.get("/v1/runs", headers=headers)).json()["runs"][0]

        before = (await client.get("/v1/sessions/me", headers=headers)).json()
        response = await client.post(f"/v1/runs/{run['run_id']}/replay", headers=headers)
        after = (await client.get("/v1/sessions/me", headers=headers)).json()

        spent = after["model_calls_spent"] - before["model_calls_spent"]
        assert spent > 0
        assert spent == response.json()["model_calls"]

    async def test_a_run_with_no_warrant_cannot_be_replayed(self, client):
        session = await open_session(client)
        response = await client.post(
            "/v1/runs/run_does_not_exist/replay", headers={SESSION_HEADER: session}
        )
        assert response.status_code == 404

    async def test_replay_states_which_model_produced_it(self, client):
        session = await open_session(client)
        run = await run_to_completion(client, session)
        response = await client.post(
            f"/v1/runs/{run['run_id']}/replay", headers={SESSION_HEADER: session}
        )
        assert "mock" in response.json()["model"].lower()
