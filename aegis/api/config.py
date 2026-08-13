"""Settings for the public API.

Every bound here exists because this service is reachable by people who are not trying
to be helpful. The ones that are genuinely *abuse controls* -- per-IP rate limits, the
session-scoped call budget -- arrive in Phase 5b and are named as such in the threat
model. What is set here in 5a is the smaller category: bounds without which a single
request can consume the process, and bounds that keep long-lived stores from growing
without limit.
"""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class ApiSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AEGIS_API_", extra="ignore")

    log_id: str = "did:web:log.aegismesh.example"
    log_seed: str = "aegis-public-log"
    """Seed for the log's signing key.

    Deterministic so that a restart does not orphan every root already handed out: a log
    whose key changes is a log whose entire signed history stops verifying. It must be
    overridden in a real deployment, where it belongs in a secrets manager rather than in
    a default -- the value here is a demo key and is published in this file, which is
    exactly why it must never sign anything that matters.
    """

    log_database: str = ""
    """Path to the SQLite file backing the log. Empty means in-memory.

    Empty is the right default for tests and for anyone running this locally; the
    deployed service sets it, and the log only demonstrates its append-only property
    across restarts when it is set.
    """

    cors_origins: str = "http://localhost:3000,http://127.0.0.1:3000"
    """Comma-separated browser origins allowed to call this API.

    An allowlist rather than ``*``, and credentials are disabled at the middleware. Both
    are worth stating because the obvious objection is that CORS protects browsers rather
    than servers -- ``curl`` ignores it entirely, so a wildcard would add no server-side
    exposure *today*. The reason it is still not the default is that the safety of a
    wildcard rests on a property of this service that is one commit away from changing:
    sessions travel in ``X-Aegis-Session`` and nothing is attached automatically. The day
    anyone introduces a cookie, a wildcard silently becomes a real hole, whereas an
    allowlist stays correct. The narrow default is the one that does not depend on
    remembering why the wide one was safe.

    The deployed console's origin is set here in Phase 7; empty disables CORS entirely.
    """

    max_sessions: int = 200
    max_runs_per_session: int = 25
    session_ttl_seconds: int = 7200

    session_model_call_budget: int = 1500
    """Total ablations one visitor may cause, across every run in their session.

    This is the aggregate above control C-18, which caps a *single* attribution. Without
    it, C-18 bounds each run and nothing bounds the number of runs.

    It also bounds memory, which is the less obvious half. Each ablation appends one event
    to the run that produced it, so retained events are
    ``max_sessions x session_model_call_budget`` in the worst case -- 200 x 1500 at these
    defaults, a few hundred megabytes of small objects. Raising either number without
    doing that multiplication is how a service that survives an attacker falls over under
    ordinary popularity.
    """

    runs_per_minute: int = 6
    sessions_per_minute: int = 10

    evaluations_per_minute: int = 2
    """Scored sweeps of the whole labelled case set, per client.

    Tighter than ``runs_per_minute`` because one call is seven attributions rather than
    one — roughly fifty model calls for a single arrival. Rate limits bound *when*, and
    this is the endpoint where a single permitted arrival buys the most work.
    """
    max_concurrent_attributions: int = 4
    """Attributions allowed to run at once, process-wide.

    The per-run and per-session ceilings bound *totals*; this bounds the instantaneous
    load. Ten visitors starting a forty-call attribution in the same second is ordinary
    traffic, not an attack, and it is what actually stalls the box.
    """

    max_streams_per_session: int = 4
    max_request_bytes: int = 65_536
    max_tracked_clients: int = 2048
    stream_heartbeat_seconds: float = 15.0
    """How long a stream waits before sending a comment frame.

    Proxies and load balancers reap idle connections, and an attribution can spend longer
    than that queued behind API-CONC without emitting anything.
    """

    trust_forwarded_for: bool = False
    """Whether ``X-Forwarded-For`` may set the rate-limit key.

    Off by default. A deployment behind a proxy it controls turns it on; anywhere else,
    honouring it lets a caller choose their own bucket by sending a header, which is worse
    than no limiter because it looks like one.
    """

    max_injection_chars: int = 4000
    """Hard cap on visitor-authored document text.

    Attribution costs O(segments) model calls, so unbounded submitted text is a cost
    amplifier -- threat T12 in our own threat model, re-instantiated the moment this is
    opened to the public. The full control (C-18, plus per-IP limits) is Phase 5b's
    subject; refusing an unbounded string is not a control so much as the absence of an
    obvious hole, and it does not belong in a later phase.
    """

    max_model_calls: int = 400
    """Passed to the engine's own ``max_model_calls`` (control C-18).

    Deliberately the engine's existing knob rather than a new limiter invented for the
    API. When a visitor hits it, the response says which control stopped them, because a
    limit that demonstrates the threat model is worth more than one that hides it.
    """

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]


settings = ApiSettings()
