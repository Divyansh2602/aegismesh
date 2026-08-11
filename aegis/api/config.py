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

    max_sessions: int = 500
    max_runs_per_session: int = 25
    session_ttl_seconds: int = 7200

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


settings = ApiSettings()
