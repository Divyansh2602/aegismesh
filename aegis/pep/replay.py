"""Nonce replay cache (control C-14).

Bounded by time rather than by size. A cache that evicts by count can be flushed by an
attacker who floods it with junk nonces and then replays the one they wanted -- eviction
pressure becomes the attack. Eviction by expiry cannot be forced that way, and a warrant
past its ``validUntil`` is rejected by step 4 regardless, so nothing needs remembering
longer than the validity window.

Local to one enforcement point. Two PEPs do not share a cache here, so a warrant could be
replayed once at each. Real deployments need a shared cache or per-PEP audience binding;
that is noted in THREAT_MODEL.md rather than silently assumed away.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

#: Comfortably longer than a warrant's five-minute validity, so a nonce never falls out of
#: the cache while the warrant carrying it is still acceptable.
DEFAULT_RETENTION = timedelta(minutes=15)


class ReplayCache:
    def __init__(self, retention: timedelta = DEFAULT_RETENTION) -> None:
        self.retention = retention
        self._seen: dict[str, datetime] = {}

    def check_and_record(self, nonce: str, now: datetime | None = None) -> bool:
        """Return True if this nonce is fresh, recording it. False if it is a replay."""
        now = now or datetime.now(UTC)
        self._expire(now)
        if nonce in self._seen:
            return False
        self._seen[nonce] = now
        return True

    def _expire(self, now: datetime) -> None:
        cutoff = now - self.retention
        for nonce in [n for n, seen in self._seen.items() if seen < cutoff]:
            del self._seen[nonce]

    def __len__(self) -> int:
        return len(self._seen)
