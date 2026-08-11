"""Per-visitor state, and the one thing every visitor shares.

**Shared: the transparency log.** A visitor who only ever sees a tree they grew
themselves has been shown a data structure, not a transparency log. The property worth
demonstrating is that the tree contains other people's entries, keeps growing between
visits, and still produces a consistency proof bridging the head you were given last
time to the head you are given now. That requires one log.

**Per-session: everything else.** Issuer key, issuer DID, policy, PEP and replay cache
are all per-visitor, so nothing a stranger submits can move another visitor's state, and
a warrant minted in one session cannot be replayed into another -- it is signed by a key
that session's PEP will not resolve.

The log being shared makes it shared mutable state reachable by strangers, which is a
real exposure and is treated as one: entries are canonicalized warrant documents, and a
warrant carries excerpt *hashes* rather than excerpt text (see ``warrant/issuer.py``).
No text a visitor submits is ever stored in the shared log or served to another visitor.
"""

from __future__ import annotations

import time
from collections import OrderedDict
from dataclasses import dataclass, field

from aegis.api.config import ApiSettings
from aegis.api.runs import RunStore
from aegis.api.scenarios import KNOWN_MANIFESTS
from aegis.common.ids import prefixed_id
from aegis.log.log import TransparencyLog
from aegis.log.witness import Witness
from aegis.pep.verifier import PolicyEnforcementPoint
from aegis.policy.library import acme_treasury_policy, operator_issuer_policy
from aegis.warrant.issuer import WarrantIssuer
from aegis.warrant.keys import KeyRing, SigningKey


@dataclass
class Session:
    """One visitor's issuing and enforcing state."""

    session_id: str
    created_at: float
    issuer_key: SigningKey
    issuer_did: str
    verification_method: str
    keyring: KeyRing
    issuer: WarrantIssuer
    witness: Witness
    pep: PolicyEnforcementPoint
    runs: RunStore
    decisions: list[dict] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "issuer_did": self.issuer_did,
            "verification_method": self.verification_method,
            "issuer_public_key_multibase": self.issuer_key.public.to_multibase(),
            "runs": len(self.runs),
            "witnessed_tree_size": self.witness.tree_size,
            "relying_party_decisions": len(self.decisions),
        }


def build_session(log: TransparencyLog, settings: ApiSettings) -> Session:
    """Mint a session with its own freshly generated issuer key.

    The key is generated, not derived from the session id. A key derivable from an
    identifier that travels in a header would be a private key anyone holding the header
    could reconstruct -- harmless for a demo signing demo warrants, and exactly the habit
    this project exists to argue against.
    """
    session_id = prefixed_id("ses")
    issuer_key = SigningKey.generate()
    issuer_did = f"did:web:aegis.acme-bank.example:sessions:{session_id}"
    verification_method = f"{issuer_did}#key-1"

    keyring = KeyRing()
    keyring.register(verification_method, issuer_key.public)

    decisions: list[dict] = []
    # The witness observes the shared log from whatever size it is at now. Its first
    # accepted head is the visitor's own baseline, so the consistency proof it can later
    # produce covers exactly the growth it personally witnessed.
    witness = Witness(log_id=log.log_id, log_key=log.signing_key.public)

    return Session(
        session_id=session_id,
        created_at=time.monotonic(),
        issuer_key=issuer_key,
        issuer_did=issuer_did,
        verification_method=verification_method,
        keyring=keyring,
        issuer=WarrantIssuer(
            issuer_did=issuer_did,
            signing_key=issuer_key,
            verification_method=verification_method,
            policy=operator_issuer_policy(),
        ),
        witness=witness,
        pep=PolicyEnforcementPoint(
            keyring=keyring,
            policy=acme_treasury_policy(),
            witness=witness,
            known_manifests=set(KNOWN_MANIFESTS),
            decision_sink=decisions.append,
        ),
        runs=RunStore(limit=settings.max_runs_per_session),
        decisions=decisions,
    )


class SessionStore:
    """Bounded, oldest-evicted store of live sessions.

    Bounded because this process is meant to stay up: an unbounded dict keyed by
    something a stranger can create is a memory exhaustion primitive with no attacker
    skill required. Eviction is by insertion order rather than by last use, so a single
    visitor cannot pin the table by refreshing.
    """

    def __init__(self, settings: ApiSettings) -> None:
        self.settings = settings
        self._sessions: OrderedDict[str, Session] = OrderedDict()

    def __len__(self) -> int:
        return len(self._sessions)

    def create(self, log: TransparencyLog) -> Session:
        self._evict_expired()
        session = build_session(log, self.settings)
        self._sessions[session.session_id] = session
        while len(self._sessions) > self.settings.max_sessions:
            self._sessions.popitem(last=False)
        return session

    def get(self, session_id: str | None) -> Session | None:
        self._evict_expired()
        if not session_id:
            return None
        return self._sessions.get(session_id)

    def _evict_expired(self) -> None:
        cutoff = time.monotonic() - self.settings.session_ttl_seconds
        expired = [sid for sid, s in self._sessions.items() if s.created_at < cutoff]
        for sid in expired:
            del self._sessions[sid]
