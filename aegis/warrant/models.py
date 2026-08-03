"""The Action Warrant credential, as specified in docs/SPEC.md section 4.

A W3C Verifiable Credential rather than a bespoke format, because the identity layer this
has to sit next to -- DIDs, CoSAI on-behalf-of chains, DIF KYA-OS -- is converging on VC,
and a format only we can read is a format only we will use.

Two representation choices are load-bearing and are not cosmetic:

**Every score is a fixed-precision string.** See ``aegis/common/decimals.py``. A float here
puts our known JCS number-formatting deviation directly onto the third-party verification
path, which is the one property the design cannot lose.

**Timestamps are stored as strings, not datetimes.** The signature covers bytes. A model
that reconstitutes a ``datetime`` and re-serializes it has introduced a second chance to
produce different bytes from the same logical value -- offset formatting, microsecond
truncation, ``+00:00`` versus ``Z``. Carrying the string through untouched removes the
opportunity.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

WARRANT_CONTEXT = [
    "https://www.w3.org/ns/credentials/v2",
    "https://aegismesh.dev/ns/warrant/v1",
]
WARRANT_TYPE = ["VerifiableCredential", "ActionWarrant"]
CRYPTOSUITE = "eddsa-jcs-2022"
PROOF_TYPE = "DataIntegrityProof"

#: A warrant authorizes one action, now. Not a session (SPEC.md section 4.1).
DEFAULT_VALIDITY = timedelta(minutes=5)

Decision = Literal["permit", "deny", "permit_with_obligations"]


def utc_now() -> datetime:
    return datetime.now(UTC)


def iso(moment: datetime) -> str:
    """Second-precision UTC with a ``Z`` suffix -- one spelling, always."""
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(text: str) -> datetime:
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


class _Model(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")
    """``extra="allow"`` so a warrant issued by a newer implementation round-trips through
    an older verifier without silently dropping fields the signature covers."""


class ActionClaim(_Model):
    tool: str
    operation: str
    arguments_hash: str
    arguments_digest_map: dict[str, str] = Field(default_factory=dict)
    """Per-field digests, so a relying party can write field-level policy without the
    warrant ever carrying a field's value. The relying party already holds the arguments;
    it recomputes and compares."""

    nonce: str
    consequential: bool = True


class MandateScope(_Model):
    action_classes: list[str] = Field(default_factory=list)
    constraints: dict[str, Any] = Field(default_factory=dict)


class MandateClaim(_Model):
    id: str
    principal: str
    authenticated_at: str
    auth_method: str
    scope: MandateScope
    expires_at: str


class DelegationHop(_Model):
    hop: int
    actor: str
    kind: Literal["human", "agent"]
    scope: list[str] = Field(default_factory=list)
    manifest_hash: str | None = None
    attenuated: bool = False


class ContributorClaim(_Model):
    """One segment's measured influence. Hashes only -- never excerpt text.

    A warrant crosses organizational boundaries. Embedding the text of a document the
    agent read would leak the operator's business data to every relying party, and would
    make the warrant itself a disclosure risk. The auditor confirms a suspected excerpt by
    hashing it (SPEC.md section 4.1).
    """

    segment_id: str
    cls: str = Field(alias="class")
    origin: str | None = None
    influence: str
    excerpt_hash: str
    granularity: str = "segment"


class ReplayRef(_Model):
    """What an auditor needs to re-run the attribution and check we told the truth.

    This exists because the transparency log proves the issuer *said* something, not that
    it was *true*. A dishonest operator (ADV-4) runs the issuer and can sign a warrant
    claiming the human caused a field the attacker set. Nothing downstream detects that.

    Carrying the trace hash and the ordered segment hashes makes the claim falsifiable: an
    auditor granted the underlying trace re-runs leave-one-out ablation over the same
    segments in the same order and compares. The re-run verifier is Phase 4 work; the
    fields are emitted now because they sit under the signature, and adding them later
    would either invalidate every warrant already issued or fork the format.

    ``seed`` is recorded, not relied upon. Many hosted APIs accept a seed without honouring
    it, so it is a hint for reproduction rather than a guarantee of it.
    """

    trace_hash: str
    segment_hashes: list[str] = Field(default_factory=list)
    model_ref: str = ""
    method_version: str = ""
    seed: int | None = None


class AttributionClaim(_Model):
    method: str = "loo-ablation"
    method_version: str = "0.1.0"
    granularity: list[str] = Field(default_factory=list)
    resamples: int = 1
    model_ref: str = ""

    influence: dict[str, str] = Field(default_factory=dict)
    necessity: dict[str, str] = Field(default_factory=dict)
    """Which classes the action *required*, kept strictly apart from which set its field
    values. Removing the human's mandate cancels the payment, which says nothing about
    where the money went; summing the two produces the exact inversion this project exists
    to prevent."""

    per_argument: dict[str, dict[str, str]] = Field(default_factory=dict)

    argument_status: dict[str, str] = Field(default_factory=dict)
    """Per field: ``attributed``, ``invariant``, or ``unknown``.

    A distribution alone cannot distinguish "no class was pivotal for this value" from "we
    were unable to measure anything", because both appear as an absence of weight. The
    relying party's policy needs them apart: the first describes a legitimately
    overdetermined field, the second is grounds to fail closed.
    """

    per_argument_confidence: dict[str, str] = Field(default_factory=dict)
    """Confidence in each field's attribution, which is the unit policy should reason over.

    An action-level number averages away the case this project exists for -- an action
    simultaneously legitimate in one field and hijacked in another."""

    top_contributors: list[ContributorClaim] = Field(default_factory=list)
    confidence: str = "0.0000"
    replay_ref: ReplayRef | None = None


class PolicyDecisionClaim(_Model):
    """The issuer's conclusion. Evidence for the relying party, not a verdict.

    A relying party that honours this field instead of evaluating its own policy has
    learned nothing from the warrant that a plain API response would not have told it, and
    has re-established exactly the trust in the operator that the design removes.
    """

    policy_id: str
    policy_version: str
    policy_hash: str
    decision: Decision
    rules_fired: list[str] = Field(default_factory=list)
    obligations: list[str] = Field(default_factory=list)


class Environment(_Model):
    tool_descriptions_hash: str = ""
    """Drift detection for ASI04: tool descriptions that changed since pinning."""

    agent_runtime: str = ""


class CredentialSubject(_Model):
    action: ActionClaim
    mandate: MandateClaim
    delegation_chain: list[DelegationHop] = Field(default_factory=list)
    attribution: AttributionClaim
    policy_decision: PolicyDecisionClaim
    environment: Environment = Field(default_factory=Environment)


class Proof(_Model):
    type: str = PROOF_TYPE
    cryptosuite: str = CRYPTOSUITE
    created: str
    verificationMethod: str
    proofPurpose: str = "assertionMethod"
    proofValue: str | None = None


class ActionWarrant(_Model):
    context: list[str] = Field(default_factory=lambda: list(WARRANT_CONTEXT), alias="@context")
    type: list[str] = Field(default_factory=lambda: list(WARRANT_TYPE))
    id: str
    issuer: str
    validFrom: str
    validUntil: str
    credentialSubject: CredentialSubject
    proof: Proof | None = None

    def to_document(self) -> dict:
        """The exact JSON object that is signed, logged, and transmitted.

        ``exclude_none`` drops unset optional fields rather than emitting ``null``. Both
        forms are legal JSON and they canonicalize differently, so the choice is arbitrary
        but must be made once -- and a verifier never re-derives this, it canonicalizes the
        document it received.
        """
        return self.model_dump(by_alias=True, mode="json", exclude_none=True)

    @classmethod
    def from_document(cls, document: dict) -> ActionWarrant:
        return cls.model_validate(document)

    def unsecured(self) -> dict:
        """The document without its proof, which is half of what the signature covers."""
        document = self.to_document()
        document.pop("proof", None)
        return document

    def is_valid_at(self, moment: datetime) -> bool:
        return parse_iso(self.validFrom) <= moment <= parse_iso(self.validUntil)
