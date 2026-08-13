"""EU AI Act Article 12 export — and an explicit statement of what it does not discharge.

Article 12 requires high-risk AI systems to record events automatically over their
lifetime, such that the operation of the system is traceable. Enforceable since
**2 August 2026**. No finalised technical standard exists (prEN 18229-1 and ISO/IEC DIS
24970 remain drafts), which is why a warrant is mapped onto the *obligations* here rather
than onto a schema nobody has ratified.

## The part that makes this worth writing

Compliance exports are usually optimistic by construction: they enumerate what the system
does and imply the rest. This one enumerates what it does **not** do with the same weight,
because an export that overstates coverage is worse than none — it converts an open gap
into a documented false assurance, and a supervisory authority reading it later will be
reading a claim somebody signed.

So every requirement carries a ``coverage`` of ``covered``, ``partial`` or ``not_covered``,
and the partial ones say what is missing rather than rounding themselves up. Three of the
seven are not fully covered, and that is the honest shape of a Phase 8 system.

**This module is not legal advice and produces no certification.** It maps a technical
artefact onto a reading of a legal text; whether that reading satisfies a given deployment
is a question for the deployer's counsel, and the export says so in its own output.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

Coverage = Literal["covered", "partial", "not_covered"]

#: The date the obligation became enforceable. Recorded because "we are working towards
#: compliance" reads differently before and after it, and it is behind us.
ENFORCEABLE_FROM = "2026-08-02"

DISCLAIMER = (
    "This export maps a technical artefact onto a reading of Article 12. It is not legal "
    "advice, it is not a certification, and it does not by itself establish compliance. "
    "Requirements marked `partial` or `not_covered` are gaps in this system, stated so "
    "that they are not mistaken for coverage."
)


@dataclass
class Requirement:
    """One Article 12 obligation, and what the warrant actually shows about it."""

    ref: str
    obligation: str
    coverage: Coverage
    mechanism: str
    gap: str = ""
    """What is missing. Required whenever coverage is not ``covered``."""

    evidence: dict[str, Any] = field(default_factory=dict)
    """Fields lifted from the warrant that substantiate the mechanism, not just describe it."""

    def as_dict(self) -> dict:
        payload = {
            "ref": self.ref,
            "obligation": self.obligation,
            "coverage": self.coverage,
            "mechanism": self.mechanism,
            "evidence": self.evidence,
        }
        if self.gap:
            payload["gap"] = self.gap
        return payload


def export(warrant: dict, receipt: dict | None = None) -> dict:
    """Build the Article 12 record for one warrant.

    ``receipt`` is optional and its absence is *reported* rather than ignored: without it
    there is no inclusion proof, so the integrity requirement drops from covered to partial.
    A record that claims tamper-evidence it cannot demonstrate is the failure this whole
    project argues against.
    """
    subject = warrant.get("credentialSubject", {})
    action = subject.get("action", {})
    attribution = subject.get("attribution", {})
    mandate = subject.get("mandate", {})
    chain = subject.get("delegation_chain", []) or []
    decision = subject.get("policy_decision", {})

    requirements = [
        _automatic_recording(warrant, action),
        _traceability(attribution, chain),
        _identification_of_risk(attribution, decision),
        _post_market_monitoring(mandate, action),
        _record_integrity(receipt),
        _human_oversight(mandate, chain),
        _retention(),
    ]

    counts: dict[str, int] = {"covered": 0, "partial": 0, "not_covered": 0}
    for requirement in requirements:
        counts[requirement.coverage] += 1

    return {
        "framework": "EU AI Act (Regulation (EU) 2024/1689) Article 12",
        "enforceable_from": ENFORCEABLE_FROM,
        "standards_status": (
            "No finalised technical standard: prEN 18229-1 and ISO/IEC DIS 24970 remain "
            "drafts, so this maps to the obligations rather than to a ratified schema."
        ),
        "warrant_id": warrant.get("id"),
        "issuer": warrant.get("issuer"),
        "issued_at": warrant.get("validFrom"),
        "summary": counts,
        "requirements": [r.as_dict() for r in requirements],
        "disclaimer": DISCLAIMER,
    }


# ------------------------------------------------------------------- requirements


def _automatic_recording(warrant: dict, action: dict) -> Requirement:
    return Requirement(
        ref="Art. 12(1)",
        obligation="Automatically record events (logs) over the lifetime of the system.",
        coverage="covered",
        mechanism=(
            "Every consequential action produces a signed Action Warrant with no operator "
            "step in between; the consequential-action gate decides what qualifies."
        ),
        evidence={
            "warrant_id": warrant.get("id"),
            "operation": action.get("operation"),
            "tool": action.get("tool"),
            "arguments_hash": action.get("arguments_hash"),
        },
    )


def _traceability(attribution: dict, chain: list) -> Requirement:
    return Requirement(
        ref="Art. 12(2)(a)",
        obligation=(
            "Logs enabling identification of situations where the system may present a "
            "risk, and traceability of its operation."
        ),
        coverage="covered",
        mechanism=(
            "The record is causal rather than merely chronological: a delegation chain "
            "showing how authority reached the actor, and measured per-argument attribution "
            "showing which provenance class supplied each value."
        ),
        evidence={
            "delegation_hops": len(chain),
            "per_argument": attribution.get("per_argument", {}),
            "argument_status": attribution.get("argument_status", {}),
        },
    )


def _identification_of_risk(attribution: dict, decision: dict) -> Requirement:
    """Partial, and the reason is the honest one: absence of evidence is not safety.

    Only ``unknown`` counts as unresolved. The first version of this function collected
    every field whose status was not ``attributed``, which swept ``invariant`` in with it
    and described a redundantly-determined value as having "no measured cause" — the exact
    flattening design decision 6 exists to forbid, reproduced inside a compliance export
    where a regulator would have read it. ``invariant`` is evidence of invariance; only
    ``unknown`` is the absence of evidence.
    """
    status = attribution.get("argument_status", {}) or {}
    unresolved = sorted(f for f, s in status.items() if s == "unknown")
    invariant = sorted(f for f, s in status.items() if s == "invariant")
    return Requirement(
        ref="Art. 12(2)(b)",
        obligation=(
            "Logs facilitating post-market monitoring and the identification of "
            "substantial modifications."
        ),
        coverage="partial",
        mechanism=(
            "Policy identifier and version are recorded per decision, and the trace commits "
            "to tool-description hashes, so drift in a tool's declared behaviour is "
            "detectable between two records."
        ),
        gap=(
            "Detecting a substantial modification requires comparing records over time, "
            "which is an operator process this system does not perform: it supplies the "
            "comparable material and does not do the comparing. Fields reported as "
            f"{unresolved or 'none'} have status 'unknown', meaning every counterfactual "
            "cancelled the action so no comparable run exists — the absence of evidence "
            "rather than evidence of safety, and a supervisory reader should treat those "
            "fields as unexplained."
        ),
        evidence={
            "policy": decision.get("policy_id"),
            "policy_version": decision.get("policy_version"),
            "rules_fired": decision.get("rules_fired", []),
            # Reported separately and never merged. `invariant` means removing any single
            # source left the value unchanged -- it is redundantly determined, which is
            # evidence, and is the normal shape of a legitimate action. `unknown` means
            # nothing could be measured. Both carry zero influence and they are different
            # findings; collapsing them is how a correct system reports a false gap.
            "unresolved_arguments": unresolved,
            "invariant_arguments": invariant,
        },
    )


def _post_market_monitoring(mandate: dict, action: dict) -> Requirement:
    return Requirement(
        ref="Art. 12(3)",
        obligation=(
            "Record the period of each use, the reference database or input data checked, "
            "and the natural persons involved in verification."
        ),
        coverage="partial",
        mechanism=(
            "The mandate records the authenticated principal, the authentication method and "
            "the time of authentication; the trace records which inputs were present and "
            "which classes they belonged to."
        ),
        gap=(
            "'Reference database' is recorded as a provenance class and a tool identity, "
            "not as a dataset version or a query. A deployment whose obligation turns on "
            "*which* records were consulted needs that identifier added at the tool "
            "boundary; this system records that a closed-world tool answered, not what it "
            "was asked."
        ),
        evidence={
            "principal": mandate.get("principal"),
            "authenticated_at": mandate.get("authenticated_at"),
            "auth_method": mandate.get("auth_method"),
            "operation": action.get("operation"),
        },
    )


def _record_integrity(receipt: dict | None) -> Requirement:
    if receipt is None:
        return Requirement(
            ref="Art. 12(1) — integrity",
            obligation="Records must be reliable for supervisory audit.",
            coverage="partial",
            mechanism="The warrant is signed, so alteration of its contents is detectable.",
            gap=(
                "No transparency-log receipt was supplied, so this export cannot show the "
                "record was published to an append-only log. A signature proves authorship; "
                "it does not prove the record was not withheld."
            ),
        )
    return Requirement(
        ref="Art. 12(1) — integrity",
        obligation="Records must be reliable for supervisory audit.",
        coverage="covered",
        mechanism=(
            "The warrant is signed and published to an append-only Merkle log. Inclusion is "
            "verifiable against a root held by a witness in a different trust domain than "
            "the issuer, so suppression and rewriting are detectable by the auditor rather "
            "than only by the operator."
        ),
        evidence={
            "log_id": receipt.get("log_id"),
            "leaf_index": receipt.get("leaf_index"),
            "tree_size": receipt.get("tree_size"),
            "root_hash": receipt.get("root_hash"),
            "inclusion_proof_length": len(receipt.get("inclusion_proof", []) or []),
        },
    )


def _human_oversight(mandate: dict, chain: list) -> Requirement:
    humans = [hop for hop in chain if hop.get("kind") == "human"]
    return Requirement(
        ref="Art. 14 (interaction)",
        obligation=(
            "Support human oversight: it must be possible to establish who authorised an "
            "action and on what basis."
        ),
        coverage="covered",
        mechanism=(
            "The delegation chain names the human principal at hop 0 and every attenuation "
            "after it, and the mandate records the scope and constraints they authorised "
            "within. Attribution then shows whether the human's instruction actually caused "
            "the values used — authorisation and causation are recorded separately, because "
            "a human authorising an action is not the same as a human causing its arguments."
        ),
        evidence={
            "human_hops": [hop.get("actor") for hop in humans],
            "scope": mandate.get("scope", {}),
            "expires_at": mandate.get("expires_at"),
        },
    )


def _retention() -> Requirement:
    return Requirement(
        ref="Art. 12(1) — retention",
        obligation="Logs must be retained for an appropriate period.",
        coverage="not_covered",
        mechanism="",
        gap=(
            "Retention is a deployment property, not a property of this system. The "
            "transparency log is append-only and has no retention policy, no deletion path "
            "and no jurisdiction-specific period configured. A deployer must state the "
            "period and operate storage that meets it. Recorded as not_covered rather than "
            "silently omitted, because the obligation does not disappear by being outside "
            "this codebase."
        ),
    )
