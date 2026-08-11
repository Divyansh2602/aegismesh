"""What a visitor can run, and the trust context it runs in.

The preset catalogue is ``aegis.evaluation.cases.build_cases()`` rather than a set of
bodies written for the UI. Those cases carry ground-truth labels, are already scored by
the Phase 2 harness, and break the tests if they drift -- so the thing on the website is
the thing the numbers were measured on. A separate catalogue authored for presentation
would be a second definition of the demo, free to diverge from the one under test.

Visitor-authored runs are marked **unlabelled** and stay that way. We know what our own
cases contain by construction; we do not know whether an arbitrary string a stranger
pastes constitutes an injection, and claiming otherwise would put a fabricated ground
truth next to measured ones. Nothing unlabelled may ever enter a scored metric.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta

from aegis.common.hashing import hash_text
from aegis.evaluation.cases import ATTACKER, LEGIT, MANDATE, build_cases, treasury_messages
from aegis.provenance.registry import MandateContext, ToolRegistry
from aegis.warrant.models import DelegationHop, MandateClaim, MandateScope, iso, utc_now

PRINCIPAL = "did:web:acme-bank.example:users:r.mehta"
MANDATE_ID = "mnd_public_demo"
TOOL = "treasury.payments"
OPERATION = "execute_transfer"

ORCHESTRATOR = "did:web:acme-bank.example:agents:procurement-orchestrator"
PROCESSOR = "did:web:acme-bank.example:agents:invoice-processor"

# The manifest hashes a relying party recognizes (control C-6). Held as constants rather
# than computed per session because the PEP is meant to know these agents in advance --
# a registry populated from whatever turned up would switch the check off.
ORCHESTRATOR_MANIFEST = hash_text("procurement-orchestrator@1.4.0")
PROCESSOR_MANIFEST = hash_text("invoice-processor@2.1.0")
KNOWN_MANIFESTS = {ORCHESTRATOR_MANIFEST, PROCESSOR_MANIFEST}


@dataclass(frozen=True)
class Scenario:
    """One runnable context, and what we honestly know about it."""

    name: str
    title: str
    summary: str
    body: dict
    labelled: bool
    poisoned: bool | None
    tags: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "title": self.title,
            "summary": self.summary,
            "labelled": self.labelled,
            "poisoned": self.poisoned,
            "tags": list(self.tags),
            "messages": self.body.get("messages", []),
        }


def _title(name: str) -> str:
    return name.replace("_", " ").capitalize()


def catalogue() -> dict[str, Scenario]:
    """The presets, built from the labelled Phase 2 case set."""
    return {
        case.name: Scenario(
            name=case.name,
            title=_title(case.name),
            summary=case.note,
            body=case.body,
            labelled=True,
            poisoned=case.poisoned,
            tags=case.tags,
        )
        for case in build_cases()
    }


def custom_scenario(injection: str) -> Scenario:
    """A run whose conduit-tool document is written by the visitor.

    The injection slot is the invoice document specifically. That is where control C-19
    says trust does not follow tool integrity -- a pinned, well-behaved reader relaying a
    supplier's PDF from outside the boundary -- so letting a visitor write it is letting
    them attack the design at the exact seam it claims to hold.
    """
    return Scenario(
        name="custom",
        title="Your own document",
        summary=(
            "Text you supplied, relayed by the pinned invoice reader. Unlabelled: the "
            "system has no ground truth for a document it did not construct."
        ),
        body={"model": "aegis-mock-1", "messages": treasury_messages(tool_note=injection)},
        labelled=False,
        poisoned=None,
        tags=["custom", "unlabelled"],
    )


def build_registry() -> ToolRegistry:
    """The two pinned tools, and the distinction that makes pinning honest.

    ``invoice_reader`` is pinned, authentic and still P3: it relays a supplier's document
    from outside the trust boundary. ``ledger_lookup`` returns Acme's own records and
    earns P2. Control C-19 -- tool integrity is not content provenance.
    """
    registry = ToolRegistry()
    registry.pin(
        name="invoice_reader",
        origin="mcp://vendor.example/invoice_reader",
        description="Reads an invoice PDF and returns its fields.",
    )
    registry.pin(
        name="ledger_lookup",
        origin="internal://acme/ledger",
        description="Looks up an approved supplier account in Acme's own ledger.",
        relays_external_content=False,
    )
    return registry


def build_mandate_context() -> MandateContext:
    """What the classifier matches P0 against.

    The instruction is the mandate text verbatim. Matching is strict substring by design
    (decision 1): anything fuzzier would be a privilege-escalation primitive, and the
    visitor-authored document is free to try.
    """
    return MandateContext(mandate_id=MANDATE_ID, principal=PRINCIPAL, instruction=MANDATE)


def build_mandate_claim() -> MandateClaim:
    now = utc_now()
    return MandateClaim(
        id=MANDATE_ID,
        principal=PRINCIPAL,
        authenticated_at=iso(now - timedelta(minutes=16)),
        auth_method="oidc+mfa",
        scope=MandateScope(
            action_classes=[f"{TOOL}:{OPERATION}"],
            constraints={"amount_max": 5000000, "currency": ["USD"]},
        ),
        expires_at=iso(now + timedelta(hours=8)),
    )


def build_delegation_chain(agent_issuer: str) -> list[DelegationHop]:
    """Human -> orchestrator -> processor, attenuating at every hop.

    ``agent_issuer`` is the session's own issuer DID, so two visitors' warrants are
    signed by different keys under different identifiers and neither can be replayed
    into the other's session.
    """
    return [
        DelegationHop(hop=0, actor=PRINCIPAL, kind="human", scope=[f"{TOOL}:*"]),
        DelegationHop(
            hop=1,
            actor=ORCHESTRATOR,
            kind="agent",
            scope=[f"{TOOL}:{OPERATION}"],
            manifest_hash=ORCHESTRATOR_MANIFEST,
            attenuated=True,
        ),
        DelegationHop(
            hop=2,
            actor=PROCESSOR,
            kind="agent",
            scope=[f"{TOOL}:{OPERATION}"],
            manifest_hash=PROCESSOR_MANIFEST,
            attenuated=True,
        ),
    ]


__all__ = [
    "ATTACKER",
    "KNOWN_MANIFESTS",
    "LEGIT",
    "MANDATE",
    "OPERATION",
    "TOOL",
    "Scenario",
    "build_delegation_chain",
    "build_mandate_claim",
    "build_mandate_context",
    "build_registry",
    "catalogue",
    "custom_scenario",
]
