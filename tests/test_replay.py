"""The audit path: does re-running the measurement catch an issuer who lied?

Every other verification in this project checks that a warrant is *authentic*. These tests
check the one property authenticity cannot give you -- that the claim inside it is true --
and, just as importantly, that the verifier refuses to reach that verdict when it is not
entitled to.
"""

from __future__ import annotations

import asyncio

import pytest

from aegis.attribution.client import InProcessMockClient
from aegis.audit.replay import replay_attribution
from aegis.common.decimals import format_score
from aegis.provenance.classes import ProvenanceClass as P
from aegis.warrant.issuer import WarrantIssuer

from conftest import (
    ISSUER_DID,
    ISSUER_METHOD,
    OPERATION,
    TOOL,
    build_chain,
    build_mandate,
    poisoned_request,
    run_pipeline,
)


@pytest.fixture
def replayable(issuer: WarrantIssuer):
    """A warrant, plus everything an auditor would be disclosed to check it."""
    body = poisoned_request()
    trace, attribution, arguments = run_pipeline(body)
    warrant = issuer.issue(
        operation=OPERATION,
        arguments=arguments,
        mandate=build_mandate(),
        delegation_chain=build_chain(),
        attribution=attribution,
        trace=trace,
        tool=TOOL,
    )
    return warrant, body, trace


def replay(warrant, body, trace):
    return asyncio.run(
        replay_attribution(
            warrant.credentialSubject.attribution, body, trace, InProcessMockClient()
        )
    )


def test_an_honest_warrant_replays_consistent(replayable):
    """The baseline. Without this the verifier could pass everything by contradicting all."""
    report = replay(*replayable)

    assert report.verdict == "consistent"
    assert not report.contradictions


def test_a_fabricated_attribution_is_contradicted(replayable):
    """ADV-4: the operator signs a warrant blaming the human for the attacker's account.

    This is the threat the transparency log cannot touch -- the signature is valid, the
    leaf is in the tree, the witness agrees. Only re-running the measurement reaches it.
    """
    warrant, body, trace = replayable
    claim = warrant.credentialSubject.attribution
    claim.per_argument["destination_account"] = {
        P.HUMAN_MANDATE.value: format_score(1.0),
    }

    report = replay(warrant, body, trace)

    assert report.verdict == "contradicted"
    assert any("destination_account" in f.check for f in report.contradictions)


def test_a_flipped_argument_status_is_contradicted(replayable):
    """Claiming a field was measured when it was not is the quieter version of the same lie.

    ``invariant`` and ``attributed`` are what policy reasons over, so an issuer who wants a
    field to pass without evidence has more to gain from moving the status than the numbers.
    """
    warrant, body, trace = replayable
    warrant.credentialSubject.attribution.argument_status["destination_account"] = "invariant"

    report = replay(warrant, body, trace)

    assert report.verdict == "contradicted"


def test_a_substituted_trace_is_inconclusive_not_consistent(replayable):
    """The auditor is handed the trace by the party under investigation.

    An operator who can swap in a context on which the signed numbers *do* reproduce would
    otherwise walk away with a clean verdict. Failing the binding must never resolve to
    ``consistent``.
    """
    warrant, body, trace = replayable
    trace.segments[-1].source.content_hash = "sha256:" + "0" * 64

    report = replay(warrant, body, trace)

    assert report.verdict == "inconclusive"
    assert not report.contradictions


def test_a_warrant_without_the_settings_commitment_cannot_be_replayed(replayable):
    """Phase 3's replay_ref did not determine the measurement, and this says so.

    Replaying under the auditor's own defaults would be the most dangerous possible
    fallback: it produces confident contradictions of issuers who did nothing wrong. The
    honest answer is that the commitment is insufficient.
    """
    warrant, body, trace = replayable
    warrant.credentialSubject.attribution.replay_ref.mode = ""

    report = replay(warrant, body, trace)

    assert report.verdict == "inconclusive"
    assert any("settings committed" in f.check for f in report.findings)


def test_replay_does_not_prove_honesty_only_reproducibility(replayable):
    """A limitation, asserted so it cannot be quietly lost.

    ``consistent`` means the numbers reproduce under the committed conditions. An issuer
    who ran a doctored *engine* and committed to its method version reproduces perfectly
    against their own binary. What defeats that is the auditor running their own copy of
    the method -- which is why this module never calls back to the issuer for anything.
    """
    warrant, body, trace = replayable
    report = replay(warrant, body, trace)

    assert report.verdict == "consistent"
    assert not any("issuer is honest" in f.check for f in report.findings)


def test_a_missing_replay_ref_is_inconclusive(replayable):
    warrant, body, trace = replayable
    warrant.credentialSubject.attribution.replay_ref = None

    report = replay(warrant, body, trace)

    assert report.verdict == "inconclusive"


def test_the_warrant_document_can_be_replayed_as_read_off_disk(replayable):
    """An auditor has a JSON file, not our pydantic models."""
    warrant, body, trace = replayable

    report = asyncio.run(
        replay_attribution(warrant.to_document(), body, trace, InProcessMockClient())
    )

    assert report.verdict == "consistent"
    assert ISSUER_DID and ISSUER_METHOD  # the auditor needed neither
