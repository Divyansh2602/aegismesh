"""The Article 12 export, and specifically its honesty.

A compliance export is the easiest artefact in a system to make dishonest, because nothing
in the code path punishes optimism: every requirement can be marked covered and the file
still validates. These tests exist mostly to make optimism fail.
"""

from __future__ import annotations

import json

from aegis.compliance.article12 import ENFORCEABLE_FROM, export


def build_warrant() -> dict:
    return {
        "id": "urn:uuid:11111111-2222-3333-4444-555555555555",
        "issuer": "did:web:aegis.acme-bank.example",
        "validFrom": "2026-08-13T10:00:00Z",
        "credentialSubject": {
            "action": {
                "operation": "execute_transfer",
                "tool": "treasury.payments",
                "arguments_hash": "sha256:abcd",
            },
            "mandate": {
                "principal": "did:web:acme-bank.example:users:r.mehta",
                "authenticated_at": "2026-08-13T09:44:00Z",
                "auth_method": "oidc+mfa",
                "scope": {"action_classes": ["treasury.payments:execute_transfer"]},
                "expires_at": "2026-08-13T18:00:00Z",
            },
            "delegation_chain": [
                {"hop": 0, "actor": "did:web:acme-bank.example:users:r.mehta", "kind": "human"},
                {"hop": 1, "actor": "did:web:acme:agents:orchestrator", "kind": "agent"},
            ],
            "attribution": {
                "per_argument": {"destination_account": {"P3": "1.0000"}},
                "argument_status": {"destination_account": "attributed", "memo": "unknown"},
            },
            "policy_decision": {
                "decision": "deny",
                "policy_id": "acme.treasury",
                "policy_version": "4.3.0",
                "rules_fired": ["no-untrusted-destination"],
            },
        },
    }


def build_receipt() -> dict:
    return {
        "log_id": "did:web:log.aegismesh.example",
        "leaf_index": 7,
        "tree_size": 12,
        "root_hash": "sha256:beef",
        "inclusion_proof": ["sha256:aa", "sha256:bb", "sha256:cc"],
    }


class TestTheExportDescribesTheWarrantItWasGiven:
    def test_it_names_the_obligation_and_the_date_it_became_enforceable(self):
        report = export(build_warrant(), build_receipt())
        assert "Article 12" in report["framework"]
        assert report["enforceable_from"] == ENFORCEABLE_FROM

    def test_evidence_is_lifted_from_the_warrant_not_described(self):
        """A mapping that only asserts 'we record the principal' is a brochure. The values
        have to be in the export, or a reader cannot check the claim against the record."""
        report = export(build_warrant(), build_receipt())
        blob = json.dumps(report)
        assert "r.mehta" in blob
        assert "oidc+mfa" in blob
        assert "sha256:beef" in blob
        assert "acme.treasury" in blob

    def test_it_is_serialisable(self):
        json.dumps(export(build_warrant(), build_receipt()))


class TestGapsAreReportedAsGaps:
    """The tests that matter. Everything above would pass on a dishonest export too."""

    def test_every_incomplete_requirement_states_what_is_missing(self):
        report = export(build_warrant(), build_receipt())
        for requirement in report["requirements"]:
            if requirement["coverage"] != "covered":
                assert requirement.get("gap"), (
                    f"{requirement['ref']} is {requirement['coverage']} with no stated gap"
                )

    def test_the_export_does_not_claim_full_coverage(self):
        """If this ever passes trivially, somebody has rounded the gaps up."""
        report = export(build_warrant(), build_receipt())
        assert report["summary"]["covered"] < len(report["requirements"])

    def test_retention_is_reported_as_not_covered(self):
        """It is a deployment property this system does not have. Omitting it entirely
        would let a reader assume it was handled."""
        report = export(build_warrant(), build_receipt())
        retention = [r for r in report["requirements"] if "retention" in r["ref"]]
        assert retention and retention[0]["coverage"] == "not_covered"

    def test_a_missing_receipt_downgrades_integrity_rather_than_asserting_it(self):
        """A signature proves authorship; it does not prove the record was not withheld.
        Without an inclusion proof the export must not claim tamper-evidence."""
        with_proof = export(build_warrant(), build_receipt())
        without = export(build_warrant(), None)

        integrity_with = [r for r in with_proof["requirements"] if "integrity" in r["ref"]][0]
        integrity_without = [r for r in without["requirements"] if "integrity" in r["ref"]][0]

        assert integrity_with["coverage"] == "covered"
        assert integrity_without["coverage"] == "partial"
        assert "withheld" in integrity_without["gap"]

    def test_unresolved_arguments_are_surfaced_not_hidden(self):
        """`memo` has status unknown in the fixture. An export that quietly dropped it
        would present absence of evidence as evidence of safety."""
        report = export(build_warrant(), build_receipt())
        blob = json.dumps(report)
        assert "memo" in blob

    def test_invariant_is_never_reported_as_unresolved(self):
        """Design decision 6, inside the compliance export.

        The first version of this module collected every field whose status was not
        `attributed`, which described a redundantly-determined value as having no measured
        cause — in a document a regulator would read. `invariant` is evidence of
        invariance and the normal shape of a legitimate action; only `unknown` is the
        absence of evidence. They must never be merged.
        """
        warrant = build_warrant()
        warrant["credentialSubject"]["attribution"]["argument_status"] = {
            "destination_account": "attributed",
            "currency": "invariant",
            "memo": "unknown",
        }
        report = export(warrant, build_receipt())
        risk = [r for r in report["requirements"] if r["ref"] == "Art. 12(2)(b)"][0]

        assert risk["evidence"]["unresolved_arguments"] == ["memo"]
        assert risk["evidence"]["invariant_arguments"] == ["currency"]
        assert "currency" not in risk["gap"]

    def test_it_disclaims_being_legal_advice_or_a_certification(self):
        report = export(build_warrant(), build_receipt())
        assert "not legal advice" in report["disclaimer"]
        assert "does not by itself establish compliance" in report["disclaimer"]
