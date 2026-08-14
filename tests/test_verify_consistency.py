"""The standalone consistency verifier, exercised the way an auditor would run it.

Every test drives ``tools/verify_consistency.py`` as a subprocess over files on disk,
because that is the only thing the claim is about: a stranger, holding one public key and
two JSON files, with no network and nothing imported from the issuing path. A test that
called ``verify()`` in-process would be checking that the library agrees with itself.

**The negative cases are the point.** A verifier that has never been shown a forgery has
not been shown to detect one, and the most valuable test here is
``test_it_rejects_a_rewritten_history``: two trees of the same size, differing in one
entry, each internally perfect. That is the attack this whole tool exists to catch, and it
is invisible to every inclusion proof.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from aegis.log.log import TransparencyLog
from aegis.warrant.keys import SigningKey

from conftest import LOG_ID

REPO = Path(__file__).resolve().parent.parent
TOOL = REPO / "tools" / "verify_consistency.py"


def entry(n: int) -> dict:
    return {"id": f"urn:uuid:{n}", "credentialSubject": {"n": n}}


def run_tool(tmp_path: Path, earlier: dict, later: dict, anchors: dict):
    paths = []
    for name, document in (
        ("earlier", earlier),
        ("later", later),
        ("trust_anchors", anchors),
    ):
        path = tmp_path / f"{name}.json"
        path.write_text(json.dumps(document, indent=2), encoding="utf-8")
        paths.append(str(path))
    return subprocess.run(  # noqa: S603 - fixed argv, paths built above
        [sys.executable, str(TOOL), *paths],
        capture_output=True,
        text=True,
        cwd=REPO,
    )


@pytest.fixture
def anchors(log_key: SigningKey) -> dict:
    return {
        "log_id": LOG_ID,
        "log_public_key_multibase": log_key.public.to_multibase(),
    }


def head_of(log: TransparencyLog) -> dict:
    return log.signed_tree_head().model_dump(mode="json")


def consistency_from(log: TransparencyLog, first: int) -> dict:
    """The shape ``GET /v1/log/consistency`` returns, built from the same calls it makes."""
    return {
        "first": first,
        "second": log.tree_size,
        "proof": log.consistency_proof(first),
        "signed_tree_head": head_of(log),
    }


class TestAGenuineExtension:
    def test_it_accepts_a_log_that_only_grew(self, log, anchors, tmp_path):
        for i in range(3):
            log.append(entry(i))
        earlier = {"signed_tree_head": head_of(log)}

        for i in range(3, 9):
            log.append(entry(i))
        later = consistency_from(log, first=3)

        result = run_tool(tmp_path, earlier, later, anchors)
        assert result.returncode == 0, result.stdout + result.stderr
        assert "CONSISTENT: 6/6 checks passed" in result.stdout
        assert "grew by 6 entries" in result.stdout

    def test_a_receipt_from_an_earlier_visit_works_unchanged(self, log, anchors, tmp_path):
        """The artifact an auditor actually has is a receipt, not a bare head.

        If bridging two visits required hand-editing JSON into a shape the tool preferred,
        nobody would do it, and the property would be checkable only in principle.
        """
        receipt = log.append(entry(0))
        for i in range(1, 5):
            log.append(entry(i))

        result = run_tool(
            tmp_path,
            json.loads(receipt.model_dump_json()),
            consistency_from(log, first=receipt.tree_size),
            anchors,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert "CONSISTENT: 6/6 checks passed" in result.stdout

    def test_two_identical_heads_are_consistent_with_an_empty_proof(
        self, log, anchors, tmp_path
    ):
        """RFC 6962's boundary: a tree is a prefix of itself, and the proof is empty.

        Worth pinning because "no proof nodes" and "no proof supplied" look identical on
        the wire, and treating the second as the first would accept anything at equal size.
        """
        for i in range(4):
            log.append(entry(i))
        earlier = {"signed_tree_head": head_of(log)}

        result = run_tool(tmp_path, earlier, consistency_from(log, first=4), anchors)
        assert result.returncode == 0, result.stdout + result.stderr
        assert "CONSISTENT: 6/6 checks passed" in result.stdout


class TestItDetectsWhatItExistsToDetect:
    def test_it_rejects_a_rewritten_history(self, log_key, anchors, tmp_path):
        """The attack. Two trees of the same size differing in one entry.

        Every inclusion proof in the second tree verifies against the second tree's own
        root, so a warrant issued against it looks perfect. Only a consistency proof
        against the head somebody was handed earlier can tell the two apart.
        """
        honest = TransparencyLog(log_id=LOG_ID, signing_key=log_key)
        for i in range(5):
            honest.append(entry(i))
        earlier = {"signed_tree_head": head_of(honest)}

        rewritten = TransparencyLog(log_id=LOG_ID, signing_key=log_key)
        for i in range(5):
            rewritten.append(entry(i) if i != 2 else {"id": "urn:uuid:2", "n": "edited"})
        for i in range(5, 9):
            rewritten.append(entry(i))

        result = run_tool(tmp_path, earlier, consistency_from(rewritten, first=5), anchors)
        assert result.returncode == 1
        assert "INCONSISTENT" in result.stdout
        assert "[FAIL] the later tree extends the earlier one" in result.stdout
        assert "no benign explanation" in result.stdout

    def test_it_rejects_a_log_that_went_backwards(self, log, log_key, anchors, tmp_path):
        """What a reset looks like from outside -- including an ephemeral disk losing it."""
        for i in range(6):
            log.append(entry(i))
        earlier = {"signed_tree_head": head_of(log)}

        restarted = TransparencyLog(log_id=LOG_ID, signing_key=log_key)
        restarted.append(entry(0))

        result = run_tool(tmp_path, earlier, consistency_from(restarted, first=1), anchors)
        assert result.returncode == 1
        assert "[FAIL] the tree did not shrink  6 -> 1" in result.stdout

    def test_it_rejects_a_proof_about_a_different_pair_of_heads(
        self, log, anchors, tmp_path
    ):
        """A real proof, correctly signed, about two trees nobody asked about.

        Every hash in it checks out. Without binding the proof to the heads in front of
        you, that is enough to pass.
        """
        for i in range(3):
            log.append(entry(i))
        earlier = {"signed_tree_head": head_of(log)}
        for i in range(3, 10):
            log.append(entry(i))

        elsewhere = consistency_from(log, first=6)  # genuine, but from size 6 not 3
        result = run_tool(tmp_path, earlier, elsewhere, anchors)
        assert result.returncode == 1
        assert "[FAIL] the proof is about these two heads" in result.stdout

    def test_it_rejects_a_head_signed_by_a_different_key(self, log, anchors, tmp_path):
        """An operator who lost the argument and stood up a second log."""
        for i in range(3):
            log.append(entry(i))
        earlier = {"signed_tree_head": head_of(log)}

        impostor = TransparencyLog(
            log_id=LOG_ID, signing_key=SigningKey.from_seed("not-the-real-log")
        )
        for i in range(6):
            impostor.append(entry(i))

        result = run_tool(tmp_path, earlier, consistency_from(impostor, first=3), anchors)
        assert result.returncode == 1
        assert "[FAIL] later head verifies under the log key" in result.stdout

    def test_it_rejects_a_tampered_root(self, log, anchors, tmp_path):
        """Editing the root breaks the signature over it, which is the point of signing it."""
        for i in range(3):
            log.append(entry(i))
        earlier = {"signed_tree_head": head_of(log)}
        for i in range(3, 8):
            log.append(entry(i))

        later = consistency_from(log, first=3)
        digest = later["signed_tree_head"]["root_hash"]
        later["signed_tree_head"]["root_hash"] = digest[:-1] + ("0" if digest[-1] != "0" else "1")

        result = run_tool(tmp_path, earlier, later, anchors)
        assert result.returncode == 1
        assert "[FAIL] later head verifies under the log key" in result.stdout


class TestItSaysWhatItCannotDo:
    def test_it_names_the_split_view_it_cannot_detect(self, log, anchors, tmp_path):
        """A passing verifier that stayed quiet about its limits would oversell itself.

        Two auditors each holding a perfectly consistent chain is exactly what a split view
        produces, so the one moment this must be said is when every check passed.
        """
        for i in range(2):
            log.append(entry(i))
        earlier = {"signed_tree_head": head_of(log)}
        for i in range(2, 5):
            log.append(entry(i))

        result = run_tool(tmp_path, earlier, consistency_from(log, first=2), anchors)
        assert result.returncode == 0
        assert "split view" in result.stdout
        assert "witness.py" in result.stdout

    def test_it_explains_itself_when_given_the_wrong_number_of_arguments(self):
        result = subprocess.run(  # noqa: S603 - fixed argv
            [sys.executable, str(TOOL)], capture_output=True, text=True, cwd=REPO
        )
        assert result.returncode == 2
        assert "earlier.json later.json trust_anchors.json" in result.stdout

    def test_it_refuses_a_file_with_no_head_rather_than_guessing(
        self, log, anchors, tmp_path
    ):
        log.append(entry(0))
        result = run_tool(tmp_path, {"not": "a head"}, consistency_from(log, 1), anchors)
        assert result.returncode != 0
        assert "no signed tree head here" in result.stdout + result.stderr
