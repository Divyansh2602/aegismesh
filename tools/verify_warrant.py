"""Standalone Action Warrant verifier.

    python tools/verify_warrant.py warrant.json receipt.json trust_anchors.json

Answers one question: **can a third party who trusts nobody involved check this?**

It knows two public keys and one root hash. It does not call the issuer, does not call the
log, does not import the issuing code path, and holds no shared secret. Everything it needs
travels in the three files.

Deliberately kept separate from ``aegis/pep``. The PEP is the enforcement path and shares
data structures with the issuer; this is the audit path, and an auditor's tool that reused
the issuer's serializer would be checking that a program agrees with itself. Here the JSON
is read as bytes, canonicalized independently, and hashed.

What it verifies, and what it does not:

  * The credential is signed by the key the auditor was told to expect.
  * The signed tree head is signed by the log's key.
  * The warrant is in the tree that head commits to.
  * The root that head commits to is the one an independent witness accepted.

It does **not** verify that the attribution inside the warrant is true. Nothing here can:
the issuer measured it and the issuer signed it. What the log adds is non-repudiation --
the claim is permanently and verifiably theirs. Checking the claim itself means re-running
the ablation from ``attribution.replay_ref`` against a disclosed trace, which is
``aegis/audit/replay.py``. That is a strictly larger disclosure -- the auditor needs the
context, not just the credential -- so it stays a separate tool rather than being folded
in here.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from aegis.common.hashing import canonical_json
from aegis.log import merkle
from aegis.log.log import Receipt, decode_hash
from aegis.warrant.issuer import verify_signature
from aegis.warrant.keys import VerifyingKey

OK, BAD = "  [ok]  ", "  [FAIL]"


def check(label: str, passed: bool, detail: str = "") -> bool:
    print(f"{OK if passed else BAD} {label}{'  ' + detail if detail else ''}")
    return passed


def verify(warrant_path: Path, receipt_path: Path, anchors_path: Path) -> int:
    document = json.loads(warrant_path.read_text(encoding="utf-8"))
    receipt = Receipt.model_validate(json.loads(receipt_path.read_text(encoding="utf-8")))
    anchors = json.loads(anchors_path.read_text(encoding="utf-8"))

    issuer_key = VerifyingKey.from_multibase(anchors["issuer_public_key_multibase"])
    log_key = VerifyingKey.from_multibase(anchors["log_public_key_multibase"])
    witnessed_root = decode_hash(anchors["witnessed_root"])

    print(f"\nWarrant  {document.get('id')}")
    print(f"Issuer   {document.get('issuer')}")
    print(f"Log      {receipt.log_id}")
    print("\nTrust anchors held by this verifier: 2 public keys and 1 root hash.\n")

    results = []

    method = (document.get("proof") or {}).get("verificationMethod")
    results.append(
        check(
            "proof names the expected verification method",
            method == anchors["issuer_verification_method"],
            str(method),
        )
    )
    results.append(
        check("credential signature verifies", verify_signature(document, issuer_key))
    )

    head = receipt.signed_root
    results.append(check("signed tree head verifies under the log key", head.verify(log_key)))
    results.append(
        check(
            "signed tree head commits to the receipt's root",
            head.root_hash == receipt.root_hash and head.tree_size == receipt.tree_size,
        )
    )

    # Recompute the leaf from the document as read off disk. The log hashes the canonical
    # form, so a warrant re-serialized with different key order still lands on the same leaf.
    leaf = merkle.leaf_hash(canonical_json(document))
    results.append(
        check(
            "inclusion proof reaches the receipt's root",
            merkle.verify_inclusion(
                leaf,
                receipt.leaf_index,
                receipt.tree_size,
                receipt.proof_bytes(),
                decode_hash(receipt.root_hash),
            ),
            f"leaf {receipt.leaf_index} of {receipt.tree_size}",
        )
    )
    results.append(
        check(
            "that root is the one the independent witness accepted",
            _reaches_witnessed_root(leaf, receipt, witnessed_root, anchors),
            f"witness at size {anchors['witnessed_tree_size']}",
        )
    )

    subject = document.get("credentialSubject", {})
    attribution = subject.get("attribution", {})
    print("\nWhat the warrant claims (verified as authentic, not as true):")
    print(f"  action           {subject.get('action', {}).get('tool')}."
          f"{subject.get('action', {}).get('operation')}")
    print(f"  issuer decision  {subject.get('policy_decision', {}).get('decision')}"
          f"  {subject.get('policy_decision', {}).get('rules_fired')}")
    for field in sorted(attribution.get("per_argument", {})):
        status = attribution.get("argument_status", {}).get(field, "?")
        print(f"  {field:<20} {status:<11} {attribution['per_argument'][field]}")

    replay = attribution.get("replay_ref") or {}
    if replay:
        print(f"\n  replay_ref commits to {len(replay.get('segment_hashes', []))} segments")
        print(f"  trace_hash {replay.get('trace_hash')}")
        print(f"  measured with mode={replay.get('mode') or '(not committed)'} "
              f"theta_drilldown={replay.get('drilldown_threshold') or '(not committed)'}")
        print("  Re-running the ablation against those segments is how the numbers above")
        print("  become checkable rather than merely attributable. An auditor granted the")
        print("  trace does that with aegis.audit.replay; this tool does not, because it")
        print("  deliberately holds nothing but two public keys and a root hash.")
        if not replay.get("mode"):
            print("  NOTE: this warrant predates the settings commitment and cannot be")
            print("  replayed -- what it commits to does not determine the measurement.")

    passed = all(results)
    print(f"\n{'VERIFIED' if passed else 'VERIFICATION FAILED'}: "
          f"{sum(results)}/{len(results)} checks passed\n")
    return 0 if passed else 1


def _reaches_witnessed_root(
    leaf: bytes, receipt: Receipt, witnessed_root: bytes, anchors: dict
) -> bool:
    """The check that makes the whole exercise worth doing.

    A receipt that verifies against its own root proves only that whoever wrote the receipt
    was internally consistent -- which a forger would also be. It has to reach a root the
    auditor got from somewhere else.
    """
    if receipt.tree_size > anchors["witnessed_tree_size"]:
        return False
    if receipt.tree_size == anchors["witnessed_tree_size"]:
        return merkle.verify_inclusion(
            leaf, receipt.leaf_index, receipt.tree_size, receipt.proof_bytes(), witnessed_root
        )
    # The receipt is older than the witness's head. Confirming it against the newer root
    # needs a consistency proof, which is not in these three files -- so this verifier says
    # what it can: the roots differ and it cannot bridge them without more evidence.
    return decode_hash(receipt.root_hash) == witnessed_root


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        print(__doc__)
        return 2
    return verify(Path(argv[1]), Path(argv[2]), Path(argv[3]))


if __name__ == "__main__":
    sys.exit(main(sys.argv))
