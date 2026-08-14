"""Standalone transparency-log consistency verifier.

    python tools/verify_consistency.py earlier.json later.json trust_anchors.json

Answers the question ``verify_warrant.py`` deliberately cannot: **is the log I am being
shown today the same log I was shown before, extended -- or a different one?**

An inclusion proof says a warrant is in *some* tree. Consistency says the tree it is in is
the same tree, grown, as the one you were handed last time. Without it, an operator can
hand every visitor a fresh history with their own entry in it, and every warrant still
verifies. That is the whole difference between a log and a list.

``verify_warrant.py`` says so at its last check: when a receipt is older than the root the
auditor holds, it compares the two roots and gives up, because bridging them needs a proof
that is not in those three files. This tool is that bridge, and it is a separate program
rather than a fourth argument because it answers a different question from different inputs
-- and because a verifier that grew an optional mode for every extra file it might be given
is one nobody can audit by reading it.

Inputs, all files, no network:

  earlier.json   anything carrying a signed tree head from the *earlier* observation --
                 a ``receipt.json`` from a previous visit works unchanged.
  later.json     the ``GET /v1/log/consistency?first=<earlier tree_size>`` response, which
                 carries the proof and the log's current signed head.
  trust_anchors  for ``log_public_key_multibase``. One public key is all this needs.

**What a pass proves.** The log signed both heads, and the later tree contains the earlier
one as a prefix: nothing you were shown before was removed, reordered, or edited.

**What a pass does not prove, and this matters.** It cannot detect a *split view*. A log
that signs two divergent histories and shows each to a different auditor gives both of them
a chain that verifies perfectly. Catching that requires comparing heads with somebody in
another trust domain -- which is what ``aegis/log/witness.py`` is for, and why the witness
is not optional scaffolding. Consistency is what one auditor can establish alone; agreement
between auditors is a strictly stronger claim that no single verifier can reach.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from aegis.log import merkle
from aegis.log.log import SignedTreeHead, decode_hash
from aegis.warrant.keys import VerifyingKey

OK, BAD = "  [ok]  ", "  [FAIL]"


def check(label: str, passed: bool, detail: str = "") -> bool:
    print(f"{OK if passed else BAD} {label}{'  ' + detail if detail else ''}")
    return passed


def _read_head(document: dict[str, Any], source: str) -> SignedTreeHead:
    """Pull a signed tree head out of whichever artifact the auditor happens to hold.

    A receipt calls it ``signed_root`` and a consistency response calls it
    ``signed_tree_head``; both are the same object. Accepting either -- and a bare head --
    means an auditor can point this at the file they were actually given rather than
    hand-editing JSON to match a shape the tool preferred, which is the kind of step that
    makes people give up on verifying things.
    """
    for key in ("signed_root", "signed_tree_head"):
        if isinstance(document.get(key), dict):
            return SignedTreeHead.model_validate(document[key])
    if "root_hash" in document and "tree_size" in document:
        return SignedTreeHead.model_validate(document)
    raise SystemExit(
        f"{source}: no signed tree head here. Expected a receipt (`signed_root`), a "
        "/v1/log/consistency response (`signed_tree_head`), or a bare head."
    )


def verify(earlier_path: Path, later_path: Path, anchors_path: Path) -> int:
    earlier_doc = json.loads(earlier_path.read_text(encoding="utf-8"))
    later_doc = json.loads(later_path.read_text(encoding="utf-8"))
    anchors = json.loads(anchors_path.read_text(encoding="utf-8"))

    earlier = _read_head(earlier_doc, str(earlier_path))
    later = _read_head(later_doc, str(later_path))
    log_key = VerifyingKey.from_multibase(anchors["log_public_key_multibase"])
    proof = [decode_hash(h) for h in later_doc.get("proof", [])]

    print(f"\nLog      {earlier.log_id}")
    print(f"Earlier  size {earlier.tree_size}  {earlier.root_hash}")
    print(f"Later    size {later.tree_size}  {later.root_hash}")
    print("\nTrust anchors held by this verifier: 1 public key.\n")

    results = [
        check("earlier head verifies under the log key", earlier.verify(log_key)),
        check("later head verifies under the log key", later.verify(log_key)),
        check(
            "both heads name the same log",
            earlier.log_id == later.log_id == anchors.get("log_id", earlier.log_id),
            str(earlier.log_id),
        ),
        # Checked before the proof, because a shrunken tree has a clear cause and a failed
        # proof does not. "The log went backwards" tells an auditor what happened; "the
        # consistency proof did not verify" leaves them to work it out.
        check(
            "the tree did not shrink",
            later.tree_size >= earlier.tree_size,
            f"{earlier.tree_size} -> {later.tree_size}",
        ),
        # Without this, a log under pressure could answer with a genuine proof between two
        # *other* heads: every hash would check out and the answer would be about a pair of
        # trees the auditor never asked about.
        check(
            "the proof is about these two heads",
            later_doc.get("first") in (None, earlier.tree_size)
            and later_doc.get("second") in (None, later.tree_size),
            f"first={later_doc.get('first')} second={later_doc.get('second')}",
        ),
        check(
            "the later tree extends the earlier one",
            merkle.verify_consistency(
                earlier.tree_size,
                later.tree_size,
                decode_hash(earlier.root_hash),
                decode_hash(later.root_hash),
                proof,
            ),
            f"{len(proof)} proof node{'' if len(proof) == 1 else 's'}",
        ),
    ]

    passed = all(results)
    print(
        f"\n{'CONSISTENT' if passed else 'INCONSISTENT'}: "
        f"{sum(results)}/{len(results)} checks passed"
    )

    if passed:
        grew = later.tree_size - earlier.tree_size
        print(
            f"\nNothing you were shown before was removed, reordered or edited; the log "
            f"grew by {grew} entr{'y' if grew == 1 else 'ies'}."
        )
    else:
        print(
            "\nThe log presented two histories that cannot both be true: an entry was "
            "altered, removed, or reordered.\nThere is no benign explanation for this."
        )

    print(
        "\nWhat this cannot tell you: whether the log showed somebody else a different\n"
        "history. A split view signs two divergent chains and hands each to one auditor,\n"
        "and both verify. Detecting it needs heads compared across trust domains --\n"
        "aegis/log/witness.py, and gossip between auditors who do not trust each other.\n"
    )
    return 0 if passed else 1


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        print(__doc__)
        return 2
    return verify(Path(argv[1]), Path(argv[2]), Path(argv[3]))


if __name__ == "__main__":
    sys.exit(main(sys.argv))
