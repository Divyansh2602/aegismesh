"""Produce the EU AI Act Article 12 record for a warrant.

    python tools/article12_export.py warrant.json [receipt.json] [--json]

Sits beside ``verify_warrant.py`` and takes the same files, because the two answer
different questions about the same artefact: that one asks whether the record is authentic,
this one asks what the record demonstrates about a legal obligation. Neither answers the
other, and a deployer needs both.

The receipt is optional and its absence changes the answer rather than being ignored:
without an inclusion proof there is no evidence the record was not withheld, so the
integrity requirement is reported as partial. Running this on a warrant alone and getting
"covered" would be the export lying on the operator's behalf.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aegis.compliance.article12 import export  # noqa: E402

MARK = {"covered": "yes", "partial": "partial", "not_covered": "NO"}


def load(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def main(argv: list[str]) -> int:
    args = [a for a in argv if not a.startswith("--")]
    if not args:
        print(__doc__)
        return 2

    warrant = load(args[0])
    receipt = load(args[1]) if len(args) > 1 else None
    report = export(warrant, receipt)

    if "--json" in argv:
        print(json.dumps(report, indent=2))
        return 0

    print(f"\n{report['framework']}")
    print(f"enforceable from {report['enforceable_from']}")
    print(f"warrant {report['warrant_id']}")
    print(f"issuer  {report['issuer']}\n")
    print(report["standards_status"])

    counts = report["summary"]
    # ASCII separators: this is run in terminals whose encoding is not the author's
    # problem to guess, and a mangled byte in a compliance report reads as corruption.
    print(
        f"\n{'=' * 78}\n"
        f"  {counts['covered']} covered | {counts['partial']} partial | "
        f"{counts['not_covered']} not covered\n{'=' * 78}"
    )

    for requirement in report["requirements"]:
        print(f"\n  [{MARK[requirement['coverage']]:>7}]  {requirement['ref']}")
        print(f"    {requirement['obligation']}")
        if requirement["mechanism"]:
            for line in _wrap(requirement["mechanism"]):
                print(f"      {line}")
        if requirement.get("gap"):
            print("    GAP:")
            for line in _wrap(requirement["gap"]):
                print(f"      {line}")

    print(f"\n{'=' * 78}")
    for line in _wrap(report["disclaimer"]):
        print(f"  {line}")
    print()
    # Exit 0 regardless of gaps. A non-zero exit would read as "this warrant failed", and
    # the gaps here are properties of the system and the deployment, not defects in the
    # record being examined.
    return 0


def _wrap(text: str, width: int = 70) -> list[str]:
    words, lines, current = text.split(), [], ""
    for word in words:
        if len(current) + len(word) + 1 > width:
            lines.append(current)
            current = word
        else:
            current = f"{current} {word}".strip()
    if current:
        lines.append(current)
    return lines


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
