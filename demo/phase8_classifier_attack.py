"""Phase 8 demo — attacking the classifier itself.

    python demo/phase8_classifier_attack.py

Runs entirely offline. No API key, no cost.

Phase 4 measured attribution **given correct classification**, and said so. This closes the
gap that left: residual risk 1, the P0 boundary, which decides what counts as human intent
and which nothing downstream can second-guess. Attribution measures over the classes this
produces, the warrant signs them, and the relying party enforces on them — so a classifier
that can be talked out of its own labels makes every number after it a confident
measurement of the wrong thing.

Three attacks succeed. They stay in the output, and they are the most useful part of it.
"""

from __future__ import annotations

import sys

from aegis.evaluation.classifier_attacks import AttackOutcome, run_attacks

#: Attacks whose failure is a finding we have written down rather than a regression. If one
#: of these starts holding, a limitation was closed and the docs need updating — the demo
#: says so rather than quietly turning green.
KNOWN_BROKEN = {
    "forged_tool_name",
    "mandate_echoed_before_the_real_one",
}
"""``unclassified_content_part`` was here and was fixed: the extraction rule now lives in
one place, ``provenance/content.py``, imported by both the classifier and ablation, and it
keeps any part carrying a ``text`` field rather than only ``type == "text"``. It is the one
finding of the three whose fix cost nothing to get right."""


def rule(title: str) -> None:
    print(f"\n{'=' * 78}\n  {title}\n{'=' * 78}")


def report(outcome: AttackOutcome) -> None:
    verdict = "DEFENCE HELD" if outcome.held else "ATTACK SUCCEEDED"
    print(f"\n  [{verdict}]  {outcome.name}")
    print(f"    does:     {outcome.what_it_does}")
    print(f"    expected: {outcome.expectation}")
    print(f"    classes:  {outcome.detail}")
    if outcome.note:
        for line in _wrap(outcome.note):
            print(f"    {line}")


def _wrap(text: str, width: int = 72) -> list[str]:
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


def main() -> int:
    outcomes = run_attacks()
    held = [o for o in outcomes if o.held]
    broken = [o for o in outcomes if not o.held]

    rule("Attacking the P0 boundary and the trust classes around it")
    print(
        f"  {len(outcomes)} attacks, {len(held)} defences held, {len(broken)} succeeded.\n\n"
        "  Phase 4 measured attribution given correct classification. Nothing had ever\n"
        "  attacked the classification itself, which is residual risk 1 in our own threat\n"
        "  model. These are the results of doing that."
    )

    rule("Attacks that succeeded — the findings")
    if not broken:
        print("\n  None. If this is unexpected, the checks are the thing to distrust.")
    for outcome in broken:
        report(outcome)

    rule("Attacks the design turned away")
    for outcome in held:
        report(outcome)

    rule("What this changes")
    print(
        "  The two coverage failures are worse than a misclassification, and the\n"
        "  distinction is the point. A segment classified P3 when it should be P0 is\n"
        "  visible, ablatable and arguable. A byte the classifier never saw is none of\n"
        "  those: it reaches the model, influences the action, and no counterfactual can\n"
        "  test it, because attribution can only ablate what classification produced.\n"
        "\n"
        "  Stated as a property rather than as a list of bugs: **the classified text and\n"
        "  the text the model receives must be the same text.** Nothing in the design\n"
        "  enforced that, and two of these attacks are what happens when it is not.\n"
    )

    regressions = [o for o in held if o.name in KNOWN_BROKEN]
    surprises = [o for o in broken if o.name not in KNOWN_BROKEN]

    for outcome in regressions:
        print(f"  NOTE: '{outcome.name}' now holds. A limitation was closed; update the docs.")

    if surprises:
        for outcome in surprises:
            print(f"\n  UNEXPECTED: '{outcome.name}' broke and is not a known finding.")
        print("\n  A control that used to hold has stopped holding. That is a regression.\n")
        return 1

    print("  Every control-class attack still holds; the three findings are documented in")
    print("  docs/THREAT_MODEL.md section 6.\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
