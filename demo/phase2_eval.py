"""Phase 2 evaluation — attribution accuracy and cost against known ground truth.

    python demo/phase2_eval.py

Runs entirely offline. Because the mock model's behaviour is a known function of its
input, every case carries an exact label, so precision and recall are measured rather than
asserted.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

from aegis.evaluation.harness import run_evaluation

RESULTS = Path(__file__).resolve().parent.parent / "results" / "phase2_evaluation.json"


def rule(title: str) -> None:
    print(f"\n{'=' * 78}\n  {title}\n{'=' * 78}")


async def main() -> int:
    rule("Phase 2 — attribution evaluation")

    report = await run_evaluation()

    print(f"\n  {'case':<38} {'truth':<11} {'flagged':<8} {'P3 share':<9} {'calls'}")
    print(f"  {'-' * 74}")
    for outcome in report.outcomes:
        if not outcome.poisoned:
            truth = "clean"
        elif outcome.effective:
            truth = "poisoned"
        else:
            truth = "no-effect"
        flag = "YES" if outcome.flagged else "no"
        mark = " " if outcome.correct else "X"
        print(
            f"{mark} {outcome.name:<38} {truth:<11} {flag:<8} "
            f"{outcome.untrusted_share:<9.2f} {outcome.model_calls}"
        )
    if report.ineffective_injections:
        print(
            f"\n  {report.ineffective_injections} injection(s) present but ineffective; "
            "reporting no causation for those is correct, not a miss."
        )

    rule("Detection")
    print(f"  precision          {report.precision:.3f}")
    print(f"  recall             {report.recall:.3f}")
    print(f"  f1                 {report.f1:.3f}")
    print(f"  localization rate  {report.localization_rate:.3f}   "
          f"(top contributor points at the injected message)")

    rule("Cost")
    print(f"  mean model calls per consequential action   {report.mean_model_calls:.1f}")
    print(f"  worst case                                  {report.max_model_calls}")
    print("\n  Cost is reported as prominently as accuracy on purpose: an attribution")
    print("  method that is accurate and unaffordable does not ship.")

    rule("Ablation-mode comparison  (SPEC.md open question 5)")
    placeholder = report
    deleted = await run_evaluation(mode="delete")
    print(f"  placeholder   f1={placeholder.f1:.3f}  "
          f"mean_calls={placeholder.mean_model_calls:.1f}")
    print(f"  delete        f1={deleted.f1:.3f}  mean_calls={deleted.mean_model_calls:.1f}")

    rule("Sentence drill-down contribution")
    segment_only = await run_evaluation(sentence_drilldown=False)
    print(f"  segment only         f1={segment_only.f1:.3f}  "
          f"localization={segment_only.localization_rate:.3f}  "
          f"mean_calls={segment_only.mean_model_calls:.1f}")
    print(f"  segment + sentence   f1={report.f1:.3f}  "
          f"localization={report.localization_rate:.3f}  "
          f"mean_calls={report.mean_model_calls:.1f}")

    RESULTS.parent.mkdir(exist_ok=True)
    RESULTS.write_text(
        json.dumps(
            {
                "placeholder_segment_and_sentence": report.as_dict(),
                "delete_mode": deleted.as_dict(),
                "segment_only": segment_only.as_dict(),
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    print(f"\n  Results written to {RESULTS.relative_to(RESULTS.parent.parent)}\n")

    failures = [o.name for o in report.outcomes if not o.correct]
    if failures:
        print(f"  MISCLASSIFIED: {', '.join(failures)}\n")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
