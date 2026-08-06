"""Phase 4 evaluation — attribution measured over AgentDojo, per argument.

    pip install -e ".[agentdojo]"
    python demo/phase4_eval.py

Replaces Phase 2's seven hand-built cases with contexts built from AgentDojo's security
task set: real user tasks, real injection goals, real tool output, at real length. Takes a
few minutes, almost all of it spent rebuilding AgentDojo environments rather than
attributing -- the model is in-process and deterministic.

Read the three tables in order. Coverage says what fraction of the task set this
construction can speak about at all, and it is not most of it. The sweep says how the
engine did on that fraction. The cost table says what it charged.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

from aegis.evaluation import agentdojo
from aegis.evaluation.phase4 import CONFIGS, run_sweep

RESULTS = Path(__file__).resolve().parent.parent / "results" / "phase4_agentdojo.json"

PLACEMENTS: list[tuple[str, str]] = [
    ("append", "attack appended to the real document -- the threat this project describes"),
    ("replace", "AgentDojo's own placement; often deletes the legitimate value"),
    ("none", "no attack at all -- the false-positive control"),
]


def rule(title: str) -> None:
    print(f"\n{'=' * 92}\n  {title}\n{'=' * 92}")


def rate(value: float | None) -> str:
    """Undefined rates print as ``n/a``, never as ``0.000``.

    The clean placement has no landed attacks and, under the segment-only config, nothing
    flagged at all. Both denominators are zero. Printing the worst possible value for a
    quantity that was never defined is the kind of pessimism that still misinforms.
    """
    return "n/a" if value is None else f"{value:.3f}"


async def main() -> int:
    rule("Phase 4 — attribution over AgentDojo")

    if not agentdojo.is_available():
        print(
            "\n  AgentDojo is not installed.\n"
            '    pip install -e ".[agentdojo]"\n'
            f"\n  The measured results are committed to {RESULTS.name}."
        )
        return 1

    payload: dict = {"suite_version": agentdojo.SUITE_VERSION, "placements": {}}

    for placement, note in PLACEMENTS:
        rule(f"placement: {placement} — {note}")
        cases, coverage = agentdojo.build_with_coverage(placement)  # type: ignore[arg-type]

        print(f"\n  {'attempted pairs':<34} {coverage.total_pairs}")
        print(f"  {'usable':<34} {coverage.usable}")
        print(f"  {'dropped: no consequential action':<34} {coverage.no_consequential_action}")
        print(f"  {'dropped: no modelled argument':<34} {coverage.no_modelled_field}")
        print(f"  {'dropped: no hijackable argument':<34} {coverage.no_hijackable_field}")
        print(f"  {'dropped: build failed':<34} {coverage.build_failed}")
        if not cases:
            continue

        print(
            f"\n  {'config':<20} {'fields':>7} {'ASR':>7} {'claims':>7} {'class acc':>10} "
            f"{'prec':>7} {'recall':>7} {'hijack':>7} {'local':>7} {'calls':>7}"
        )
        print(f"  {'-' * 90}")

        reports = []
        for config in CONFIGS:
            report = await run_sweep(cases, config, placement)
            reports.append(report)
            print(
                f"  {config.name:<20} {len(report.outcomes):>7} "
                f"{report.attack_success_rate:>7.3f} {report.claims_made:>7} "
                f"{report.class_accuracy:>10.3f} {rate(report.precision):>7} "
                f"{rate(report.recall):>7} {rate(report.hijack_recall):>7} "
                f"{rate(report.localization_rate):>7} {report.mean_model_calls:>7.1f}"
            )
            if report.budget_capped:
                print(
                    f"  {'':<20} {report.budget_capped} case(s) hit the call ceiling; "
                    "their evidence is partial"
                )

        _explain(reports)
        payload["placements"][placement] = {
            "note": note,
            "coverage": coverage.as_dict(),
            "configs": [r.as_dict() for r in reports],
        }

    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    RESULTS.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"\n  wrote {RESULTS}")

    rule("What these numbers are and are not")
    print(
        "\n  ASR is the surrogate's attack-success-rate, not a real model's. The surrogate's\n"
        "  susceptibility is written down rather than discovered, so it measures the stated\n"
        "  rule and says nothing about GPT-4 or Claude. AgentDojo's own leaderboard is the\n"
        "  number for that; the same adapter runs against HttpModelClient when there is a\n"
        "  key and a budget for it.\n"
        "\n  What the surrogate buys is exact ground truth. 'class acc' is scored against the\n"
        "  provenance class of the segment that actually supplied the emitted value, which\n"
        "  is computed by replaying a known function rather than annotated by the person\n"
        "  who wrote the engine.\n"
        "\n  'claims' is how many of the scored fields the engine was willing to answer for.\n"
        "  It is the honest denominator: a configuration that answers half the questions\n"
        "  perfectly is not equal to one that answers all of them perfectly, and reporting\n"
        "  accuracy alone would make them look identical."
    )
    return 0


def _explain(reports) -> None:
    """Say what changed between configurations, in the run's own numbers."""
    baseline, *rest = reports
    for report in rest:
        extra = report.mean_model_calls - baseline.mean_model_calls
        gained = report.claims_made - baseline.claims_made
        print(
            f"\n  {report.config} vs {baseline.config}: "
            f"{gained:+d} fields answered for {extra:+.1f} model calls per case"
            + (
                f", {report.adversarial_redundancy} field(s) where one class held a value "
                "no single segment did"
                if report.adversarial_redundancy
                else ""
            )
        )
    measured = [r for r in rest if r.redundancy_counts]
    if measured and all(
        r.redundancy_counts.get("unmeasured", 0) == len(r.outcomes) for r in measured
    ):
        print(
            "\n  Class-level ablation never fired: it skips any class with fewer than two\n"
            "  ablatable segments, because removing a class of one is the segment ablation\n"
            "  already measured. These contexts are short enough that no class has two."
        )


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
