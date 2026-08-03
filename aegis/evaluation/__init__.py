"""Evaluation harness: scores attribution against known ground truth."""

from aegis.evaluation.cases import Case, build_cases
from aegis.evaluation.harness import CaseOutcome, Report, run_evaluation

__all__ = ["Case", "CaseOutcome", "Report", "build_cases", "run_evaluation"]
