"""The consequential-action gate.

Ablation costs one model call per segment per resample, so running it on every action is
not deployable. The gate decides which actions are worth measuring: those with external
side effects -- money moving, data leaving, state being destroyed.

This is also a single point of bypass, and SPEC.md section 9 flags it as such. An attacker
who can make a payment look non-consequential skips attribution entirely. Two consequences
for the design:

  * The gate matches on the *operation*, never on model-supplied free text. An attacker
    influences arguments far more easily than they influence which tool exists.
  * Unknown operations are treated as consequential, not as safe. A tool nobody classified
    is a tool nobody reviewed.
"""

from __future__ import annotations

import re

from pydantic import BaseModel

from aegis.attribution.models import ActionSignature

#: Verbs that imply an external side effect.
#:
#: Extended in Phase 4 after attacking the gate. The additions are all verbs that name a
#: consequential operation in ordinary product vocabulary and were absent: ``checkout``,
#: ``wire``, ``replace``, ``approve``, ``charge``. Because a consequential match is tested
#: *before* a read-only one, growing this tuple can only ever move an operation toward
#: being measured, so additions are safe and omissions are not.
CONSEQUENTIAL_VERBS = (
    "transfer", "pay", "purchase", "refund", "remit", "settle", "withdraw",
    "send", "email", "post", "publish", "share", "invite", "notify",
    "delete", "remove", "drop", "revoke", "disable", "terminate",
    "create", "update", "write", "modify", "patch", "upload", "grant",
    "execute", "run", "deploy", "install",
    "checkout", "wire", "charge", "debit", "credit", "buy", "sell", "trade",
    "order", "book", "reserve", "subscribe", "cancel", "approve", "sign",
    "submit", "issue", "mint", "replace", "overwrite", "truncate", "reset",
    "rotate", "archive", "schedule", "move", "rename", "restore", "merge",
)

#: Operations known to be read-only. Explicit allowlist -- membership must be earned.
#:
#: **This list is the gate's residual risk and it is not closable by adding words.** An
#: operation whose name contains only read verbs is never attributed, so a tool called
#: ``check_out``, ``find_and_replace`` or ``describe_and_wire`` bypasses the whole system
#: while doing something consequential. Widening ``CONSEQUENTIAL_VERBS`` raises the bar; it
#: does not remove the bypass, because the attacker picks the name.
#:
#: The mitigation that works is not lexical: an operator must pass consequential operations
#: explicitly, and a tool nobody classified is already treated as consequential. Naming is a
#: fallback for unreviewed tools, and for those the read-verb branch is the dangerous
#: direction. THREAT_MODEL.md section 6 carries this as a demonstrated evasion.
READ_ONLY_VERBS = (
    "get", "list", "read", "search", "query", "find", "lookup", "fetch",
    "describe", "summarize", "summarise", "view", "check", "count",
)

_WORD = re.compile(r"[a-z]+")


class GateDecision(BaseModel):
    consequential: bool
    reason: str


class ConsequenceGate:
    """Classifies actions as consequential or not.

    ``read_only`` and ``consequential`` override the verb heuristics for operations the
    operator has explicitly reviewed. Explicit classification always beats inference.
    """

    def __init__(
        self,
        read_only: set[str] | None = None,
        consequential: set[str] | None = None,
    ) -> None:
        self.read_only = read_only or set()
        self.consequential = consequential or set()

    def evaluate(self, action: ActionSignature) -> GateDecision:
        if action.is_empty():
            return GateDecision(
                consequential=False, reason="no tool call proposed; nothing to attribute"
            )

        name = (action.tool or "").lower()

        if name in self.consequential:
            return GateDecision(
                consequential=True, reason=f"'{name}' is explicitly classified consequential"
            )
        if name in self.read_only:
            return GateDecision(
                consequential=False, reason=f"'{name}' is explicitly classified read-only"
            )

        words = set(_WORD.findall(name))

        if words & set(CONSEQUENTIAL_VERBS):
            matched = sorted(words & set(CONSEQUENTIAL_VERBS))
            return GateDecision(
                consequential=True,
                reason=f"operation name contains side-effecting verb(s): {', '.join(matched)}",
            )

        if words & set(READ_ONLY_VERBS):
            matched = sorted(words & set(READ_ONLY_VERBS))
            return GateDecision(
                consequential=False,
                reason=f"operation name contains only read verb(s): {', '.join(matched)}",
            )

        return GateDecision(
            consequential=True,
            reason=(
                f"'{name}' is unclassified; treated as consequential because an "
                "unreviewed tool is not a safe tool"
            ),
        )
