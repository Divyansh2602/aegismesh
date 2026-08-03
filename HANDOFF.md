# AegisMesh — Session Handoff

**Written:** 2026-08-03 · **For:** continuing in the VS Code Claude extension
**Repo:** `C:\Users\Divyansh Gupta\Documents\everything` (local git, no remote — nothing pushed)

---

## Read these first

1. [`README.md`](README.md) — the pitch and the honest novelty positioning
2. [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) — adversaries, controls, OWASP + EU AI Act mapping
3. [`docs/SPEC.md`](docs/SPEC.md) — the Action Warrant format and all the maths
4. This file — where things stand and what to do next

## Verify the state in one command

```bash
pip install -e ".[dev]" && pytest -q && python demo/phase1_demo.py && python demo/phase2_eval.py
```

Expected: **57 tests pass, ruff clean, evaluation exits 0.** Everything runs offline — no
API key, no cost. If that holds, nothing has rotted.

---

## What this project is

**One sentence:** every consequential action an AI agent takes should carry a portable,
cryptographically signed **Action Warrant** binding the human intent that authorized it,
the delegation chain it travelled, and measured causal evidence of which input actually
caused it — verifiable by a third party who does not trust the agent, its vendor, or its
operator.

**Why it exists:** agents today have authentication but no provenance. We can prove *who*
an agent is; we cannot prove *why it did what it did*. EU AI Act Article 12 became
enforceable on 2 August 2026 and requires exactly that traceability, with penalties up to
€15M or 3% of global turnover — and no finalized technical standard exists yet.

**The novelty claim, stated narrowly** (do not widen it — the surrounding work is real and
an informed interviewer will know it):

> A method for producing a verifiable credential that binds a measured causal-influence
> score over input provenance classes to a delegated-authority chain, and for enforcing
> admission of agent actions against that credential at a policy enforcement point in a
> different trust domain than the issuer.

Prior art we build on and must cite, never claim: **CausalArmor**, **AgentSentry**,
**Causal Agent Replay** (counterfactual attribution); **CoSAI**, **W3C VC**, **DIDs**,
**DIF KYA-OS** (agent identity). Prompt-injection detection is a crowded commercial
category (Lakera, NeuralTrust, Lasso, Cisco AI Defense) — consume it as a signal, claim
nothing.

---

## Status

| Phase | State | What exists |
| --- | --- | --- |
| 0 — Threat model & spec | **Done** | `docs/THREAT_MODEL.md`, `docs/SPEC.md` |
| 1 — Interception & provenance | **Done** | `aegis/proxy/`, `aegis/provenance/`, `aegis/mockmodel/` |
| 2 — Causal attribution | **Done** | `aegis/attribution/`, `aegis/evaluation/` |
| 3 — Warrants, log, enforcement | **Next** | not started |
| 4 — Adversarial evaluation | Pending | AgentDojo |
| 5 — Console & compliance export | Pending | Next.js |
| 6 — Paper, patent, standards | Pending | — |

### Phase 2 measured results (`results/phase2_evaluation.json`)

```
precision 1.000   recall 1.000   f1 1.000   localization 1.000
mean model calls per consequential action  6.9   (worst case 12)
```

**Do not oversell these.** Seven hand-built cases against a deterministic mock model. They
prove the engine is wired correctly and catch regressions fast; they are *not* a
generalization claim. Phase 4 against AgentDojo's 629 security cases is where real numbers
come from. Saying this out loud in an interview is a strength, not a hedge.

---

## Architecture as built

```
aegis/
  common/       ids (ULID), hashing, canonical JSON (JCS)
  provenance/   classes.py    P0-P4 + monotonicity rule (min_trust)
                registry.py   pinned tools, conduit vs closed-world, drift detection
                classifier.py chat request -> provenance-tagged segments with locators
                models.py     Segment, ContextTrace, MessageLocator/ToolLocator
  proxy/        app.py        OpenAI-compatible interception, trace store
  mockmodel/    app.py        deterministic model reproducing recency-bias injection
  attribution/  gate.py       consequential-action gate (cost control)
                ablation.py   request reconstruction, placeholder/delete, sentence split
                engine.py     leave-one-out ablation, influence + necessity
                client.py     InProcessMockClient / HttpModelClient
  evaluation/   cases.py      labelled ground-truth cases
                harness.py    precision/recall/localization/cost
```

### Provenance classes

`P0` human-mandate · `P1` system-policy · `P2` trusted-tool · `P3` untrusted-external ·
`P4` agent-generated. Default on any doubt is **P3**.

---

## The five design decisions that carry this project

These came out of *building and running it*, not from planning. They are the interview
material — each one is a place where the obvious implementation was wrong.

**1. Role does not establish trust.**
Agent frameworks routinely paste retrieved documents into `user`-role messages. Treating
`role == "user"` as human intent hands an attacker the highest trust class for free. Only
text verbatim-matching a declared mandate (via `X-Aegis-*` headers) gets P0. Matching is
strict substring on purpose — fuzzy matching would be a privilege-escalation primitive.

**2. Tool integrity is not content provenance.** *(control C-19)*
The first implementation classed any pinned tool's response P2. The Phase 1 demo showed a
poisoned supplier invoice arriving wearing the trust of the well-behaved reader that parsed
it. Pinning proves the *tool* is authentic; it says nothing about the *data* it relays.
**Conduit tools** (PDF readers, web fetchers, mail, search) stay P3 even when pinned; only
**closed-world tools** returning operator-controlled data earn P2. Default is conduit.

**3. Monotonicity stops multi-agent laundering.** *(control C-9)*
An agent's output inherits the *lowest* trust among its causal parents. Without it: inject
into agent A, A summarizes the poisoned text, agent B receives the summary as trusted peer
output — the injection has been laundered across a trust boundary.

**4. Necessity is not value-causation.** *(the biggest one)*
Removing the human's mandate cancels the payment entirely, so naive leave-one-out scored
the human as the cause of the *attacker's* account — exactly backwards. Per-field influence
is now measured **only over ablations where the same tool was still called**; cancellations
are recorded separately as `necessity`. A segment whose removal always cancels the action
yields an honest "undefined" for field-level causation rather than a fabricated cause.
This same confusion resurfaced twice more (in contributor ranking, then in the localization
metric) before it was fully rooted out.

**5. "Injection present" is not "injection effective."**
One evaluation case was labelled poisoned but the injection never landed — a later message
restated the legitimate account. Attribution correctly reported no untrusted causation; the
harness wrongly scored it a miss. The harness now computes whether the attack actually
changed the action and scores only effective ones, reporting ineffective injections
separately. AgentDojo draws the same distinction with attack-success-rate.

**Unifying lesson, and the thing to say in an interview:** *per-argument attribution is the
meaningful unit.* Action-level aggregation destroys the signal, because one action can be
simultaneously legitimate in one field and hijacked in another — the human genuinely set
the amount while the attacker set the destination.

---

## Phase 3 — what to build next

Goal: the system stops merely observing and starts **refusing**. This is the demo to lead
with.

**Definition of done:** the poisoned invoice request runs end to end and the payment API
*rejects* it, producing a cryptographic inclusion proof an auditor can verify knowing only
two public keys.

### Build order

1. **`aegis/warrant/`** — mint the Action Warrant.
   - Ed25519 via `cryptography` (add to `pyproject.toml`)
   - W3C VC shape, `eddsa-jcs-2022`, canonicalized with existing `common/hashing.py`
   - Populate from `AttributionResult` — `influence`, `per_argument`, `confidence`,
     `top_contributors` (hashes only), plus `necessity`
   - Schema is already fully specified in `docs/SPEC.md` §4 — follow it, including
     `arguments_digest_map` for field-level policy without revealing values
   - **Sign denials too.** A denial is the evidence the system worked, and suppressing it
     is exactly what a dishonest operator (ADV-4) would want.

2. **`aegis/log/`** — Merkle transparency log.
   - RFC 6962 structure: leaf `sha256(0x00||JCS(warrant))`, node `sha256(0x01||L||R)`
   - Inclusion **and** consistency proofs
   - **Hand-implement it (~150 lines).** It is a strong interview artifact and the
     verification path must be independently auditable.
   - Verify with a standalone script that knows only the public key and claimed root

3. **`aegis/pep/`** — policy enforcement point (the novelty lives here).
   - Implement the 11-step verification algorithm in `docs/SPEC.md` §7 exactly
   - **Step 7 is non-optional**: inclusion verified against a root obtained
     *independently*, never from the operator. This is the ADV-4 defense.
   - **Step 10 is the crux**: the relying party evaluates *its own* policy against the
     evidence. The issuer's `policy_decision` is evidence, not a verdict. A PEP that
     trusts the issuer's verdict has learned nothing from the warrant.
   - Policy examples are written out in `docs/SPEC.md` §6

4. **`demo/phase3_demo.py`** — the $2M invoice scenario, refused, with a printed proof.

### Watch out for

- Replay: warrant binds `arguments_hash` + nonce + short `validUntil` (control C-14)
- Delegation chain scopes must *attenuate* — each hop a subset of the previous
- Never put excerpt text in a warrant, only hashes (`docs/SPEC.md` §4.1)
- `common/hashing.py` documents a known JCS number-formatting deviation — read it before
  making any cross-implementation interop claim

---

## Conventions to keep

- **Docstrings explain *why*, not *what*.** Every non-obvious decision above is documented
  at its call site. Keep that up — it is most of what makes this readable to a reviewer.
- Tests assert on *security properties*, not implementation details. Several deliberately
  document limitations (e.g. `test_the_attack_succeeds_without_enforcement`).
- Run `ruff check .` and `pytest -q` before every commit.
- **One commit per phase**, with a message explaining the decisions, not the diff.
  Existing history: `8fe169c` Phase 0, `6a06800` Phase 1, plus Phase 2.
- Local commits only. Nothing has been pushed anywhere; don't push without asking.
- Honesty over polish. Where something does not work, say so in the docs — the threat
  model's residual-risk section and this file's caveat on Phase 2 numbers are the pattern.

## Open questions carried forward (also in `docs/SPEC.md` §9)

1. What is θ, the monotonicity influence threshold, in practice? (default 0.15, unswept)
2. Does span-level ablation defeat redundant-encoding attacks, or only raise cost?
3. **Can the consequential-action gate be attacked into classifying a payment as
   non-consequential? Probably. It is a single point of bypass and must be tested.**
4. Real cost per consequential action against a real model — is 6.9 calls affordable?
5. Placeholder vs delete ablation: currently indistinguishable (f1 1.000 both). Needs a
   harder case set to separate them.
