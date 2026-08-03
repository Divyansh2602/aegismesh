# AegisMesh — Session Handoff

**Written:** 2026-08-04 · **For:** continuing in the VS Code Claude extension
**Repo:** `C:\Users\Divyansh Gupta\Documents\everything` (local git, no remote — nothing pushed)

---

## Read these first

1. [`README.md`](README.md) — the pitch and the honest novelty positioning
2. [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) — adversaries, controls, OWASP + EU AI Act mapping
3. [`docs/SPEC.md`](docs/SPEC.md) — the Action Warrant format and all the maths
4. This file — where things stand and what to do next

## Verify the state in one command

```bash
pip install -e ".[dev]" && pytest -q && ruff check .   && python demo/phase1_demo.py && python demo/phase2_eval.py && python demo/phase3_demo.py   && python tools/verify_warrant.py        results/phase3_warrant.json results/phase3_receipt.json results/phase3_trust_anchors.json
```

Expected: **263 tests pass, ruff clean, all three demos exit 0, and the standalone verifier
reports 6/6 checks passed.** Everything runs offline — no API key, no cost. If that holds,
nothing has rotted.

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
| 3 — Warrants, log, enforcement | **Done** | `aegis/warrant/`, `aegis/log/`, `aegis/policy/`, `aegis/pep/`, `tools/verify_warrant.py` |
| 4 — Adversarial evaluation | **Next** | AgentDojo |
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
  common/       ids (ULID), hashing + RFC 8785 JCS, decimals (fixed-precision scores)
  provenance/   classes.py    P0-P4 + monotonicity rule (min_trust)
                registry.py   pinned tools, conduit vs closed-world, drift detection
                classifier.py chat request -> provenance-tagged segments with locators
                models.py     Segment, ContextTrace, MessageLocator/ToolLocator
  proxy/        app.py        OpenAI-compatible interception, trace store
  mockmodel/    app.py        deterministic model reproducing recency-bias injection
  attribution/  gate.py       consequential-action gate (cost control)
                ablation.py   request reconstruction, placeholder/delete, sentence split
                engine.py     leave-one-out ablation, influence/necessity/argument_status
                client.py     InProcessMockClient / HttpModelClient
  evaluation/   cases.py      labelled ground-truth cases
                harness.py    precision/recall/localization/cost
  warrant/      keys.py       Ed25519, base58btc/multibase, KeyRing (stands in for DID)
                models.py     the W3C VC as pydantic, per SPEC section 4
                issuer.py     eddsa-jcs-2022 signing, replay_ref, verify_signature
  log/          merkle.py     RFC 6962 by hand: inclusion + consistency, both directions
                log.py        append-only log, signed tree heads, receipts
                witness.py    independent observer; raises ForkDetected
  policy/       engine.py     declarative rules as data, so policy_hash means something
                library.py    the treasury policy (SPEC section 6) and issuer policies
                evidence.py   builds the evaluation input in both trust domains
  pep/          verifier.py   the eleven-step algorithm (SPEC section 7)
                replay.py     nonce cache, bounded by time not by count

tools/
  verify_warrant.py           standalone auditor path: 2 public keys, 1 root, nothing else
```

`policy/` is its own package rather than living inside `pep/` because the issuer and the
enforcement point both use it. They share an *evaluator*, never a *policy* — and they are
expected to disagree.

### Provenance classes

`P0` human-mandate · `P1` system-policy · `P2` trusted-tool · `P3` untrusted-external ·
`P4` agent-generated. Default on any doubt is **P3**.

---

## The design decisions that carry this project

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

**6. "No measured influence" is two different findings, and merging them denies real work.**
*(Phase 3, and the sharpest one yet)*
Enforcing on Phase 2's evidence refused the **legitimate** payment. In the clean case the
destination account is named by both the human's mandate and Acme's own ledger, so removing
either leaves the other and no single ablation changes the value. Every class scored zero —
and the engine normalized that all-zero total into a **uniform** distribution, asserting a
0.2 untrusted share it had never measured, which tripped a policy forbidding any untrusted
influence on that field.

Zero influence *after a comparable run* is evidence of invariance. Zero influence *because
every run cancelled the action* is the absence of evidence. Only the second is grounds to
fail closed. Fields now carry `argument_status` ∈ {`attributed`, `invariant`, `unknown`}.

Two things make this worth telling. First, **redundancy is the normal case for legitimate
actions** — a design that cannot express it fails asset A6, and a control that blocks real
work gets switched off. Second, **Phase 2's metrics could not see it**: the harness flags at
a 0.5 untrusted share and the fabricated value was 0.2, so it sat quietly under the
threshold and every number still read 1.000. It took building the enforcement layer to
surface it. That is the argument for building the thing that consumes your metric.

**7. Canonicalization is not a detail when a third party has to reproduce your bytes.**
The signed payload must be byte-reproducible by a verifier in another language, and
`json.dumps` is not RFC 8785 — Python writes the mock model's `amount: 2000000.0` as
`2000000.0` where every JCS implementation writes `2000000`. That value goes straight into
`arguments_hash`, so an honest relying party recomputing it would have concluded the warrant
was tampered with. `common/hashing.py` is now a real JCS implementation (ECMAScript
`Number::toString`, UTF-16 key ordering, minimal escaping). Scores we *do* control are
carried as fixed-precision decimal strings instead, which takes them out of the argument
entirely. The earlier code documented this deviation and deferred it on the grounds that it
could not be reached; it was on the critical path the whole time.

**Unifying lesson, and the thing to say in an interview:** *per-argument attribution is the
meaningful unit.* Action-level aggregation destroys the signal, because one action can be
simultaneously legitimate in one field and hijacked in another — the human genuinely set
the amount while the attacker set the destination. Decision 6 is the same lesson arriving
from the other side: the per-field answer has three possible values, not two, and flattening
them is how a correct system refuses correct work.

---

## Phase 3 — what was built

**Definition of done, met:** the poisoned invoice request runs end to end, the payment API
rejects it, and `tools/verify_warrant.py` confirms the result knowing only two public keys
and one root hash.

`python demo/phase3_demo.py` runs the attack and then attacks the defence:

| Scene | What it shows |
| --- | --- |
| 1–5 | poisoned transfer → attribution → signed warrant → logged & witnessed → **REJECTED** |
| 6 | the same pipeline **admits** the legitimate payment (asset A6) |
| 7 | operator edits the warrant's attribution → signature breaks |
| 8 | operator signs a **permit** → the payment API denies on its own policy (step 10) |
| 9 | operator forks the log → the auditor's witness detects it, both heads validly signed |
| 10 | valid warrant replayed onto a larger transfer → arguments binding rejects it (C-14) |

Decisions worth defending:

- **Merkle log hand-implemented** (~150 lines, RFC 6962). The tamper-evidence claim reduces
  entirely to whether those functions are correct, so they must be independently readable.
  Tested by sweeping every (index, size) and every (first, second) pair up to 17 — proof
  bugs are shape bugs that appear only at non-power-of-two sizes.
- **The witness is not optional scaffolding.** Without a party in another trust domain
  holding a root, SPEC step 7 is a comment: the operator would supply the warrant, the
  receipt, and the root to check it against.
- **Denials are signed and logged like permits.** An issuer that logs only its permits
  produces an audit trail in which nothing ever went wrong.
- **`replay_ref` is emitted now, verified in Phase 4.** It sits under the signature, so
  adding it later would invalidate every warrant already issued.
- **Rules are data, not callables**, so `policy_hash` covers the whole policy rather than a
  rule's name while its behaviour lives in a function body nobody committed to.

---

## Phase 4 — what to build next

Goal: replace hand-built confidence with measured numbers, and attack our own system on
purpose. This is where the honest results come from.

**Definition of done:** attribution precision/recall and enforcement outcomes reported over
AgentDojo's security cases, with at least one working evasion documented rather than hidden.

### Build order

1. **`aegis/evaluation/agentdojo.py`** — adapter for AgentDojo's 629 security cases.
   - Map their suites onto our provenance classes and consequential-action gate
   - Report attack-success-rate alongside our precision/recall; they measure different
     things and both matter
   - **Expect the numbers to drop.** Seven hand-built cases against a deterministic mock is
     a wiring proof. If AgentDojo reproduces 1.000, distrust the adapter before the engine.

2. **Class-level ablation** — the highest-value attribution change, and the answer to
   SPEC §9 open question 6.
   - Ablate every segment of one provenance class at once, per class
   - Separates benign redundancy (human and ledger agree) from adversarial redundancy (an
     attacker plants the same value twice so no single removal moves it) — which
     `argument_status: invariant` currently cannot tell apart
   - Costs |classes| extra calls; measure whether it earns them

3. **Span-level ablation (control C-15)** — specified since Phase 0, still unbuilt.
   - The only route to attributing a field entangled with the transfer intent in the same
     segment. The `amount` in our own demo is permanently `invariant` without it.

4. **`aegis/audit/replay.py`** — the verifier for `replay_ref`.
   - Re-run the ablation from a disclosed trace and compare against the signed numbers
   - This is what turns a lying issuer from *non-repudiable* into *falsifiable*
   - The commitment fields already ship; only the checker is missing

5. **Attack the gate.** SPEC §9 open question 3 has been flagged since Phase 0 and is still
   untested. It is a single point of bypass: an action the gate calls non-consequential
   never gets attributed at all.

6. **Sweep θ**, the monotonicity threshold (default 0.15, never swept).

### Watch out for

- The Phase 2 case set must keep passing; it is the fast regression signal
- Cost is a headline result, not a footnote — an accurate method nobody can afford does
  not ship
- Report evasions that work. THREAT_MODEL §6 is the format

---

## Conventions to keep

- **Docstrings explain *why*, not *what*.** Every non-obvious decision above is documented
  at its call site. Keep that up — it is most of what makes this readable to a reviewer.
- Tests assert on *security properties*, not implementation details. Several deliberately
  document limitations and are written to **pass while the system does the wrong thing** —
  `test_the_attack_succeeds_without_enforcement`,
  `test_the_log_does_not_prove_the_attribution_is_true`,
  `test_a_suppressed_denial_leaves_no_gap`. Do not "fix" these; they are the honesty
  mechanism. If one starts failing, a limitation was closed and the docs need updating.
- Run `ruff check .` and `pytest -q` before every commit.
- **One commit per phase**, with a message explaining the decisions, not the diff.
  Existing history: `8fe169c` Phase 0, `6a06800` Phase 1, Phase 2, Phase 3.
- Local commits only. Nothing has been pushed anywhere; don't push without asking.
- Honesty over polish. Where something does not work, say so in the docs — the threat
  model's residual-risk section and this file's caveat on Phase 2 numbers are the pattern.

## Open questions carried forward (also in `docs/SPEC.md` §9)

1. What is θ, the monotonicity influence threshold, in practice? (default 0.15, unswept)
2. Does span-level ablation defeat redundant-encoding attacks, or only raise cost? It is now
   also the only route to attributing a field entangled with the transfer intent.
3. **Can the consequential-action gate be attacked into classifying a payment as
   non-consequential? Probably. It is a single point of bypass and must be tested.**
4. Real cost per consequential action against a real model — is 6.9 calls affordable?
5. Placeholder vs delete ablation: currently indistinguishable (f1 1.000 both). Needs a
   harder case set to separate them.
6. **`invariant` does not separate benign redundancy from adversarial redundancy.** Class-
   level ablation would; it is untested and is the most likely home for an ADV-5 evasion.
7. Does per-argument confidence carry policy weight that action-level confidence does not?
   The 0.60 action-level floor fires on a legitimate action split evenly between two trusted
   classes, which looks like a false-positive generator waiting for a real workload.
8. Sentence-level ablations are measured but do not feed `per_argument` or
   `argument_status`, which come from segment-level results only. Folding them in may
   improve accuracy or just add variance — a Phase 4 measurement.
