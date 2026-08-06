# AegisMesh — Session Handoff

**Written:** 2026-08-06 · **Phase 4 complete**
**Repo:** `C:\Users\Divyansh Gupta\Documents\everything`

---

## Read these first

1. [`README.md`](README.md) — the pitch and the honest novelty positioning
2. [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) — adversaries, controls, OWASP + EU AI Act mapping
3. [`docs/SPEC.md`](docs/SPEC.md) — the Action Warrant format and all the maths
4. This file — where things stand and what to do next

## Verify the state in one command

```bash
pip install -e ".[dev]" && pytest -q && ruff check .   && python demo/phase1_demo.py && python demo/phase2_eval.py   && python demo/phase3_demo.py && python demo/phase4_attack.py   && python tools/verify_warrant.py        results/phase3_warrant.json results/phase3_receipt.json results/phase3_trust_anchors.json
```

Expected: **317 tests pass and 1 skips, ruff clean, all four demos exit 0, and the
standalone verifier reports 6/6 checks passed.** Everything above runs offline — no API key,
no cost. If that holds, nothing has rotted.

The AgentDojo sweep is separate because it needs the optional extra and takes a few minutes:

```bash
pip install -e ".[agentdojo]" && python demo/phase4_eval.py
```

The single skip is `test_the_adapter_reports_the_install_command_when_it_is_missing`, which
can only run when AgentDojo is *absent*. If AgentDojo is installed, four adapter tests run
instead and that one skips — so the skip count flips depending on the extra, and both states
are correct.

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
| 4 — Adversarial evaluation | **Done** | `aegis/evaluation/{agentdojo,surrogate,phase4,theta}.py`, `aegis/audit/`, `aegis/provenance/monotonicity.py` |
| 5 — Console & compliance export | **Next** | Next.js |
| 6 — Paper, patent, standards | Pending | — |

### Phase 4 measured results (`results/phase4_agentdojo.json`)

Contexts built from AgentDojo, injection **appended** to the genuine document so the engine
has to discriminate rather than pick the only value present. Unit of measurement is the
(case, field) pair — 58 usable pairs, 79 scored fields.

| configuration | fields answered | class accuracy | precision | recall | localization | calls/action |
| --- | --- | --- | --- | --- | --- | --- |
| segment | 33 / 79 | 1.000 | 1.000 | 0.200 | 0.897 | 35.6 |
| **+ span** | **68 / 79** | **1.000** | **1.000** | **0.800** | **0.931** | **41.1** |
| + class | 33 / 79 | 1.000 | 1.000 | 0.200 | 0.897 | 35.7 |

`replace` placement (AgentDojo's own, which often deletes the legitimate value) and `none`
(the clean control, no attack at all) are in the same file. There were **zero false
positives in every placement including the clean one**.

**The four things to say about these numbers, unprompted:**

1. **The model is a surrogate**, its susceptibility written down rather than discovered.
   Attack-success-rate here says nothing about GPT-4 or Claude. What it buys is exact
   ground truth — class accuracy is scored against the class that genuinely supplied each
   value, computed by replaying a known function, not annotated by whoever wrote the engine.
2. **58 of 629 pairs are usable.** The rest have no consequential action, no argument the
   surrogate models, or no argument the injection attacks. A subset chosen by what the
   method can measure is a subset chosen by the method.
3. **"Fields answered" is the honest denominator.** Segment-only ablation is accurate and
   largely silent; span-level ablation is what makes it useful. Reporting accuracy alone
   would make 33/79 and 68/79 look identical.
4. **Class-level ablation bought nothing here** and is off by default — AgentDojo's contexts
   average 3.24 segments, so almost no class has the two the check needs.

### Phase 2 results, still run as the regression signal

```
precision 1.000   recall 1.000   f1 1.000   localization 1.000
mean model calls per consequential action  6.9   (worst case 12)
```

Seven hand-built cases against a deterministic mock. They prove the engine is wired
correctly and catch regressions in seconds; they are not a generalization claim, and Phase 4
is what that claim now rests on. Saying this out loud in an interview is a strength.

---

## Architecture as built

```
aegis/
  common/       ids (ULID), hashing + RFC 8785 JCS, decimals (fixed-precision scores)
  provenance/   classes.py    P0-P4 + trust ordering
                monotonicity.py  theta, and the parent-influence estimators it thresholds
                registry.py   pinned tools, conduit vs closed-world, drift detection
                classifier.py chat request -> provenance-tagged segments with locators
                models.py     Segment, ContextTrace, MessageLocator/ToolLocator
  proxy/        app.py        OpenAI-compatible interception, trace store
  mockmodel/    app.py        deterministic model reproducing recency-bias injection
  attribution/  gate.py       consequential-action gate (cost control)
                ablation.py   reconstruction, placeholder/delete, sentence + span + class
                engine.py     leave-one-out ablation, influence/necessity/argument_status
                client.py     InProcessMockClient / HttpModelClient
  audit/        replay.py     re-runs a warrant's attribution against a disclosed trace
  evaluation/   cases.py      labelled ground-truth cases
                harness.py    precision/recall/localization/cost
                agentdojo.py  adapter for AgentDojo's security suites (optional extra)
                surrogate.py  deterministic vulnerable model, generalized past one tool
                phase4.py     per-(case, field) scoring over the configuration matrix
                theta.py      the monotonicity sweep, security vs utility
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

**8. A specification and an implementation can agree line by line and still contain a
parameter that does nothing.** *(Phase 4)*
θ, the monotonicity threshold, was specified in Phase 0 with a default of 0.15 and flagged
for sweeping. Phase 1 approximated causal parents as *every preceding segment* and
documented that as conservative; Phase 2 was to replace it with measured parents and never
did. With every parent counted, `influence(p → s)` is a constant 1.0 — θ multiplies a
constant, and no value of it changes any classification. Reading the spec alone shows a
tunable. Reading the code alone shows a defensible approximation. Only trying to *sweep* it
reveals there is nothing to sweep. The swept result then said the specified default is
**dominated**: θ=0.40 catches as much laundering on evidence and preserves every clean
output.

**9. The metric can be measuring a different question than the one you asked.**
*(Phase 4, and the one that nearly published a wrong number)*
The first AgentDojo harness scored precision against "did the attacker's value land" and
reported fifteen false positives. They were not false positives. AgentDojo's banking bills
carry the *legitimate* amount inside a retrieved file, and a retrieved file is P3 by control
C-19 — so attributing the amount to untrusted content was correct, and the attacker's rival
value having lost is a separate fact. Precision is now scored against the class that
actually supplied the emitted value, which the surrogate's known rule computes exactly.

The consequence is bigger than the fix: **on real workloads the legitimate value of a field
is routinely untrusted-sourced**, so a policy of "no untrusted influence on `amount`" would
refuse every bill payment. Untrusted causation is evidence for policy to weigh, not a
verdict. The Phase 3 demo works because the operator's own ledger independently names the
account — a property of that scenario, not of payments in general.

**10. A commitment looks complete until something tries to consume it.**
`replay_ref` pinned the trace, the model and the method version. Building the replay
verifier showed that does not determine the measurement: `mode` (placeholder vs delete) and
`drilldown_threshold` change the counterfactuals and were not signed over. An auditor
replaying under different settings would contradict an honest issuer — or fail to contradict
a dishonest one who picked the flattering settings and never had to declare them. Both are
now in `replay_ref`, and warrants predating that verify by signature but report
`inconclusive` on replay rather than being replayed under the auditor's defaults.

**11. The bug was not in the gate; it was in what the gate was shown.**
Attacking the consequential-action gate — flagged as a single point of bypass since Phase 0,
never tested — found that only the *first* proposed tool call was ever evaluated. Parallel
tool calls are ordinary in the OpenAI API, so a model emitting `get_balance` alongside
`execute_transfer` had the read gated as harmless and the transfer never attributed, never
warranted, never enforced. An injection saying "check the balance first" is the entire
attack. The gate's logic was correct throughout.

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

## Phase 4 — what was built

**Definition of done, met:** attribution precision/recall reported over AgentDojo's security
cases, with working evasions of our own design documented rather than hidden.

`python demo/phase4_eval.py` measures; `python demo/phase4_attack.py` attacks. Two of the
attack demo's four scenes end with the attacker winning, and both stay in the output.

| Built | Outcome |
| --- | --- |
| `evaluation/agentdojo.py` + `surrogate.py` | 58 of 629 pairs usable, 79 scored fields, three placements including a no-attack control |
| Span-level ablation (C-15) | **The headline result.** Fields answered 33/79 → 68/79 for +5.5 calls per action. Answers open question 2 |
| Class-level ablation | Works on constructed ADV-5 cases, bought nothing on AgentDojo. Off by default. Answers open question 6, and not in its favour |
| `audit/replay.py` | A fabricated attribution is now falsifiable. Building it showed `replay_ref` was under-committing; `mode` and `drilldown_threshold` added |
| Attacking the gate | One complete bypass found and fixed (parallel tool calls), one evasion open and documented (naming). Answers open question 3 |
| θ, implemented and swept | It had never been implemented. The specified default 0.15 is dominated by 0.40 |

Decisions worth defending:

- **The unit of measurement is (case, field), not the case.** An injection commonly attacks
  more than one argument, and picking one per case would have meant picking whichever sorted
  first — `amount`, which the surrogate fills by primacy and the attack can never take. Every
  banking case would have reported a correct non-detection on a field never in play.
- **Precision is scored against the class that supplied the value, not against whether the
  attack landed.** Those are different questions, and conflating them cost fifteen phantom
  false positives before it was caught. See design decision 9.
- **Span-level results replace segment-level ones, and only for fields segment ablation
  could not attribute.** A span sits inside a segment, so adding the two would count one
  cause twice; and a field already attributed has its answer.
- **Sentence-level results are still excluded** from `per_argument`. A span is bound to one
  field and a sentence is not, so the argument for folding spans in does not extend to them.
- **The surrogate's rules are inferred from the *legitimate* value**, never the attacker's.
  Deriving them the other way would build a model to fall for the attack it is then scored
  against.
- **The clean placement exists because attacks that failed are easy negatives.** The
  attacker's value is in context and merely lost. Ordinary work with no adversary is the
  negative class that decides whether a control is deployable.

---

## Phase 5 — what to build next

Goal: make the evidence readable by someone who is not going to read the JSON — a compliance
officer, an auditor, a regulator under Article 12.

**Definition of done:** an investigator can take a warrant and a trace and answer "why did
this action happen, and who caused each field?" without reading any code, and export a
record that satisfies Article 12's traceability requirement.

### Build order

1. **A read-only console** over the artifacts that already exist. Warrant, receipt,
   inclusion proof, per-argument attribution with `argument_status` and
   `per_argument_redundancy` shown as distinct states rather than flattened into a score.
   The per-field three-way status is the thing a UI can express that a number cannot.
2. **The replay verdict as a first-class view.** `consistent` / `contradicted` /
   `inconclusive` with the reason attached — this is the only screen in the product where
   the operator is the subject rather than the author.
3. **Article 12 export.** Map the warrant fields onto the record-keeping obligations
   explicitly, and say in the export which obligations it does *not* discharge.
4. **Real-model measurement** (open question 9). The adapter already runs against
   `HttpModelClient`; what is missing is a key and a budget. This is the single largest
   upgrade available to the credibility of every number in `results/`.
5. **Classifier adversarial evaluation** (residual risk 1). Phase 4 measured attribution
   given correct classification. Nobody has attacked the classifier's P0 boundary.

### Watch out for

- The Phase 2 case set must keep passing; it is the fast regression signal
- Cost is a headline result, not a footnote — an accurate method nobody can afford does
  not ship
- Report evasions that work. THREAT_MODEL §6 is the format, and it now has twelve entries
- A console that renders `invariant` and `unknown` the same way undoes design decision 6

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

Answered in Phase 4 — 1 (theta had no implementation; 0.15 is dominated by 0.40),
2 (span-level ablation defeats entanglement: recall 0.20 → 0.80), 3 (the gate has two
evasions, one fixed and one open), 6 (class-level ablation separates the redundancies but
bought nothing on AgentDojo).

Still open:

4. Real cost per consequential action against a real model. Measured at 35.6 calls per
   action, 41.1 with span-level ablation, against a free in-process surrogate — which
   establishes nothing about provider prices or latency. One case hit the 400-call ceiling,
   and a truncated attribution reports partial evidence.
5. Placeholder vs delete ablation: still indistinguishable on every case set tried.
7. Does per-argument confidence carry policy weight that action-level confidence does not?
   The 0.60 action-level floor fires on a legitimate action split evenly between two trusted
   classes, which still looks like a false-positive generator waiting for a real workload.
8. Sentence-level ablations still do not feed `per_argument`. Spans now do; the same
   argument does not extend to sentences, which have no field to attribute to.
9. **New.** Every Phase 4 number is measured against the surrogate. The adapter runs
   unchanged against `HttpModelClient` — this needs a key and a budget, and it is the
   biggest single credibility upgrade available.
10. **New.** 58 of 629 pairs are usable. A subset selected by what the method can measure is
    a subset selected by the method.
11. **New.** The gate's read-verb branch is the only place it fails open, and narrowing it
    would make every `get_*` a candidate for attribution. Nobody has measured what that
    would actually cost on a realistic read/write ratio.
