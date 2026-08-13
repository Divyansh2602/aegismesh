# AegisMesh — Session Handoff

**Written:** 2026-08-06 · **Updated:** 2026-08-12 · **Phase 5 complete**
**Repo:** `C:\Users\Divyansh Gupta\Documents\everything`

---

## Read these first

**Picking this up in a new session? Read *this file* end to end before anything else.** It is
the only document that carries what the code cannot tell you: why each decision went the way
it did, which limitations are deliberate, what is stale, and what to build next. The others
describe the system; this one describes the *project*.

1. **This file** — status, the eleven design decisions, the product target Phases 5–8 build
   toward, and the conventions that must not regress
2. [`README.md`](README.md) — the pitch and the honest novelty positioning
3. [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) — adversaries, controls, twelve residual
   risks, OWASP + EU AI Act mapping
4. [`docs/SPEC.md`](docs/SPEC.md) — the Action Warrant format, the maths, and §9's open
   questions with their Phase 4 answers

Then run the verification command below before changing anything, so you know whether you are
debugging your own change or something that was already broken.

## Verify the state in one command

```bash
pip install -e ".[dev]" && pytest -q && ruff check .   && python demo/phase1_demo.py && python demo/phase2_eval.py   && python demo/phase3_demo.py && python demo/phase4_attack.py   && python tools/verify_warrant.py        results/phase3_warrant.json results/phase3_receipt.json results/phase3_trust_anchors.json
```

Expected: **692 tests pass and 1 skips, ruff clean, all five demos exit 0, and the
standalone verifier reports 6/6 checks passed.** Everything above runs offline — no API key,
no cost. If that holds, nothing has rotted.

The API is exercised by `tests/test_api.py` through an in-process ASGI transport, so it is
covered by the command above. To drive it over a real socket:

```bash
AEGIS_API_LOG_DATABASE=log.sqlite3 uvicorn aegis.api.app:app --port 8000
```

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
| 5a — Public API, endpoints | **Done** | `aegis/api/`, `aegis/log/storage.py`, `tests/test_api.py`, `tests/test_log_storage.py` |
| 5b — Streaming & abuse controls | **Done** | SSE at `/v1/runs/{id}/events`, `AblationObserver` on the engine, `aegis/api/limits.py`, `tests/test_api_streaming.py` |
| 6a — CORS, attack lab, replay | **Done** | `aegis/api/attacks.py`, `Run.evidence`, CORS, `POST /v1/runs/{id}/replay`, `tests/test_api_attacks.py` |
| 6b — Console, all six screens | **Done** | `web/` — Next 16 + TS + Tailwind v4. Runner, stepper, live counterfactuals, three-state evidence, verdict, context, attack lab, auditor view, scored case grid |
| 7 — Ship it | **Built, not deployed** | `.github/workflows/ci.yml`, `Dockerfile`, `render.yaml`, incremental Merkle tree, error handler. The deploy itself needs Divyansh's accounts |
| 8 — Article 12, paper, patent, standards | Pending | — |

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
mean model calls per consequential action  7.7   (worst case 13)
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
                              plus AblationObserver: one event per measurement, hashes only
                client.py     InProcessMockClient / HttpModelClient
  audit/        replay.py     re-runs a warrant's attribution against a disclosed trace
  api/          app.py        sessions, runs, SSE, shared log, auditor artifact downloads
                runner.py     the pipeline driven once, every stage recorded as an event
                scenarios.py  presets = the labelled case set; visitor runs stay unlabelled
                session.py    per-visitor issuer key, policy, PEP, witness; shared log
                runs.py       Run, RunEvent, per-subscriber wake-up flags, bounded RunStore
                limits.py     named controls; every refusal says which one refused
                config.py     every bound, with the reasoning at the field
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
                storage.py    durable backing; SQLite, insert-only, schema-enforced
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

## The product target — stated by Divyansh, 2026-08-06

> "I want a full frontend and backend, everything working. An interviewer or any person
> using GitHub should be able to fully use the functionality, and it should be interactive
> and responsive and legitimate."

Not a screenshot tour and not a canned walkthrough. Someone lands on a URL, drives the real
pipeline with their own input, attacks it, and leaves convinced. **Phases 5–7 exist to
deliver that**; Phase 8 is the research tail.

Read "legitimate" as the binding constraint. Every number on that site must come from
`aegis` executing, every signature must verify, every proof must check. The moment any
screen renders a plausible-looking mock, the site is arguing against the thesis of the
project it is demonstrating.

### The single most convincing thing this can offer

**Artifacts downloaded from the live site must verify offline on the visitor's own laptop.**
A recruiter downloads `warrant.json`, `receipt.json` and `trust_anchors.json`, runs
`python tools/verify_warrant.py` locally with no network and no shared secret, and gets 6/6.
That is the entire third-party-verifiability claim demonstrated rather than asserted, by a
stranger who trusts nobody involved. Build toward it — it is the thing nothing else in this
space can show.

### Two earlier assessments that this target reverses

Both were recorded in this file on the same day under a narrower target. Stated plainly so
the next session does not follow the stale advice:

1. **"Drop Next.js for server-rendered HTML" is withdrawn.** That was correct for a
   click-through demo with no interactivity. The target now *is* interactivity — bring your
   own injection, watch ablations stream, inspect evidence, re-run attacks — so a real
   frontend framework is justified on technical grounds rather than résumé ones.
2. **"Persistence does not block a demo" is withdrawn for the log specifically.** A
   transparency log's whole value is being append-only *over time*. A log that resets when
   the host sleeps demonstrates nothing, and a shared log that visibly grows across visitors
   — with a consistency proof between two visits — is the most compelling artifact
   available. `TransparencyLog` needs durable storage before launch. The replay cache and
   trace store can stay in memory.

   **Done in Phase 5a** rather than deferred to Phase 7, because the log-access layer would
   otherwise have been written twice — once against an in-memory tree and again against a
   database — and because it is the one property a returning visitor can test personally.

---

## Phase 5a — the public API, as built

**Definition of done, met:** the Phase 3 pipeline is drivable end to end over HTTP by
something that is not Python, a visitor can put their own document in front of the agent,
and the three files the API hands out verify offline under `tools/verify_warrant.py`.

Verified over a real socket, not only through the test client: `uvicorn` on a SQLite-backed
log, a custom injection posted by `curl`, the files downloaded and checked by the standalone
verifier — **6/6**. Then the process was killed and restarted against the same database: same
tree size, byte-identical root, and a consistency proof bridging the pre-restart head to the
post-restart one verified.

### The surface

```
POST /v1/sessions                             your own issuer key, policy, PEP, witness
POST /v1/runs                                 preset name, or custom + your own document
GET  /v1/runs/{id}                            status and the ordered event log
GET  /v1/runs/{id}/events                     SSE; resumable by Last-Event-ID or ?after=
GET  /v1/runs/{id}/{context|proposal|attribution|warrant|receipt|decision}
GET  /v1/runs/{id}/artifacts                  the three auditor files, pinned as one snapshot
GET  /v1/runs/{id}/artifacts/{name}.json      one file, as a download
GET  /v1/log · /v1/log/consistency?first=N · /v1/log/entries/{i}      no session needed
GET  /v1/witness                              what your witness has accepted
GET  /v1/scenarios                            the catalogue, and what produced its numbers
```

### Decisions worth defending

- **The preset catalogue *is* `evaluation/cases.build_cases()`.** Authoring a second set of
  scenarios for presentation would create a second definition of the demo, free to drift
  from the one the harness scores and the tests protect. The thing on the website is the
  thing the numbers were measured on.
- **Visitor-authored runs are marked `labelled: false`, permanently.** We know what our own
  cases contain by construction; we have no ground truth for a string a stranger pasted.
  Calling it "poisoned" because it looks like an injection would put a fabricated label
  beside measured ones, which is the failure mode this project is an argument against.
  Nothing unlabelled may ever enter a scored metric.
- **The injection slot is the conduit tool's document, not an arbitrary message.** That is
  where control C-19 says trust does not follow tool integrity — a pinned, well-behaved
  reader relaying a supplier's PDF. Letting a visitor write it is letting them attack the
  design at the seam it claims to hold, rather than at a seam we invented for the demo.
- **Sessions travel in `X-Aegis-Session`, never a cookie.** Nothing is attached to a request
  automatically, so the service has no CSRF surface rather than a defended one.
- **Per-session issuer keys are generated, not derived from the session id.** A key
  reconstructible from a header is a private key anyone holding the header has — harmless
  for demo warrants, and exactly the habit this project exists to argue against.
- **The auditor bundle is pinned on first request.** For an offline verifier to reach 6/6,
  the receipt's tree size must equal the size the witness accepted. The shared log grows
  while a visitor reads the page, so a receipt fetched at one moment and anchors fetched at
  another describe different trees and fail a check that is doing its job. The bundle is
  built once under the log lock and cached; every later request returns identical bytes.
- **Stages are absent when they did not run.** A missing stage is a 409 that says so, never
  an empty object shaped like a real one. Same rule the console inherits: never render a mock.
- **The 4 000-character cap on submitted text is in 5a, not 5b.** It is not really a control
  so much as the absence of an obvious hole — attribution is O(segments) model calls, so
  unbounded submitted text is threat T12 with no attacker skill required. The 413 names T12
  in its body. The controls proper — per-IP limits, session budgets, C-18 surfaced in the UI
  — are still 5b.

### Durable transparency log

`aegis/log/storage.py`. `TransparencyLog` takes an optional `LogStorage`; in-memory is still
the default, so every demo and test is unchanged. SQLite keeps the RFC 6962 implementation
readable, which was the point of hand-writing it, and `idx` is the primary key with plain
`INSERT` only — a second writer at the same index gets an `IntegrityError` from the database,
so append-only is enforced by the schema rather than by convention. The durable write happens
*before* the in-memory tree advances, because a log that counts an entry it failed to persist
comes back shorter than the roots it already signed.

**Stated honestly, and tested as such:** persistence detects corruption, not tampering.
Whoever can write the database can rewrite an entry and its stored leaf together, and no
check inside the storage layer can tell. `test_a_rewritten_row_with_a_matching_leaf_loads_cleanly`
documents exactly that, and the reason it does not matter: the root changes, and the witness
in another trust domain is the party that notices.

### One bug worth remembering

`TransparencyLog` defines `__len__`, so an **empty log is falsy**. `app.state.log = log or
_build_log(config)` therefore threw away the injected durable log and served an in-memory one
— but only when the log was empty, which is to say only on a cold start, which is to say only
on the exact path durability exists for. It passed every test that appended first.
`test_an_empty_injected_log_is_not_replaced` is the regression. The general form: `or`-defaulting
is safe for `None` and wrong for anything with a length.

## Phase 5b — streaming and the abuse controls, as built

**Definition of done, met:** a subscriber watches ablations arrive one at a time, and every
refusal names the control that refused it.

### The engine grew one hook

`AttributionEngine(observer=...)` — an `AblationObserver` called once per completed
measurement with an `AblationEvent`. The only library change Phase 5 required.

- **Called at every `_measure` site, including sentence-level ones whose results are then
  discarded below the noise floor.** A consumer counting events against `model_calls` would
  otherwise come up short with no way to know why: a counterfactual that was tested and found
  uninteresting still happened. `test_the_ablation_events_reconcile_with_the_reported_cost`
  pins the two together.
- **Synchronous, and exceptions are not caught.** Awaitable would let a slow subscriber stall
  the attribution it is watching. Swallowing would leave an attribution running unobserved
  while reporting a total nobody could reconcile with what they saw.
- **Hashes, never text** — the same rule as `Contributor`. A progress feed must not become
  the disclosure channel; `test_ablation_events_carry_hashes_and_never_text` uses a canary.
- **`comparable` rides on every event.** `invariant` and `unknown` both present as zero
  influence, and a consumer forced to tell them apart from the numbers would get it wrong.
  That is design decision 6 arriving on the wire.

### The stream

`GET /v1/runs/{id}/events`, `text/event-stream`. Resumable by `Last-Event-ID` (which
`EventSource` sends automatically on reconnect) or `?after=`; the run retains its event log,
so a reconnect is a replay rather than a gap. A malformed `Last-Event-ID` replays everything
rather than 400-ing — it arrives from an automatic reconnect, where there is nobody to show
an error to, and replaying too much is recoverable while skipping is not.

- **One wake-up flag per subscriber, not one shared `Event`.** A shared flag must be cleared
  before waiting, and whichever consumer clears it can swallow a notification another had not
  yet seen. Two people watching one run is not an edge case; it is a second browser tab.
- **The ordering that makes it correct:** subscribe, then drain, then check status. The
  waiter is registered before the first drain, so an event emitted while we are yielding
  cannot be missed; and status is only consulted after a full drain, so a subscriber can
  never see `complete` with events outstanding. `run.emit("end", ...)` happens in a `finally`,
  so a failed run still wakes and closes its streams.
- **Heartbeat comment frames** every 15s, and `X-Accel-Buffering: no` — nginx buffers proxied
  responses by default, which turns a live stream into one delivery at the end.

**What could not be demonstrated, and why.** Against the bundled in-process mock an entire
attribution finishes in microseconds, so every frame of a real run arrives in the same
millisecond: a wall-clock trace proves the stream *delivers*, not that it is incremental
rather than buffered-then-flushed. That property is instead asserted structurally, by driving
`_event_stream` directly and holding the emitting side still between pulls
(`TestTheStreamIsIncrementalRatherThanBuffered`). It becomes visible on its own the moment a
slower model is behind it — which is open question 9's territory, not this phase's.

### The controls, and why each one exists

`aegis/api/limits.py`. Every refusal carries the control's id, its name, where it comes from,
and the T12 note — because a limit that names itself demonstrates the threat model, while a
bare 429 is a workaround for it.

| id | what it bounds | why it is not covered by the others |
| --- | --- | --- |
| `C-18` | model calls per attribution | the design's own control, already in the engine |
| `C-18/session` | model calls per visitor | C-18 bounds each run; nothing bounded the number of runs |
| `API-RATE` | arrivals per client per minute | bounds *when*, where the budgets bound *how much* |
| `API-CONC` | attributions running at once | the totals bound cumulative cost; this bounds instantaneous load, which is what actually stalls the box |
| `API-CONTEXT` | submitted context length | bounds what the engine is asked to ablate |
| `API-SIZE` | request body bytes | bounds what the process ingests; a body under 64KB can still be a context costing hundreds of calls |
| `API-STREAMS` | live SSE connections per session | connections are the other exhaustible resource |

- **The session budget is checked at admission, so overshoot is bounded by one run's C-18 —
  stated rather than papered over.** Aborting an attribution halfway would mean issuing a
  warrant over partial evidence, which is worse than a small overshoot. Confirmed live: a
  session with a budget of 5 reported "spent 8 model calls of 5" and refused the next run.
- **The limiter is itself keyed on attacker-controlled input**, so the client table is capped
  and evicted oldest-first. A rate limiter that can be made to exhaust the host has not
  limited anything.
- **A rejected arrival does not advance the window.** Recording rejected attempts would let a
  client hammering the endpoint extend its own penalty indefinitely and never recover.
- **`X-Forwarded-For` is ignored unless `trust_forwarded_for` is set.** Honouring it
  unconditionally lets any caller pick their own rate-limit bucket by sending a header, which
  is worse than having no limiter because it looks like one. **Phase 7 must set this** if the
  service ends up behind a proxy, or every visitor will share one bucket.
- **Check order is arrival rate, then session budget, then scenario parsing.** Parsing first
  would let a client over its limit still drive the classifier.
- **`session_model_call_budget` bounds memory as well as cost**, which is the less obvious
  half: each ablation appends one event to its run, so retained events are
  `max_sessions × session_model_call_budget` — 200 × 1500 at current defaults. Raising either
  without doing that multiplication is how a service that survives an attacker falls over
  under ordinary popularity.

### Still true, and still binding

- **Surrogate only, labelled.** No real-model path in the public API: it needs a key, costs
  money per visitor, and would make the site abusable as a free LLM proxy. Every response
  that carries numbers already carries `runner.MODEL_LABEL`; keep it that way.
- **Read-only by construction.** Nothing a visitor submits may change policy, keys, or
  another session's state.
- **No submitted text in the shared log.** Warrants carry excerpt hashes, not excerpts, so
  this holds by construction — and `test_the_shared_log_never_carries_submitted_text` asserts
  it against a canary rather than trusting the design note.

---

## Phase 6a — what the console needs that Phase 5 did not build

**Definition of done, met:** a browser on another origin can reach the API, drive the four
Phase 3 attack scenes, and ask an auditor to re-measure a warrant's own numbers.

Written because "Phase 6 is a frontend" turned out to be false. Three of the six screens
depended on backend that did not exist, and building the console first would have meant
building it against endpoints invented to suit it.

| Built | Why it was not optional |
| --- | --- |
| CORS, allowlisted, credentials off | There was none. Every screen was unreachable from a browser — not a styling problem, a total blocker |
| `aegis/api/attacks.py` | Screen 5's scenes lived only in `demo/phase3_demo.py`. The attack lab is backend work |
| `POST /v1/runs/{id}/replay` | `audit/replay.py` existed since Phase 4 with nothing serving it. Screen 6 needs the verdict |
| `Run.evidence` | Attacks re-issue and replay re-measures; both need the live trace and `AttributionResult`, not the serialized stage |

### Decisions worth defending

- **`fork_log` never touches the shared log, and the ordering is a cost decision.** Every
  visitor's receipt is checked against a root derived from the shared log, so genuinely
  forking it would invalidate proofs already handed to people who are not attacking
  anything. The demo builds a shadow history as long as the real one; that is O(n) appends
  at O(n) each. Instead a fresh witness accepts a *short* doctored history first and is
  then shown the real log's head, which cannot extend it. Same `ForkDetected`, same
  conclusion — two authentically signed heads under one key — at O(n) instead of O(n²).
- **The attack lab is bounded by the same controls as a run.** Attacks and replays pass the
  arrival limiter, and replay also passes the session budget and the concurrency semaphore.
  Replay is a *second* full attribution, so unbudgeted it would be the cheapest denial of
  service on the surface: unlimited model calls under a different route name. Its calls are
  counted by wrapping the client, in a `finally`, so a failure halfway still bills.
- **The client is wrapped rather than the engine injected.** `replay_attribution` rebuilds
  its engine from the warrant's own `replay_ref`; letting the API hand in a pre-built engine
  would replay under the API's settings while reporting a verdict about the issuer's — the
  exact failure `audit/replay.py` refuses to commit when the commitment is incomplete.
- **CORS is an allowlist even though a wildcard is defensible today.** Sessions travel in a
  header, so nothing is attached automatically and a wildcard would add no server-side
  exposure now. The reason it is still not the default: that safety rests on a property one
  commit away from changing. The day anyone adds a cookie, a wildcard becomes a real hole
  and an allowlist stays correct.
- **CORS sits outside the size middleware.** A preflight carries no body and must not be
  size-checked, and a 413 returned without CORS headers is an opaque network error in the
  console — turning the design's most deliberate response, the refusal that names its own
  control, into a browser-level failure with no body. `test_a_refused_request_is_still_readable_by_the_browser`
  pins the ordering.

### The bug worth remembering, and it is design decision 6 from the attacker's side

`tamper_attribution` picks a field and rewrites its causation to `P0 1.0000` — the operator
blaming the human. The first implementation picked whichever attributed field sorted first.
On the poisoned scenario that is **`amount`**, which the human genuinely set and which
already read `P0 1.0000`. The attack rewrote a value to itself: the bytes never changed, the
signature verified correctly, and the endpoint reported a successful defence that had not
happened. `failed_steps` came back `[6, 10]` with step 3 passing, which is what exposed it.

The general form is the project's own central finding pointed inward: *one action is
legitimate in one field and hijacked in another*, so "the attributed field" is not a
well-defined thing to whitewash. Selection now prefers a field the measurement blamed on
untrusted content and skips any field already equal to the target, and
`test_the_tampered_field_is_one_the_measurement_actually_blamed_elsewhere` pins it.

### `EventSource` is unusable here — the console must use `fetch`

`GET /v1/runs/{id}/events` requires `X-Aegis-Session`, and the browser's `EventSource` API
cannot send custom headers. The Phase 5b note that `EventSource` supplies `Last-Event-ID`
automatically is accurate and unreachable. The console consumes the stream with `fetch` +
`ReadableStream` and resumes with `?after=`, which the endpoint already supports. No backend
change — but it decides how the frontend is written, so it is recorded rather than
rediscovered.

---

## Phase 6 — the console

**Goal:** the frontend Divyansh described — full, interactive, responsive, legitimate.

**Definition of done:** a non-technical interviewer reaches "the payment was refused, and
here is which sentence caused it" without reading JSON or asking a question. A technical one
reaches "I attacked it myself, two of my attacks worked, and it told me so."

### Screens

1. **The scenario runner.** Pick a preset (poisoned invoice, clean payment, an AgentDojo
   case) *or write your own context*. Bring-your-own-injection is the feature that makes this
   a product rather than a slideshow.
2. **The pipeline, live.** Context coloured by provenance class P0–P4 with the classification
   reason on hover; ablations streaming in; the action assembling.
3. **The evidence panel.** Per-argument attribution where `attributed` / `invariant` /
   `unknown` are **three visually distinct states, never one number**. Flattening them is
   design decision 6, and undoing it in the UI would undo the project's sharpest finding.
   Show `per_argument_redundancy` beside it.
4. **The decision.** The PEP's verdict, the rules that fired, and the warrant — with the
   issuer's own decision shown as a *claim*, visibly not the authority.
5. **The attack lab.** All eight scenes as buttons, plus custom injections. **The two that
   succeed are the point**; render them as prominently as the ones that fail.
6. **The auditor view.** Merkle tree visual, inclusion proof, witness state, the replay
   verdict with its reason — and the download button for the three artifacts.

### Stack

Next.js App Router + TypeScript + Tailwind + shadcn/ui. Responsive is a stated requirement,
so mobile is a test case rather than an afterthought. Frontend on Vercel, backend container
on Railway or Fly.

### What exists as of 2026-08-13

**Directory is `web/`, not `console/`.** npm refuses a package named `console` — it is a
Node core module name — and `create-next-app` names the package after the directory. The
docs still call it the console.

Built and **verified in a real browser against a live API**, not asserted: pick a scenario,
run it, watch counterfactuals stream in one at a time, read per-argument attribution, see
the payment API refuse. Shared log observed growing 0 → 1. Screens 1, 2, 3 and the decision
half of 4 are up; the attack lab and the auditor view are not.

- `web/lib/api.ts` — typed client. The SSE reader splits on blank lines rather than parsing
  line-by-line, because a chunk boundary can land mid-frame and a parser that assumes whole
  events per read drops data under exactly the conditions streaming exists for.
- `web/components/EvidencePanel.tsx` — **the one that carries design decision 6.** Only
  `attributed` gets a bar. `invariant` is a bordered panel saying the value is redundantly
  determined; `unknown` is hatched with "no comparable run exists". Three forms, not three
  shades — a bar renders the last two identically, which is the flattening that made an
  earlier version of this system refuse a legitimate payment.
- `web/components/Stepper.tsx` — the six pipeline stages advancing live. This is the piece
  that makes the system legible to somebody who will never read the JSON: the panels are the
  evidence, this is the sentence the evidence is arranged into. A stage is `done` because its
  own event arrived, never because a later one did, so a halted run leaves the rest visibly
  unreached instead of quietly filled in.
- `web/components/Reading.tsx` — the measurement in one plain sentence ("human mandate set
  amount · untrusted external set destination_account"), every clause **derived from the
  per-argument distribution**, never written in advance. Prose is the easiest place on the
  page to smuggle in a claim nobody measured, so it is generated from the same data the bars
  are.

### The visual direction, and why it changed

The first pass was a dark theme with oversized Bebas Neue caps, a neon accent, film grain, a
custom cursor and a magnetic button. Divyansh's verdict was that it read as a vibe-coded
site, and he was right: that combination *is* the generic AI-landing-page signature, and on a
project whose entire argument is "do not trust things that merely look convincing" it works
against the thesis.

Rebuilt as an instrument rather than a landing page. **Warm paper (`#fbfaf8`), ink, one deep
blue accent, print-derived provenance colours** muted enough to sit next to body text at
11px. Source Serif 4 for display at restrained sizes — authority from the face and the
spacing, not from setting it 9rem tall — Inter for UI, JetBrains Mono with `tnum` for hashes
so columns of numbers line up and can be compared. Hierarchy comes from small-caps labels and
hairline rules. The cursor, the grain and the magnetic button are **deleted**; the only motion
left is a short opacity/transform rise on scroll and a 220ms row-in on streamed rows, both
compositor-only and both disabled under `prefers-reduced-motion`.

Enterprise details that were missing and now are not: sticky top bar carrying live log size
and API reachability, copy-to-clipboard on every hash and warrant id (an auditor's whole job
is comparing one against another, so truncating without offering the full value looks precise
while being useless), a skip link, `aria-live` narration of run progress, `role="log"` on the
stream, and correct pluralisation.

**Mobile is verified**, by measurement rather than by screenshot. The automation tooling's
window resize silently does not apply — it reports success while `window.innerWidth` stays at
the desktop value, which is why an earlier check was recorded as inconclusive. Instead the
page shells are forced to 390px and every element measured for overflow: **zero offenders,
no document overflow**. That is the stricter test, because viewport media queries stay at
desktop, so the two-column grids and three-column tables get crushed into phone width rather
than stacking as they would on a real phone.

**Tailwind resolves class names statically**, so a constructed `text-${tone}` never gets
generated. Verdict and status colours are inline styles off the CSS custom properties.

### The last three blocks, and the endpoint one of them needed

**`POST /v1/evaluation`** scores the whole labelled case set in a single request and returns
every case beside its outcome. It calls `run_evaluation` — the same function
`demo/phase2_eval.py` calls — so the grid on the site and `results/phase2_evaluation.json`
cannot drift apart. Verified live: precision 1.000, recall 1.000, f1 1.000, localization
1.000, mean 6.86 calls, 48 spent across seven cases.

**Why an endpoint rather than seven runs from the browser.** The arrival limiter allows six
runs a minute, so a client looping over seven scenarios is refused on the last one — the
control working correctly and ruining the demo. One arrival, one slot, cost billed to the
session. It has its own tighter limit (`evaluations_per_minute = 2`) because one call is
seven attributions: rate limits bound *when*, and this is the endpoint where a single
permitted arrival buys the most work.

**Why the grid matters more than any single run.** A detector that flags everything scores
perfectly on the four poisoned cases and is worthless. The three clean rows are what make
the poisoned ones mean anything, so they are tinted as a group and never hidden behind a
summary number. This is the block that turns the site from a demo into evidence.

- `web/components/AttackLab.tsx` — the four Phase 3 attacks as buttons against the run you
  just produced. `defended` is rendered as a **measurement**, and an attack that wins is
  styled as prominently as one that loses; a panel that could only report success would be
  an advertisement.
- `web/components/AuditorView.tsx` — the three artifact downloads with the verifier command,
  the witness state, the inclusion proof, and replay. Downloads go through `fetch` + a blob
  rather than an `<a download href>`, because the endpoint needs the session header and a
  plain anchor cannot send one — the same constraint that rules out `EventSource`.
- Replay verified live from the browser: **consistent, 13 checks, 0 contradictions**.

**One UX defect found by driving it.** The run button was enabled during the round trip that
mints the session, and `run()` returns silently when `session` is null — so an early click
did nothing and said nothing. It now shows "Connecting" and is disabled until the session
exists. Worth remembering as a shape: a guard clause that protects correctness while leaving
the control live is a control that lies about being ready.

**Sessions are minted once per page load**, not per action, so the scored sweep, the run, the
attacks and the audit all bill against one budget. A visitor who could reset their budget by
re-rendering a component would not be bounded by it.

---

## Phase 7 — what is built, and the one step left

**Everything except the deploy itself is done and verified.** The remaining step needs
Divyansh's Render and Vercel accounts, which is why it stops here rather than being half-done.

| Built | Verified how |
| --- | --- |
| `.github/workflows/ci.yml` | ruff, pytest, all four demos and the standalone verifier, on Python 3.11 and 3.13, plus console lint and build. **Not yet observed green on GitHub** — first push runs it |
| `Dockerfile` + `.dockerignore` | Image built, container run, `whoami` → `aegis` (non-root), poisoned run returned REJECT, and the durable log **survived `docker restart` with a byte-identical root** |
| `render.yaml` | Blueprint with the disk, health check, generated log seed, and `trust_forwarded_for` |
| `web/.env.example` | The one variable the console needs |
| Unhandled-error handler | Returns an incident id, never a traceback; control refusals still name their control. Both pinned by tests |

### Decisions worth defending

- **CI runs the demos and the verifier, not only `pytest`.** A green check that proved the
  unit tests pass would say nothing about the claim this repository makes. The last step is
  the command an auditor would run, on a machine that has never seen the project.
- **CI deliberately does *not* assert `results/` is unchanged after the demos run.** Warrants
  carry a fresh UUID and current timestamps, so those files differ on every execution by
  design. That check would fail on every commit and be switched off within a week, which is
  worse than not having it. It was written, caught, and removed before it landed.
- **The container runs as a non-root user with one writable path.** The API executes
  attacker-supplied *text*, never attacker-supplied code — but running as root because
  nothing is known to escape is the reasoning this project exists to criticize.
- **`CMD` is JSON form wrapping `sh -c ... exec`.** Bare shell form leaves `sh` as PID 1,
  which swallows SIGTERM: the container gets killed rather than shut down and uvicorn never
  closes its open SSE streams. `exec` makes uvicorn PID 1 while still expanding `$PORT`.
- **The error handler cannot swallow the refusals that are the point.** `HTTPException` —
  including every control refusal from `limits.refuse` — is handled by Starlette *before* it,
  so the responses that name the control keep their bodies. The handler exists only for
  failures nobody designed. `test_a_control_refusal_still_names_its_control` pins that.

### Render specifically, and the cost that is not optional

**Free instances cannot attach a persistent disk** (confirmed against Render's current terms,
2026-08-13) and they sleep when idle. On a free plan the transparency log therefore resets on
every wake, which does not merely lose data — it destroys the one property a returning visitor
can test personally. Disks require a paid instance plus $0.25/GB/month.

If the disk is dropped, **delete `AEGIS_API_LOG_DATABASE` with it**. Setting the path with no
disk behind it is the worst case: `/health` reports `log_durable: true` while the history
silently restarts.

`AEGIS_API_LOG_SEED` uses Render's `generateValue`, which mints it once and keeps it stable —
secret *and* unchanging, which is the actual requirement, because a log whose signing key
changes is a log whose entire signed history stops verifying. The service logs a warning if a
durable log is running on the published default.

### Keeping it awake, and what that workflow is really for

`.github/workflows/keep-warm.yml` pings `/health` every ten minutes. Render's free instances
spin down after **15 minutes** idle and take 30–60s to wake (confirmed 2026-08-13), so ten
minutes sits comfortably inside that window. **Paid instances do not sleep**, so on the
`starter` plan the Blueprint specifies, this is not needed for warmth.

It still earns its place, because of the second thing it does: every ping records the log's
tree size and compares it to the previous one, and **fails if the log shrank**. An
append-only log cannot get shorter, and this catches that from *outside* the operator's own
infrastructure — which is exactly what a free instance with no persistent disk will trip.

Stated precisely so it is not oversold: this is a **weak external witness**. It compares
counts, not roots, so it cannot detect a fork or a rewrite that preserves length. It is not a
substitute for `aegis/log/witness.py`, and nothing in the trust argument should lean on it.

Two GitHub caveats worth knowing rather than discovering: scheduled workflows are
**best-effort** and are frequently delayed under load, and GitHub disables schedules on
repositories with no activity for 60 days. If the service must never sleep, the paid instance
is the answer and this workflow is the monitor. It is guarded by
`if: vars.AEGIS_API_URL != ''` so it skips cleanly before the first deploy — a monitor that
fails every ten minutes until you deploy trains you to ignore its notifications, which is
worse than having none.

### The remaining step

1. Render → New Blueprint → point at this repo. Confirm the paid instance and the disk.
2. Vercel → import, root directory `web`, set `NEXT_PUBLIC_AEGIS_API` to the Render URL.
3. Set `AEGIS_API_CORS_ORIGINS` on Render to the Vercel origin. **Without this every screen
   is blank** — the console talks to the API from the browser and fails at the preflight.
4. Set the GitHub repository variable `AEGIS_API_URL` to the Render URL, which enables the
   keep-warm workflow (Settings → Secrets and variables → Actions → Variables).
5. Put the URL at the top of the README, and flip the repo public.

---

## Phase 7 — the original plan

**Definition of done:** the URL is in the README, it survives a stranger, and it stays up.

1. Dockerfile for the API; Vercel project for the console.
2. **CI**: `ruff` + `pytest` on every push. The repo has none, and a public project whose
   selling point is verifiability needs a green check.
3. ~~Durable storage for the transparency log.~~ **Landed in Phase 5a** — `aegis/log/storage.py`.
   What remains here is deployment-side: set `AEGIS_API_LOG_DATABASE` to a path on a volume
   that survives a container restart, and set `AEGIS_API_LOG_SEED` from a secrets manager
   rather than the published default — a log whose key changes is a log whose entire signed
   history stops verifying.
4. Health checks, structured logs, an error page that does not leak stack traces.
   `GET /health` exists and reports tree size, durability and the model label.
5. Custom domain, and the demo URL at the top of the README.
6. ~~**The log's append cost is quadratic in its size.**~~ **Fixed 2026-08-13** —
   `aegis/log/incremental.py`. `merkle.py` is untouched and is now the executable
   *specification*; `IncrementalTree` is what runs, and `tests/test_incremental_tree.py`
   asserts they agree on the root for every size 0–130 and on every inclusion and
   consistency proof for every size 1–65 and every index and split point. Keeping both is
   only defensible because a disagreement is a test failure rather than a silent
   divergence — which is a stronger position than having one implementation.

   RFC 6962 splits at the largest power of two, which makes the tree left-complete, so it
   stores as levels where a canonical subtree root is a lookup instead of a walk. Appending
   touches only the right spine. Measured before → after: building 20 000 leaves
   **727 s → 1.58 s (459×)**, a single append at that size **73 ms → 0.083 ms**,
   `signed_tree_head` **19.2 ms → 0.07 ms**. Build is now linear and append is flat across a
   200× size range. The original quadratic measurement is kept below because the reasoning
   is the useful part:

   *(historical)* building n leaves took 22.6 ms at n=100, 1.53 s at n=1 000, 36.7 s at
   n=5 000, 727 s at n=20 000 — 4× the leaves for 19.8× the time. `root()` rehashed the
   whole leaf list and `append` walked the tree three times.
   Measured 2026-08-13, not inferred: building a tree of *n* leaves takes 22.6 ms at
   n=100, 1.53 s at n=1 000, 36.7 s at n=5 000, 727 s at n=20 000 — 4× the leaves for
   19.8× the time, which is n². `root()` rehashes the whole leaf list and `append` walks
   the tree three times (`root()` twice, plus `inclusion_proof`), so **one append at
   n=20 000 costs ~73 ms** and ~365 ms at n=100 000. `signed_tree_head()` on its own stays
   cheap (19 ms at n=20 000).

   **This is not a bug and should not be "fixed" casually.** The Merkle log was
   hand-written so the tamper-evidence claim reduces to functions a reviewer can read, and
   recomputing the root from the leaves is the most readable form of it. What is new is
   that Phase 5a made the log durable and shared, so *n* now grows for the life of the
   deployment instead of resetting. The honest options, in order of preference: cache the
   root and maintain the frontier incrementally (keeps the readable functions as the
   test oracle, which is the point of having them); or accept it and state the tree size
   at which the service is retired. Do not discover this in production — a public site
   whose selling point is the log getting longer has a cost curve pointed the wrong way.

---

## Phase 8 — Article 12, paper, patent, standards

Unchanged in substance, moved back by the three phases above.

- **EU AI Act Article 12 export** — map warrant fields onto the record-keeping obligations,
  and state which obligations it does *not* discharge.
- **Real-model measurement** (open question 9) — the adapter already runs against
  `HttpModelClient`; it needs a key and a budget. Single biggest credibility upgrade to every
  number in `results/`. Run it offline and publish the numbers; do not wire it into the
  public site.
- ~~**Classifier adversarial evaluation** (residual risk 1)~~ **Done 2026-08-13.**
  `aegis/evaluation/classifier_attacks.py`, `demo/phase8_classifier_attack.py`,
  `tests/test_classifier_attacks.py`. Eight attacks, **three succeeded and all three are now
  fixed**; the suite reports 8/8 holding and each attack is the regression test for its fix.
  Eight attacks no longer working is a far smaller claim than the classifier being safe —
  this suite is a floor, not a ceiling, and its own blind spots are what let these sit
  undetected for four phases.

  The strict-substring P0 boundary held against everything aimed at it — authority framing,
  Cyrillic homoglyphs, unknown roles, tool-description drift. What broke was the assumption
  underneath it, and the most serious finding is not a misclassification at all:

  ~~**F1 — content the classifier never sees.**~~ **Fixed, same phase.** `_as_text`
  (classifier) and `message_text` (`attribution/ablation.py`) both kept only content parts
  typed exactly `"text"`. A part typed `input_text` — OpenAI's Responses API shape — was
  never a segment, so **no counterfactual could test it**, because attribution can only
  ablate what classification produced. Worse, reconstruction flattens the list to a string,
  so the unseen part sat in the baseline and was absent from *every* ablated body: each
  counterfactual differed from the baseline by more than the segment under test and the
  missing part's effect was folded silently into the others. The property nothing enforced:
  **the classified text and the text the model receives must be the same text.**

  **The root cause was duplication.** One rule, written twice, in two modules, required to
  agree — and both copies were wrong identically, which is the failure duplication makes
  easy to miss. It now lives once in `aegis/provenance/content.py`, imported by both, and
  `test_the_classified_text_is_the_text_ablation_removes` asserts **identity**, not
  behavioural equality: behavioural equality only proves agreement on cases somebody thought
  to write down. Extraction is now permissive — any part carrying a `text` field counts —
  because over-restricting is visible and under-covering is not. Parts with no text at all
  (images) stay outside what a text classifier can measure; `untyped_part_kinds` names them
  instead of dropping them.

  **F2 — P2 from a name alone.** Tool responses are trusted on `message["name"]`; nothing
  binds one to a `tool_call` that was actually issued. Same class of error as C-19 — pinning
  proves the *tool* is authentic and says nothing about this payload.

  **F3 — first match wins the P0 span.** A document quoting the mandate above the human's
  typing takes P0. Bounded honestly: both copies are byte-identical, so the attacker chooses
  *which copy* is elevated, not *what* — the damage is to provenance's answer, not the trust
  boundary.

  **F2 — fixed, and it was the expensive one.** A tool response now earns P2 only if it
  binds to a call the agent issued *earlier in the same transcript*. Matching prefers
  `tool_call_id`; an id issued for a different tool is refused rather than falling back to
  the name, or the id would be decorative; and issued calls are collected while walking, so a
  result arriving before its call cannot bind.

  The cost is the instructive part. **No scenario in the repository issued a `tool_call`** —
  every transcript jumped from the human straight to results nobody requested, which is not a
  shape a real framework produces. Under the new rule Acme's own ledger correctly stopped
  being trusted. The fixtures were made realistic rather than the rule made weaker, so
  `treasury_messages` now emits the agent's tool-calling turn, and **Phase 2 was
  re-measured**: accuracy unchanged at 1.000 across precision, recall and localization; cost
  6.9 → **7.7** mean model calls, worst case 12 → **13**, because that turn is another
  segment to ablate.

  **Two index bugs surfaced while doing it, and both are the same bug.** Inserting a message
  shifted every hardcoded position: `injected_message_index` in the cases silently dropped
  localization from 1.000 to 0.250, and thirteen `body["messages"][3]` references in the
  attribution tests pointed at the wrong message. Nothing failed loudly in the first case —
  the harness simply compared against a message that had moved. Both are now *found* rather
  than counted (`carrier_index`, `msg()`, `idx()`). Ground truth that is a hand-counted
  offset into a list somebody else edits is ground truth waiting to be wrong.

  **F3 — fixed by declining to guess.** A mandate appearing verbatim more than once in one
  user turn grants P0 to neither copy, and the reason names the count. There is no heuristic
  available: the spans are byte-identical. This is the design's own rule applied to itself —
  *default on any doubt is P3* — and it fails where the action loses authorisation rather
  than gains a forged one.

  **Still not touched:** `unicode_normalisation` held only in the availability direction, and
  normalising to fix it is the same change that would break `homoglyph_mandate`. The two pull
  opposite ways and only one is safe.
- Paper, patent decision (see the licence note — Apache-2.0 §3 already grants users a patent
  licence over claims this code necessarily infringes), standards engagement.

### Watch out for, across all of Phases 5–8

- The Phase 2 case set must keep passing; it is the fast regression signal
- Cost is a headline result, not a footnote — an accurate method nobody can afford does
  not ship
- Report evasions that work. THREAT_MODEL §6 is the format, and it now has twelve entries
- **A console that renders `invariant` and `unknown` the same way undoes design decision 6.**
  The single easiest way to destroy this project's best finding is a progress bar
- **Never render a mock.** If a screen cannot yet be driven by real `aegis` output, ship the
  screen empty with an honest "not built" rather than filled with something plausible. On a
  project about verifiable evidence, a fake screenshot is not a placeholder, it is a
  counterexample
- The public site must state which model produced its numbers. Every caveat in
  `demo/phase4_eval.py`'s closing section applies verbatim to anything the UI displays
- Opening the API to strangers turns attribution cost into threat T12. Use control C-18
  rather than inventing a new limiter, and say so in the UI

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
- **One commit per phase**, with a message explaining the decisions, not the diff. Every
  commit hash in this file's earlier history is stale — the history was rewritten on
  2026-08-06 (see below), so use `git log` rather than any hash quoted in prose.
- **Divyansh is the sole author. Never add a `Co-Authored-By` trailer**, and commit as
  `Divyansh Gupta <divyansh2622005@gmail.com>` — his global git config already sets this, so
  just do not override it. Both were retrofitted across all seven commits with
  `git filter-branch` + force push on 2026-08-06 and verified through the GitHub API. This is
  the convention most likely to regress silently, because tooling defaults tend to add the
  trailer. After any history rewrite, also delete `refs/original/refs/heads/<branch>`:
  filter-branch leaves it behind, it never appears in `git branch`, and it pins the old
  history indefinitely.
- **Remote is `github.com/Divyansh2602/aegismesh`, currently private.** He has asked for it to
  be public and wants to review GitHub's rendering first, so treat flipping it as expected
  rather than as a new decision. Push freely to `main`; ask before any further force push.
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
