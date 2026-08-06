# AegisMesh — Threat Model

**Version:** 0.1 · **Date:** 2026-08-03 · **Status:** Phase 0 deliverable

This document defines what AegisMesh defends, who it defends against, what it explicitly
does *not* defend, and how each control maps to the OWASP Top 10 for Agentic Applications
2026 and to EU AI Act Article 12.

It is written before any implementation deliberately. A control that cannot be traced to a
named adversary and a named asset is decoration.

---

## 1. System under consideration

A **deployed agentic system**: one or more LLM-driven agents that plan, hold memory, call
tools, and act with authority delegated from a human principal, operating across
organizational boundaries (third-party MCP servers, SaaS APIs, partner systems).

### 1.1 Trust boundaries

```
   ┌─ TB1 ──────────────────────────────────────────────────┐
   │  Human principal                                       │
   │      │ mandate (authenticated, scoped)                 │
   │      ▼                                                 │
   │  ┌─ TB2 ────────────────────────────────────────────┐  │
   │  │  Operator's agent runtime                        │  │
   │  │     agent  ⇄  aegis-proxy  ⇄  LLM provider  ─────┼──┼──▶ TB4
   │  │                    │                             │  │
   │  │                    ├─▶ aegis-causa               │  │
   │  │                    ├─▶ aegis-warrant             │  │
   │  │                    └─▶ aegis-log (append-only)   │  │
   │  └──────────────────────────────────────────────────┘  │
   └────────────────────────┬───────────────────────────────┘
                            │ action + warrant
                            ▼
   ┌─ TB3 ── Relying party (different org) ──────────────────┐
   │   aegis-pep  ──▶  payment API / CRM / filesystem        │
   └─────────────────────────────────────────────────────────┘

   TB4 = external content sources: web pages, emails, documents,
         third-party MCP servers, other agents.  UNTRUSTED.
```

- **TB1 → TB2**: the mandate boundary. Everything downstream derives authority from here.
- **TB2 → TB4**: the contamination boundary. Content crossing inward is untrusted and must
  be provenance-tagged.
- **TB2 → TB3**: **the boundary that matters most.** The relying party does not trust the
  operator. This is why warrants must be independently verifiable and why the transparency
  log must be publicly auditable. Systems that only log internally cannot cross this line.

### 1.2 Assets

| ID | Asset | Why it matters |
| --- | --- | --- |
| A1 | Integrity of consequential actions | Money moves, data is deleted, messages are sent |
| A2 | Human mandate authenticity | The root of all delegated authority |
| A3 | Causal attribution truthfulness | A forged attribution is worse than none — it launders an attack |
| A4 | Warrant non-repudiation | Regulatory and legal defensibility |
| A5 | Transparency-log append-only property | Third-party auditability collapses without it |
| A6 | Agent utility | A defense that blocks legitimate work will be turned off |

A6 is an asset, not an afterthought. Every control below is evaluated against it.

---

## 2. Adversary model

| ID | Adversary | Capability | Goal |
| --- | --- | --- | --- |
| **ADV-1** | **Content injector** | Controls text in a document, email, web page, or third-party tool response the agent will read. No system access. | Cause an unauthorized consequential action |
| **ADV-2** | **Malicious tool provider** | Operates an MCP server the agent uses. Controls tool descriptions and responses. | Tool poisoning; confused-deputy escalation |
| **ADV-3** | **Compromised sub-agent** | Full control of one agent in a multi-agent chain | Launder malicious intent as legitimate upstream output |
| **ADV-4** | **Dishonest operator** | Runs the agent and the AegisMesh instance itself | Forge or suppress warrants to escape liability |
| **ADV-5** | **Adaptive attacker** | ADV-1, plus full knowledge of AegisMesh's design and attribution method | Craft input that survives ablation-based attribution |
| **ADV-6** | **Gate-shape attacker** | ADV-1. Influences *how many* calls the agent proposes and in what order, not what tools exist | Hide a consequential call behind a harmless one so it is never measured. **Found and fixed in Phase 4 — §6.12** |
| **ADV-7** | **Naming attacker** | ADV-2. Chooses the names of the operations it exposes | Name a consequential operation so the gate reads it as read-only. **Found in Phase 4, open — §6.11** |

**ADV-4 is the reason this project is architecturally interesting.** Most agent-security
products implicitly trust the operator, which makes their audit logs worthless to a
regulator. Defending against a dishonest operator forces external verifiability: signed
warrants, a public append-only log, and verification performed by the relying party. It is
also why a blockchain is *not* required — see §5.

**ADV-5 is the reason evaluation is mandatory.** Published prompt-injection defenses have
repeatedly fallen to adaptive attacks. Phase 4 attacks our own system and reports what works.

### Out of scope

Not defended, and stated so we do not pretend otherwise:

- Compromise of the host OS, container runtime, or hypervisor
- Theft of the warrant issuer's Ed25519 private key (mitigated operationally: short-lived
  keys, HSM/KMS storage, log-based revocation — not cryptographically prevented)
- The LLM provider itself being adversarial or backdoored
- Attacks on the human principal (phishing the mandate itself)
- Model-level jailbreaks that do not result in a *tool call* — AegisMesh governs actions,
  not speech

---

## 3. Threat catalogue and controls

Notation: **C-n** = control. Provenance classes (`P0`–`P4`) are defined in `SPEC.md` §2.

| # | Threat | Adversary | Control |
| --- | --- | --- | --- |
| T1 | Indirect prompt injection via retrieved content | ADV-1 | **C-1** provenance tagging at ingest; **C-2** per-argument causal attribution; **C-3** policy requiring minimum `P0` causal share for the action class |
| T2 | Tool poisoning via malicious tool description | ADV-2 | **C-4** tool descriptions classed `P3` unless pinned and hash-matched; **C-5** description-hash pinning with drift alerts that downgrade trust until re-pinned |
| T2b | **Trusted conduit relay** — injection arrives inside the payload of a *legitimately pinned* tool | ADV-1, ADV-2 | **C-19** conduit tools (PDF readers, web fetchers, mail, search) are classed `P3` even when pinned. Only closed-world tools returning operator-controlled data earn `P2`. |
| T3 | Confused deputy — upstream sees the operator, not the user | ADV-1, ADV-2 | **C-6** delegation chain carried in-warrant with scope attenuation per hop; **C-7** PEP authorizes against the *originating principal*, not the caller |
| T4 | Excessive agency / over-broad scope | ADV-1 | **C-8** mandate scope is an explicit allowlist of action classes with value bounds |
| T5 | Multi-agent laundering — malicious content re-emitted as `P4` agent output | ADV-3 | **C-9** provenance classes are *monotonic*: an agent's output inherits the lowest-trust class among its causal inputs. `P3`-influenced output cannot become `P2`. |
| T6 | Memory / context poisoning across sessions | ADV-1, ADV-3 | **C-10** stored memory retains its provenance class; recall re-tags rather than promoting to `P0` |
| T7 | Operator forges a favourable warrant | ADV-4 | **C-11** warrant is only valid with a transparency-log inclusion proof; **C-12** relying party verifies inclusion against an independently-witnessed root. **Scope: this makes a forged claim non-repudiable, not impossible — see §6.6** |
| T8 | Operator suppresses an inconvenient warrant | ADV-4 | **C-13** append-only log with consistency proofs; **root-forks** are externally detectable, and an unlogged *permit* is unusable because the relying party requires an inclusion proof. **Omission of a denial is not detectable — see §6.7** |
| T9 | Replay of a valid warrant onto a different action | ADV-1, ADV-3 | **C-14** warrant binds `argumentsHash` + nonce + short `validUntil`; PEP rejects mismatch or reuse |
| T10 | Attribution evasion — input crafted so ablation shows low influence | **ADV-5** | **C-15** multi-granularity ablation (segment, sentence, span); **C-16** low attribution *confidence* is itself a policy input, so "unattributable" fails closed rather than open |
| T11 | Cascading failure across an agent chain | ADV-3 | **C-17** chain depth limit and per-hop scope attenuation are policy-enforceable |
| T12 | Denial of service via attribution cost | ADV-1 | **C-18** consequential-action gate + result cache + hard per-mandate ablation budget |

**C-19 was added after the Phase 1 demo, not before it.** The first implementation classed
any pinned tool's response `P2`, which meant a supplier's poisoned invoice arrived wearing
the trust of the well-behaved reader that parsed it. The lesson generalizes: *tool integrity
and content provenance are different properties, and trust must attach to the origin of the
data rather than to the mechanism that delivered it.*

**C-9 (monotonic provenance) and C-16 (unattributable fails closed) are the two controls to
be able to defend in detail.** C-9 is what stops multi-agent laundering, which is the most
under-addressed threat in the current literature. C-16 is what prevents ADV-5 from turning
an evasion into a bypass: defeating attribution yields a *denied* action, not an approved one.

---

## 4. Mapping to OWASP Top 10 for Agentic Applications 2026

Identifiers per the OWASP GenAI Security Project list published 9 December 2025.

| OWASP | Title | Covered by | Coverage |
| --- | --- | --- | --- |
| ASI01 | Agent Goal Hijack | C-1, C-2, C-3 | **Primary** — this is the core case |
| ASI02 | Tool Misuse & Exploitation | C-4, C-5, C-8 | **Primary** |
| ASI03 | Identity & Privilege Abuse | C-6, C-7, C-8 | **Primary** |
| ASI04 | Agentic Supply Chain Vulnerabilities | C-5 | Partial — tool pinning only; not package supply chain |
| ASI05 | Unexpected Code Execution (RCE) | C-3, C-8 | Partial — governs *whether* code execution is admitted, not sandbox escape |
| ASI06 | Memory & Context Poisoning | C-10, C-9 | **Primary** |
| ASI07 | Insecure Inter-Agent Communication | C-6, C-9, C-11 | **Primary** — warrants travel with the action |
| ASI08 | Cascading Failures | C-11, C-17 | Partial — bounds propagation; does not solve availability cascades |
| ASI09 | Human-Agent Trust Exploitation | C-2, console UX | Partial — surfaces causal evidence to the human, but UX is not a hard control |
| ASI10 | Rogue Agents | C-6, C-13 | Partial — an unregistered agent cannot obtain valid warrants, but detection of rogue agents is out of scope |

Honest summary: AegisMesh is a **primary** control for five of ten and a **partial** control
for five. It is not a complete agent-security stack and should not be presented as one.

---

## 5. Mapping to EU AI Act Article 12

Article 12 requires high-risk AI systems to support automatic logging enabling traceability
of operation throughout the lifecycle. Enforceable from **2 August 2026**. No finalized
technical standard exists (prEN 18229-1 and ISO/IEC DIS 24970 remain drafts).

| Article 12 requirement | AegisMesh mechanism |
| --- | --- |
| Automatic recording of events over the lifetime | Every consequential action produces a warrant; every warrant is logged |
| Traceability of system operation | Delegation chain + causal attribution = a *causal* trace, not merely a chronological one |
| Identification of risk situations & substantial modifications | Policy version and tool-description hashes are recorded per action; drift is detectable |
| Records supporting post-market monitoring | Transparency log is queryable and exportable per mandate, principal, or action class |
| Integrity of records for supervisory audit | Merkle inclusion + consistency proofs; tamper-evidence survives a dishonest operator |

**Why a Merkle transparency log rather than a blockchain** — the design question a senior
reviewer will ask:

The requirement is *tamper-evidence and third-party verifiability*, not *decentralized
consensus*. A Certificate-Transparency-style Merkle log delivers append-only guarantees,
O(log n) inclusion proofs, and O(log n) consistency proofs at microsecond cost and
negligible operational burden. A blockchain would add consensus latency, cost per record,
and the compliance absurdity of publishing regulated financial metadata to a public chain —
while providing no integrity property the Merkle log lacks, given external witnesses.

The genuinely useful blockchain role is **root anchoring**: periodically publishing the
Merkle root to a public chain to obtain third-party timestamping that even a colluding
witness set cannot backdate. That is an *optional* enhancement in Phase 3, not the substrate.

---

## 6. Residual risk

Stated explicitly, because a threat model that claims full coverage is not credible.

1. **Provenance classification is itself an attack surface.** An adversary who gets content
   mislabelled `P0 human-mandate` defeats the entire chain. Classification correctness is the
   system's weakest link.

   Phase 4 measured the *downstream* half of this and not the mislabelling itself: over
   AgentDojo, every field the engine was willing to answer for was attributed to the class
   that genuinely supplied its value (class accuracy 1.000 across all placements and
   configurations). That is a statement about attribution given correct classification. The
   claim not made, and the one that matters here, is that the classifier resists an
   adversary trying to earn P0 — matching is strict-substring against a declared mandate
   precisely so that it cannot be approximated into, but no adversarial evaluation of the
   classifier has been run.
2. **Attribution is approximate.** Leave-one-out ablation measures counterfactual influence,
   not mechanistic causation. It can be fooled by redundant encoding — where content is
   duplicated so removing any single copy changes nothing. C-15 mitigates but does not
   eliminate this. Expect Phase 4 to find working evasions and report them.

   Phase 3 sharpened this into a specific, testable gap. The system now reports a field no
   single ablation moved as `invariant` rather than as unattributed, which is what lets a
   legitimately overdetermined field be admitted. But `invariant` does not on its own
   distinguish benign redundancy from adversarial redundancy.

   **Phase 4 built class-level ablation to separate them**, and fields now carry
   `per_argument_redundancy`: `within_class` means one provenance class controlled the value
   even though no single segment did, which on P3 is the ADV-5 signature. It works on
   constructed cases. It bought **nothing** on AgentDojo — those contexts average 3.24
   segments, so almost no class ever has the two segments the check needs, and it answered
   no field segment ablation had not already answered. The control exists and is off by
   default; the case for it rests on a constructed test, and the honest reading is that
   ADV-5 has a detector without a measurement.
3. ~~**Some fields cannot be attributed at all at current granularity.**~~ **Closed in
   Phase 4 by span-level ablation (C-15).** Ablating one written occurrence of a value
   leaves the sentence carrying the intent standing, so the action survives, the run is
   comparable, and the field is attributed. Over AgentDojo this moved the fields the engine
   would answer for from 33 of 79 to 68 of 79 at +5.5 model calls per action, precision
   unchanged. The residual is narrower: a field whose value never appears in the context in
   any recognizable written form still has no span to ablate.
4. **Attribution cost may be prohibitive** for high-throughput agents. Measured at 35.6
   model calls per consequential action over AgentDojo, 41.1 with span-level ablation, and
   one case hit the 400-call ceiling — a truncated attribution reports partial evidence,
   where an unablated segment's influence reads as zero for reasons unrelated to causation.
   All of it against a free in-process surrogate, so none of it establishes affordability at
   provider prices.
5. **Key compromise is unmitigated cryptographically.** Warrant forgery becomes possible with
   the issuer key. Operational controls only.
6. **The log proves what was said, not that it was true.** ADV-4 runs the issuer and can
   sign a warrant asserting the human caused a field the attacker set. The signature is
   genuine, the log entry is genuine, the inclusion proof is genuine, and every step of the
   relying party's verification passes. What the transparency log buys is
   **non-repudiation** — the claim is permanently and verifiably theirs — not prevention.
   C-11 and C-12 should be read that way.

   `attribution.replay_ref` (SPEC.md §4.4) commits under the signature to the exact
   classified context the measurement was taken over, so an auditor granted the trace can
   re-run the ablation and catch a discrepancy. That makes a lie **falsifiable**, which is
   the strongest property available short of attested execution. This is asserted by a test
   deliberately written to *pass* while the system is admitting a fraudulent action
   (`test_the_log_does_not_prove_the_attribution_is_true`).

   **Phase 4 built the re-run verifier** (`aegis/audit/replay.py`), and building it exposed
   that `replay_ref` did not commit to enough: `mode` and `drilldown_threshold` change the
   measurement and were not carried, so an issuer could have chosen flattering settings and
   never declared them. Both are now under the signature. Three limits remain, and they are
   the whole shape of what replay is worth:

   - It needs the **trace disclosed**, which is a far larger disclosure than a credential.
     An operator who refuses is not thereby contradicted.
   - `consistent` means *reproducible*, not *honest*. An operator running a doctored engine
     reproduces perfectly against their own binary; the property holds only because the
     auditor runs their own copy of the method and never calls back to the issuer.
   - `contradicted` is evidence, not intent. Silent provider-side model revision behind a
     stable `model_ref` produces the same verdict.
7. **Consistency proofs detect rewriting, not omission.** An entry never submitted leaves no
   gap; the tree is perfectly consistent without it. For permits this is harmless — the
   relying party will not honour an action without an inclusion proof, so an unlogged permit
   is unusable. For denials it is real: a suppressed denial is invisible, and what is lost
   is evidence rather than control. An operator who never logs its refusals produces an
   audit trail in which nothing ever went wrong.
8. **One witness is one point of trust.** The reference implementation runs a single witness.
   It detects a log that forks between the witness and another party — demonstrated in the
   Phase 3 demo — but does nothing about a witness that colludes with the operator, because
   then both sides of the comparison are the same party. *N* independent witnesses gossiping
   heads is the production answer and is out of scope here.
9. **The replay cache is local to one enforcement point.** Two PEPs do not share a nonce
   cache, so one warrant can be replayed once at each. Real deployments need a shared cache
   or an audience binding in the warrant. Also asserted by a passing test, so it cannot be
   quietly forgotten.
10. **The relying party must actually verify.** A PEP that is deployed but not enforced
    provides zero security while appearing to provide it — the single most likely real-world
    failure mode of this design.
11. **The consequential-action gate can be evaded by naming (ADV-7, open).** The gate
    classifies on the operation name, and an operation whose name contains only read verbs
    is never attributed, never warranted and never enforced — the whole system is off for
    that action. `check_out` charges a card; `lookup_settlement` moves money. Two further
    names found in the same sweep, `find_and_replace` and `describe_and_wire`, are caught
    only because `replace` and `wire` were added to the verb list in response, which is the
    shape of the problem rather than a fix: `settlement` evades a list containing `settle`
    by three letters, and the attacker picks the name.

    **The mitigation is not lexical.** An operator must classify consequential operations
    explicitly — `ConsequenceGate(consequential={...})` — and a tool nobody classified is
    already treated as consequential, so the read-verb branch is the only one that fails
    open. Narrowing it would make every `get_*` a candidate for attribution and multiply
    cost by the read/write ratio of the workload, which is why it has not simply been
    removed. Asserted by a test that passes while the bypass works
    (`test_an_operation_named_only_with_read_verbs_is_never_attributed`).
12. **Only the first proposed tool call used to be gated (ADV-6, fixed).** Parallel tool
    calls are ordinary in the OpenAI API. A model emitting `get_balance` alongside
    `execute_transfer` had the read gated as harmless and the transfer skipped entirely —
    a complete bypass reachable by an injection saying "check the balance first". The gate
    now evaluates every proposed call and attributes the first consequential one; ablations
    compare against the same operation rather than against whatever call arrived first, so
    a model that merely reorders its calls is not scored as having cancelled the action.

    Recorded here rather than quietly patched because it is the honest answer to a question
    this document has carried since Phase 0 and never tested, and because the failure was
    not in the gate's logic at all — it was in what the gate was shown.

---

## References

- OWASP Top 10 for Agentic Applications 2026, OWASP GenAI Security Project (Dec 2025)
- EU AI Act Article 12 — Record-keeping and automatic logging; enforceable 2 Aug 2026
- CoSAI Agentic Identity and Access Management framework (Apr 2026) — on-behalf-of token
  chains, scope attenuation, signed agent manifests
- Debenedetti et al., *AgentDojo* — evaluation benchmark used in Phase 4
- *CausalArmor*, *AgentSentry*, *Causal Agent Replay* — counterfactual attribution prior art
- RFC 6962 — Certificate Transparency, the Merkle log design AegisMesh follows
