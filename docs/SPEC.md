# AegisMesh — Action Warrant Specification

**Version:** 0.1 · **Date:** 2026-08-03 · **Status:** Phase 0 deliverable

Defines the Action Warrant credential, the provenance model it rests on, the policy language
that consumes it, the transparency-log format, and the verification algorithm a relying party
executes.

Design constraint throughout: **the relying party must be able to verify a warrant knowing
only the issuer's public key and the transparency log's public key.** No shared secrets, no
API call back to the issuer, no trust in the operator.

---

## 1. Terminology

| Term | Meaning |
| --- | --- |
| **Principal** | The human who issues a mandate. Identified by a DID. |
| **Mandate** | A scoped, time-bounded grant of authority from a principal to an agent. |
| **Agent** | An LLM-driven actor. Identified by a DID; may hold a signed manifest. |
| **Action** | A proposed tool invocation: `(tool, operation, arguments)`. |
| **Consequential action** | An action with external side effects — write, send, pay, delete, execute. Only these require warrants. |
| **Warrant** | A signed credential admitting one specific action. |
| **Relying party** | The service asked to honor the action. Runs the PEP. |
| **Receipt** | Proof that a warrant was included in the transparency log. |

---

## 2. Provenance model

Every segment of context entering the model is assigned exactly one **provenance class**.

| Class | Name | Source | Trust |
| --- | --- | --- | --- |
| `P0` | `human-mandate` | Authenticated instruction from the principal | Highest |
| `P1` | `system-policy` | Operator-configured system prompt / policy | High |
| `P2` | `trusted-tool` | Response from a pinned **closed-world** tool | Medium |
| `P3` | `untrusted-external` | Web, email, documents, unpinned MCP servers | **None** |
| `P4` | `agent-generated` | Output of this or another agent | Derived — see §2.2 |

### 2.0 Tool integrity is not content provenance

Pinning a tool establishes that **the tool** is authentic and does its job faithfully. It
establishes nothing about **the data the tool returns**. Conflating the two is a live
vulnerability, and it is subtle enough that the reference implementation shipped it before
the Phase 1 demo exposed it.

Tools are therefore split:

- **Conduit tools** relay content from outside the trust boundary — PDF readers, web
  fetchers, email clients, search. Their responses are attacker-influenced *by design*, so
  they are classed `P3` **even when pinned**. Pinning `invoice_reader` proves it parses PDFs
  faithfully; it says nothing about whether the supplier who wrote the PDF is honest, and
  the PDF is exactly where injections live.
- **Closed-world tools** return operator-controlled data only — an internal ledger lookup, a
  policy table. Their responses may be classed `P2`.

The registry flag is `relays_external_content`, defaulting to **True**: an unreviewed tool is
assumed to touch the outside world.

### 2.1 Segment record

```jsonc
{
  "segment_id": "seg_01J8...",        // ULID, stable across the request
  "class": "P3",
  "source": {
    "kind": "tool_response",           // user_input | system | tool_response | memory_recall | agent_message
    "origin": "mcp://vendor.example/invoice_reader",
    "retrieved_at": "2026-08-03T10:14:02Z",
    "content_hash": "sha256:9f2a..."
  },
  "span": { "start": 4211, "end": 5033 },   // byte offsets in the assembled context
  "parent_segments": ["seg_01J7..."]        // for P4, the causal inputs
}
```

### 2.2 Monotonicity rule (control C-9)

> An agent-generated segment inherits the **lowest-trust class among the segments that
> causally influenced it**, above an influence threshold θ.

Formally, for a `P4` segment *s* with causal parents `parents(s)`:

```
class(s) = min_trust({ class(p) : p ∈ parents(s), influence(p → s) ≥ θ })
```

This is the control that stops multi-agent laundering. Without it, an attacker injects into
agent A, A summarizes the poisoned content, and agent B receives the summary as trusted
`P4` peer output — the injection has been laundered clean across a trust boundary. With it,
a `P3`-influenced summary stays `P3` forever.

θ is a tunable; default `0.15`. It is a security/utility knob and must be swept in Phase 4.

---

## 3. Causal attribution

### 3.1 Method

**Leave-one-out counterfactual ablation.** For a proposed action *a* with argument set *A*,
and each candidate segment *s*:

1. Reconstruct the context with *s* removed (or replaced by a neutral placeholder of similar
   length, to control for position and length effects).
2. Re-execute the decision step at temperature 0 with a fixed seed where the provider
   supports it.
3. Record whether the same tool is called, and per argument field, whether the value is
   unchanged.

Influence of *s* on field *f*:

```
influence(s, f) = 1 - agreement(f | context)   over n resamples
```

Influence is aggregated to the class level:

```
influence(class c, field f) = Σ_{s : class(s) = c} influence(s, f)
```

then normalized to a distribution over classes.

**Why this method:** it is black-box, so it works against any hosted API model without
logits, attention, or gradients. Attention-based attribution is cheaper but unavailable on
commercial endpoints and is a poor proxy for causal influence.

**Multi-granularity (control C-15):** ablation runs at segment, sentence, and span level.
Redundant-encoding attacks that survive segment-level ablation frequently fail at span level.

### 3.2 Necessity is not value-causation

Removing the human's mandate typically cancels the action outright. That proves the mandate
was *necessary* for the action to occur, and says nothing about which account the money went
to — in the counterfactual there was no account to compare.

Per-field influence is therefore measured **only over ablations where the same tool was
still called**, i.e. conditioned on the action surviving. Cancellations are recorded
separately as `necessity`. The two are never summed. Scoring cancellation as field-level
influence made the human mandate look like the cause of an attacker-supplied destination,
which is precisely backwards.

### 3.3 Three outcomes per field, not two

An all-zero field score has two incompatible causes, and collapsing them is a defect:

- **`invariant`** — comparable runs happened and none changed the value. The field is
  overdetermined (several sources name the same value) or independent of context.
  Every class is *measured* zero.
- **`unknown`** — every ablation cancelled the action, so no comparable run exists. Nothing
  was measured at all.

Only `unknown` is grounds to fail closed. Normalizing an `invariant` field's zeros into a
uniform distribution fabricates influence for classes shown to have none — see §4.3.

A known consequence of §3.2 that this exposes: **a field whose only determining segment is
also the segment whose removal cancels the action can never be attributed at segment or
sentence granularity.** The amount in the invoice scenario is the worked example — it
appears only in the human's mandate, and removing that mandate removes the transfer intent
along with it, so no comparable counterfactual exists. Separating the two would need
span-level ablation (control C-15), which is specified and not yet implemented.

### 3.4 Confidence

```
confidence = 1 - H(influence_distribution) / log|classes|
```

Reported at both action level and per argument. **The per-argument number is the meaningful
one.** An action-level figure averages away the case this system exists for: an action
simultaneously legitimate in one field and hijacked in another scores near-uniform overall
while the hijacked field is attributed with certainty.

Low confidence is **not** treated as "safe". Per control C-16, policy may require a minimum
confidence, so an unattributable action **fails closed**. This is what makes attribution
evasion (ADV-5) yield a denial rather than a bypass.

### 3.5 Cost gate

Ablation costs *O(|segments| × n)* model calls, so it is gated:

1. A cheap classifier decides whether the proposed action is **consequential**. Non-consequential
   actions (reads, searches) skip attribution entirely.
2. Results are cached on `(context_hash, action_hash)`.
3. A per-mandate ablation budget bounds worst-case cost (control C-18).

Expected: attribution runs on a small minority of actions. **The measured ratio and cost per
consequential action are Phase 4 headline results** — they determine deployability.

---

## 4. The Action Warrant

A W3C Verifiable Credential. Conforming to the VC data model rather than inventing a format
is deliberate: it interoperates with the emerging CoSAI/DID/KYA-OS identity stack.

```jsonc
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://aegismesh.dev/ns/warrant/v1"
  ],
  "type": ["VerifiableCredential", "ActionWarrant"],
  "id": "urn:uuid:6f3c...",
  "issuer": "did:web:aegis.acme-bank.example",
  "validFrom": "2026-08-03T10:14:07Z",
  "validUntil": "2026-08-03T10:19:07Z",     // short-lived; 5 min default

  "credentialSubject": {

    "action": {
      "tool": "treasury.payments",
      "operation": "execute_transfer",
      "arguments_hash": "sha256:7c1d...",   // canonical JSON (RFC 8785 JCS)
      "arguments_digest_map": {             // per-field, enables field-level policy
        "amount":              "sha256:aa31...",
        "destination_account": "sha256:04be...",
        "reference":           "sha256:d19f..."
      },
      "nonce": "01J8ZQ...",                 // replay protection
      "consequential": true
    },

    "mandate": {
      "id": "mnd_01J8Y...",
      "principal": "did:web:acme-bank.example:users:r.mehta",
      "authenticated_at": "2026-08-03T09:58:11Z",
      "auth_method": "oidc+mfa",
      "scope": {
        "action_classes": ["treasury.payments:execute_transfer"],
        "constraints": { "amount_max": 5000000, "currency": ["USD"] }
      },
      "expires_at": "2026-08-03T17:00:00Z"
    },

    "delegation_chain": [
      { "hop": 0, "actor": "did:web:...:users:r.mehta", "kind": "human",
        "scope": ["treasury.payments:*"] },
      { "hop": 1, "actor": "did:web:...:agents:procurement-orchestrator",
        "kind": "agent", "manifest_hash": "sha256:31ff...",
        "scope": ["treasury.payments:execute_transfer"],
        "attenuated": true },
      { "hop": 2, "actor": "did:web:...:agents:invoice-processor",
        "kind": "agent", "manifest_hash": "sha256:8b02...",
        "scope": ["treasury.payments:execute_transfer"],
        "attenuated": true }
    ],

    "attribution": {
      "method": "loo-ablation",
      "method_version": "0.1.0",
      "granularity": ["segment", "sentence"],
      "resamples": 3,
      "model_ref": "groq/llama-3.3-70b@2026-07",

      // Every score is a fixed-precision STRING. See 4.2 -- this is a wire-format
      // requirement, not a serialization detail.
      "influence": {                        // action-level, normalized
        "P0": "0.0900", "P1": "0.0200", "P2": "0.0200", "P3": "0.8700"
      },
      "necessity": {                        // which classes the action *required*
        "P0": "1.0000"
      },
      "per_argument": {
        "amount":              {},          // empty: see argument_status below
        "destination_account": { "P0": "0.0900", "P2": "0.0400", "P3": "0.8700" }
      },
      "argument_status": {
        "amount":              "invariant",
        "destination_account": "attributed"
      },
      "per_argument_confidence": {
        "amount":              "0.0000",
        "destination_account": "0.8100"
      },
      "top_contributors": [
        { "segment_id": "seg_01J8...", "class": "P3",
          "origin": "mcp://vendor.example/invoice_reader",
          "influence": "0.6200", "excerpt_hash": "sha256:c0a1...",
          "granularity": "sentence" }
      ],
      "confidence": "0.8100",

      // What an auditor needs to re-run the measurement and check it (4.3).
      "replay_ref": {
        "trace_hash": "sha256:c035...",
        "segment_hashes": ["sha256:1a2b...", "sha256:9f2a..."],
        "model_ref": "groq/llama-3.3-70b@2026-07",
        "method_version": "0.1.0",
        "seed": 7
      }
    },

    "policy_decision": {
      "policy_id": "acme.treasury.v4",
      "policy_version": "4.2.1",
      "policy_hash": "sha256:5e77...",
      "decision": "deny",                   // permit | deny | permit_with_obligations
      "rules_fired": ["require_human_intent_on_destination"],
      "obligations": []
    },

    "environment": {
      "tool_descriptions_hash": "sha256:ab99...",   // ASI04 drift detection
      "agent_runtime": "aegis-proxy/0.1.0"
    }
  },

  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-jcs-2022",
    "created": "2026-08-03T10:14:07Z",
    "verificationMethod": "did:web:aegis.acme-bank.example#key-1",
    "proofPurpose": "assertionMethod",
    "proofValue": "z3Mv..."
  }
}
```

### 4.1 Design notes

- **Excerpts are hashed, never embedded.** A warrant crosses organizational boundaries; it
  must not leak the content of the documents the agent read. The auditor can confirm a
  specific excerpt matches by hashing it, without the warrant carrying it.
- **`arguments_digest_map` enables field-level policy** without revealing values. A relying
  party already knows the arguments it received, so it recomputes and compares.
- **A `deny` decision is still signed and logged.** Denials are the evidence that the system
  worked, and suppressing them is exactly what ADV-4 would want to do.
- **`validUntil` is short** because a warrant authorizes one action, now — not a session.

### 4.2 Score encoding — normative

Version 0.1 of this document showed scores as JSON numbers. That was wrong and is corrected
here. **Every score in a warrant is a string at a fixed quantum**, and the rules below are
part of the wire format: two implementations that both skip one of them will still disagree,
and disagreement means an honest warrant reads as a forgery.

| Rule | Value |
| --- | --- |
| Quantum | `0.0001` — four decimal places, always present |
| Rounding mode | **`ROUND_HALF_EVEN`** |
| Order of operations | **normalize first, then round** |
| Sum of a rounded distribution | **not required to be `1.0000`** |
| Consumer type | arbitrary-precision decimal — **never `float`** |

*Why strings.* The warrant's whole purpose is that a third party in another language
recomputes our bytes and checks an Ed25519 signature over them. JCS mandates ECMAScript
`Number::toString`; a naive implementation emits its host language's float repr. Encoding
scores we control as decimal strings removes them from that argument entirely.

*Why normalize before rounding.* Rounding first lets the normalizing divisor differ between
implementations, which moves every value in the distribution.

*Why the sum is not checked.* Four independent roundings routinely land on `0.9999` or
`1.0001`. A verifier that demands an exact sum rejects honest warrants — this is an easy
check to add in good faith and it must not be added.

*Why decimal at the consumer.* Parsing back to `float` at the policy enforcement point
reintroduces the same class of error one layer below, where it presents as a comparison
being subtly wrong rather than as a serialization mismatch.

Numbers that are *not* scores — `resamples`, `hop`, `leaf_index`, and tool-call arguments —
remain JSON numbers, because they arrive from elsewhere and we do not control their form.
For those, `common/hashing.py` implements RFC 8785 number serialization properly.

### 4.3 `argument_status` — normative

`per_argument` alone cannot distinguish two very different findings, because both appear as
an absence of weight:

| Status | Meaning | Policy consequence |
| --- | --- | --- |
| `attributed` | Some class measurably set this value. | The distribution is meaningful. |
| `invariant` | Comparable ablations ran and none changed the value. The field is overdetermined or context-independent; no class was pivotal. | Every class is *measured* zero. Not grounds to fail closed. |
| `unknown` | Every ablation cancelled the action, so no comparable run exists. Nothing was measured. | **Fail closed** (control C-16). |

Conflating `invariant` with `unknown` is not a theoretical concern: it denied the
legitimate invoice payment in the Phase 3 demo. A destination account named by both the
human's mandate and the operator's own ledger survives the removal of either, so
leave-one-out measures no pivotal cause — and encoding that as a *uniform* distribution
asserts a `0.2` untrusted share that no measurement supports, tripping any policy that
forbids untrusted influence on that field.

Redundancy is the normal case for legitimate actions. A design that cannot express it
fails asset A6.

### 4.4 `replay_ref`

The transparency log proves an issuer *said* something. It does not prove the statement was
true, and ADV-4 runs the issuer. `replay_ref` commits, under the signature, to the exact
classified context the attribution was measured over — the ordered segment hashes, the
trace hash, the model reference, and the method version — so that an auditor granted the
underlying trace can re-run the ablation and compare. That does not prevent a lie; it makes
one **falsifiable**, which is the strongest property available short of attested execution.

The fields are emitted from Phase 3 even though the re-run verifier is Phase 4 work,
because they sit under the signature: adding them later would invalidate every warrant
already issued or fork the format.

`seed` is recorded, not relied upon. Many hosted APIs accept a seed without honouring it,
so reproducibility rests on `model_ref` pinning — and even that degrades across provider
version drift.

---

## 5. Transparency log

Append-only Merkle tree, RFC 6962 in structure.

**Leaf:** `sha256(0x00 || JCS(warrant))`
**Node:** `sha256(0x01 || left || right)`

### 5.1 Receipt

Returned on submission; the relying party requires it.

```jsonc
{
  "log_id": "did:web:log.aegismesh.example",
  "leaf_index": 148213,
  "tree_size": 148214,
  "root_hash": "sha256:e41c...",
  "inclusion_proof": ["sha256:...", "sha256:..."],   // audit path, O(log n)
  "signed_root": {
    "timestamp": "2026-08-03T10:14:08Z",
    "signature": "z5Hq..."                            // log's Ed25519 signature over (size, root, ts)
  }
}
```

### 5.2 Proofs supported

- **Inclusion** — this warrant is in the log at this root.
- **Consistency** — root *R₂* at size *n₂* is an append-only extension of root *R₁* at size
  *n₁*. This is what makes **rewriting** detectable (control C-13).

**Consistency proofs detect rewriting, not omission.** An entry that was never submitted
leaves no gap to find; the tree is perfectly consistent without it. For *permits* this is
harmless, because a relying party will not honour an action without an inclusion proof, so
an unlogged permit is unusable. For *denials* it is real: a suppressed denial is simply
invisible, and what is lost is evidence rather than control.

### 5.3 Witnesses

A witness is a party in a different trust domain that holds the last signed tree head it
accepted and verifies a consistency proof before accepting the next one. It is what makes
verification step 7 meaningful; without one, nothing distinguishes this design from an
internal audit log.

The reference implementation runs **one** witness, which is enough to demonstrate the
mechanism and not enough to deploy. A single witness detects a log that forks between it and
someone else. It does nothing about a witness that colludes with the operator, because then
both sides of the comparison are the same party. The production answer is *N* independent
witnesses gossiping heads, so a fork must fool all of them at once. That is out of scope
here and is stated in THREAT_MODEL.md §6 as residual risk rather than assumed away.

### 5.4 Optional public anchoring

Merkle roots may be periodically published to a public chain (Polygon) purely for
third-party timestamping. Records are never published — only roots. See `THREAT_MODEL.md` §5
for why the log itself is not a blockchain.

---

## 6. Policy language

Declarative, Rego-influenced. Evaluated by the PEP at the relying party.

```rego
package aegis.treasury

default decision := "deny"

# Untrusted external content must not touch where the money goes, at all.
deny contains "no_untrusted_influence_on_destination" if {
    input.attribution.per_argument.destination_account.P3 > 0.05
}

# Nothing measurable about the destination at all -- fail closed  (control C-16).
deny contains "destination_not_attributable" if {
    input.action.operation == "execute_transfer"
    input.attribution.argument_status.destination_account == "unknown"
}

# A high-value destination attributed to something other than the human principal.
# The status guard is load-bearing -- see below.
deny contains "require_human_intent_on_destination" if {
    input.action.operation == "execute_transfer"
    amount_exceeds(10000)
    input.attribution.argument_status.destination_account == "attributed"
    input.attribution.per_argument.destination_account.P0 < 0.70
}

# Coarse floor on action-level attribution confidence.
deny contains "attribution_confidence_too_low" if {
    input.attribution.confidence < 0.60
}

# Bound the delegation chain  (control C-17).
deny contains "chain_too_deep" if {
    count(input.delegation_chain) > 3
}

decision := "permit" if { count(deny) == 0 }
```

### 6.1 The guard on `require_human_intent_on_destination`

Version 0.1 of this document wrote that rule without the `argument_status` guard, as a bare
threshold on `P0`. Implementing it in Phase 3 denied the *legitimate* invoice payment.

In the clean case the destination account appears in both the human's mandate and Acme's
own ledger. Removing either leaves the other, so no single ablation changes the value and
`P0` is not `0.70` — it is zero, because nothing was pivotal. The rule as originally written
demands positive human causation for a value that is legitimately overdetermined, which no
correctly attributed redundant field can ever satisfy.

The corrected rule applies when the field *was* attributed to some class and that class was
not the human. Fields nothing was pivotal for are handled by
`no_untrusted_influence_on_destination` and `destination_not_attributable` instead.

This is asset A6 in practice: a control that blocks legitimate work gets switched off, and
then protects nothing.

### 6.2 Evaluation semantics — normative

- **Conditions are evaluated in order and short-circuit.** Order is part of a rule's
  meaning: guards come first, so a rule that does not apply never reaches its later lookups.
- **A condition that cannot be resolved makes its rule fire.** A rule that applies but
  cannot be evaluated denies. Skipping it would let malformed input turn a control off.
- **Missing numeric paths under `attribution.influence`, `attribution.necessity`,
  `attribution.per_argument` and `attribution.per_argument_confidence` resolve to zero**,
  because a distribution omits classes below the noise floor — an absent class is the
  encoding of "caused nothing". `attribution.argument_status` is deliberately excluded:
  a missing status is a genuine unknown.
- **Comparisons are decimal.** Never `float`. See §4.2.
- **Rules are data, not code.** Conditions are declared as path/operator/value triples so
  that `policy_hash` covers the entire policy. A rule implemented as a callable would make
  the hash a claim about a name while the behaviour lived in a function body nobody
  committed to.

Policies are versioned and hashed; the hash is recorded in the warrant so that any decision
can be replayed against the exact policy that produced it. The hash covers the rule set, the
thresholds, the default decision and the **engine version** — but not the evaluator's source.
A policy hash identifies the rules, not the code that ran them.

---

## 7. Verification algorithm (relying party)

Executed by `aegis-pep` before honoring an action. Any failure ⇒ reject.

1. **Parse** the warrant; reject unknown `@context` or `type`.
2. **Resolve** `issuer` DID → public key. Reject if the key is unknown, expired, or revoked.
3. **Verify signature** over the JCS-canonicalized credential.
4. **Check validity window**: `validFrom ≤ now ≤ validUntil`.
5. **Bind to this action**: recompute `arguments_hash` from the arguments actually received
   and compare. Reject on mismatch — this defeats replay onto a different action (C-14).
6. **Check nonce** against a replay cache covering at least the validity window.
7. **Verify log inclusion**: check the inclusion proof against a `root_hash` that the relying
   party obtained *independently* — from its own witness or a gossip peer, never from the
   operator. **This step is what defends against ADV-4 and is non-optional.** Without a
   party in another trust domain holding that root, the operator supplies the warrant, the
   receipt, *and* the root to check it against, and the exercise proves only that the
   operator is internally consistent — which a forger would also be. A receipt whose
   `tree_size` exceeds what the witness has accepted is rejected: an operator must not be
   able to get ahead of its witness and settle up later.
8. **Verify delegation chain**: each hop's scope is a subset of the previous hop's
   (attenuation), the chain terminates at the named principal, and every agent manifest hash
   is known.
9. **Check mandate**: not expired, and this action class ∈ `mandate.scope.action_classes`,
   with constraints satisfied.
10. **Evaluate local policy** against the attribution evidence. The relying party's policy is
    authoritative — the issuer's `policy_decision` is *evidence*, not a verdict. A relying
    party that simply trusts the issuer's verdict has learned nothing from the warrant.
11. **Emit** its own decision record to the log.

Step 10 is the crux of the design. The issuer says what it concluded; the relying party
decides for itself using evidence it can verify.

---

## 8. Interfaces (Phase 1+)

```
POST /v1/intercept/chat/completions   OpenAI-compatible; provenance-tagging passthrough
POST /v1/intercept/messages           Anthropic-compatible
ANY  /v1/intercept/mcp/*              MCP proxy; classifies tool descriptions & responses

POST /v1/attribute                    { context_id, proposed_action } -> attribution
POST /v1/warrant                      { action, mandate, attribution } -> warrant + receipt
GET  /v1/warrant/{id}
POST /v1/log/entries                  -> receipt
GET  /v1/log/proof/inclusion?leaf=&size=
GET  /v1/log/proof/consistency?from=&to=
GET  /v1/log/sth                      signed tree head
POST /v1/verify                       { warrant, receipt, arguments } -> decision + reasons
```

---

## 9. Open questions for later phases

1. What is θ (monotonicity threshold) in practice? Sweep in Phase 4.
2. Does span-level ablation actually defeat redundant-encoding attacks, or only raise cost?
   It is now also the only route to attributing a field entangled with the transfer intent
   in the same segment — see §3.3.
3. Can the consequential-action classifier itself be attacked into classifying a payment as
   non-consequential? **Probable. Must be tested — it is a single point of bypass.**
4. What is the real cost per consequential action, and is it acceptable?
5. Does a neutral placeholder control for position effects better than deletion, or introduce
   its own bias?
6. `invariant` currently means "no single segment was pivotal". It does not distinguish
   *benign* redundancy (the human and the ledger agree) from *adversarial* redundancy — an
   attacker who plants the same value twice so that no single ablation moves it. Class-level
   ablation, removing every segment of one class at once, would separate them at a cost of
   |classes| extra calls. Untested, and it is the most likely place an ADV-5 evasion lives.
7. Does per-argument confidence carry policy weight that action-level confidence does not?
   The action-level floor of 0.60 fires on a legitimate action split evenly between two
   trusted classes, which looks like a false-positive generator waiting for a real workload.
8. Sentence-level ablations are measured but do not feed `per_argument` or
   `argument_status`, which are computed from segment-level results only. A field
   attributable at sentence granularity but not segment granularity is therefore reported
   as `invariant`. Whether folding them in improves accuracy or just adds variance is a
   Phase 4 measurement.

---

## References

- W3C Verifiable Credentials Data Model 2.0
- RFC 8785 — JSON Canonicalization Scheme (JCS)
- RFC 6962 — Certificate Transparency
- CoSAI Agentic Identity and Access Management (Apr 2026)
- OWASP Top 10 for Agentic Applications 2026
