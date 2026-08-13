"use client";

import { useEffect, useState } from "react";
import {
  ApiError,
  api,
  downloadArtifact,
  type ArtifactBundle,
  type ReplayReport,
  type WitnessState,
} from "@/lib/api";
import { Button } from "@/components/Button";
import { Hash } from "@/components/Hash";

const FILES = ["warrant", "receipt", "trust_anchors"] as const;

const VERIFY_COMMAND =
  "python tools/verify_warrant.py \\\n    warrant.json \\\n    receipt.json \\\n    trust_anchors.json";

/**
 * What a third party who trusts nobody gets.
 *
 * The download is the strongest thing this project can offer, and it is worth being
 * precise about why: the three files verify **on the visitor's own laptop, offline, with
 * no shared secret** — two public keys and a root hash obtained from a witness in a
 * different trust domain than the issuer. Every other product in this space asks you to
 * trust its dashboard.
 *
 * Replay is the second, different claim. Authenticity says the warrant is genuinely the
 * issuer's; replay asks whether the numbers *inside* it reproduce. An operator can sign a
 * lie and have every signature check pass, so the lie has to be falsifiable separately.
 */
export function AuditorView({ session, runId }: { session: string; runId: string }) {
  const [bundle, setBundle] = useState<ArtifactBundle | null>(null);
  const [witness, setWitness] = useState<WitnessState | null>(null);
  const [replay, setReplay] = useState<ReplayReport | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    let cancelled = false;
    Promise.all([api.artifacts(session, runId), api.witness(session)])
      .then(([artifacts, witnessState]) => {
        if (cancelled) return;
        setBundle(artifacts);
        setWitness(witnessState);
      })
      .catch((caught) => {
        if (!cancelled) setError(caught instanceof Error ? caught.message : String(caught));
      });
    return () => {
      cancelled = true;
    };
  }, [session, runId]);

  const verify = async () => {
    setBusy(true);
    setError(null);
    try {
      setReplay(await api.replay(session, runId));
    } catch (caught) {
      const message =
        caught instanceof ApiError
          ? `${caught.control ? `[${caught.control}] ` : ""}${caught.message}`
          : String(caught);
      setError(message);
    } finally {
      setBusy(false);
    }
  };

  const copyCommand = async () => {
    try {
      await navigator.clipboard.writeText(VERIFY_COMMAND.replace(/\\\n\s+/g, " "));
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      /* the command is on screen either way */
    }
  };

  if (error && !bundle) {
    return (
      <section className="card p-6">
        <h3 className="label">Auditor view</h3>
        <p className="mono mt-3 text-[12px] text-ink-soft">{error}</p>
      </section>
    );
  }

  return (
    <section className="card p-6">
      <h3 className="label">What an auditor gets</h3>
      <p className="mt-2 max-w-2xl text-[13px] leading-relaxed text-ink-soft">
        Two public keys and one root hash the witness accepted. Nothing else — no account,
        no network call to us, no shared secret.
      </p>

      {/* ------------------------------------------------------------- the download */}
      <div className="mt-6 rounded-lg border border-accent/25 bg-accent-soft/60 p-5">
        <p className="text-[13px] font-medium text-ink">Verify it yourself, offline</p>
        <p className="mt-1.5 text-[12.5px] leading-relaxed text-ink-soft">
          Download all three, then run the standalone verifier from the repository root.
          It makes no network calls and holds nothing but the two keys and the root.
        </p>

        <div className="mt-4 flex flex-wrap gap-2">
          {FILES.map((name) => (
            <Button
              key={name}
              variant="quiet"
              onClick={() => downloadArtifact(session, runId, name).catch(() => undefined)}
            >
              ↓ {name}.json
            </Button>
          ))}
        </div>

        <button
          type="button"
          onClick={copyCommand}
          className="mono mt-4 block w-full rounded-md border border-line bg-surface px-3.5 py-3 text-left text-[11.5px] leading-relaxed text-ink transition-colors hover:border-line-strong"
          aria-label="Copy the verification command"
        >
          <span className="text-ink-faint">$ </span>
          {VERIFY_COMMAND.split("\n").map((line, index) => (
            <span key={line} className={index > 0 ? "block" : undefined}>
              {line}
            </span>
          ))}
          <span className="mt-2 block text-[10.5px] text-ink-faint">
            {copied ? "copied" : "click to copy"} · expected: 6/6 checks passed
          </span>
        </button>
      </div>

      {/* --------------------------------------------------------------- the proofs */}
      {bundle && witness && (
        <dl className="mono mt-6 grid gap-x-8 gap-y-4 border-t border-line pt-5 text-[11px] sm:grid-cols-2">
          <Field term="Leaf index">
            <span className="tnum">
              {bundle.receipt.leaf_index} of {bundle.receipt.tree_size}
            </span>
          </Field>
          <Field term="Inclusion proof">
            <span className="tnum">{bundle.receipt.inclusion_proof.length} hashes</span>
          </Field>
          <Field term="Witnessed root" wide>
            <Hash value={bundle.trust_anchors.witnessed_root} head={26} tail={10} label="root" />
          </Field>
          <Field term="Issuer key" wide>
            <Hash
              value={bundle.trust_anchors.issuer_public_key_multibase}
              head={26}
              tail={10}
              label="issuer public key"
            />
          </Field>
          <Field term="Log key" wide>
            <Hash
              value={bundle.trust_anchors.log_public_key_multibase}
              head={26}
              tail={10}
              label="log public key"
            />
          </Field>
        </dl>
      )}

      {witness && (
        <p className="mt-4 text-[12px] leading-relaxed text-ink-faint">
          The witness has accepted{" "}
          <span className="mono tnum text-ink-soft">{witness.tree_size}</span> entries and{" "}
          {witness.root ? "serves a root" : "serves no root — it has seen a fork"}. Inclusion
          is checked against that root, never against the one the operator supplied with the
          receipt.
        </p>
      )}

      {/* --------------------------------------------------------------- the replay */}
      <div className="mt-6 border-t border-line pt-6">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="max-w-lg">
            <p className="text-[13px] font-medium text-ink">Re-measure the attribution</p>
            <p className="mt-1.5 text-[12.5px] leading-relaxed text-ink-soft">
              Every check above proves the warrant is <em>authentic</em>. None of them touch
              whether the numbers inside it are <em>true</em>. Replay re-runs the same
              measurement under the conditions the warrant committed to.
            </p>
          </div>
          <Button onClick={verify} disabled={busy} variant="quiet">
            {busy && <span className="breathe h-1.5 w-1.5 rounded-full bg-accent" aria-hidden />}
            {busy ? "Replaying…" : "Replay"}
          </Button>
        </div>

        {error && bundle && (
          <p className="mono mt-3 text-[11.5px] text-reject">{error}</p>
        )}

        {replay && <ReplayOutcome report={replay} />}
      </div>
    </section>
  );
}

function ReplayOutcome({ report }: { report: ReplayReport }) {
  const colour =
    report.verdict === "consistent"
      ? "var(--permit)"
      : report.verdict === "contradicted"
        ? "var(--reject)"
        : "var(--p4)";

  return (
    <div className="mt-5">
      <div className="flex flex-wrap items-baseline gap-x-4 gap-y-1">
        <span className="text-[15px] font-medium" style={{ color: colour }}>
          {report.verdict}
        </span>
        <span className="mono tnum text-[11px] text-ink-faint">
          {report.checks} checks · {report.contradictions} contradictions ·{" "}
          {report.model_calls} model calls
        </span>
      </div>

      <ul className="mono mt-3 max-h-56 space-y-1 overflow-y-auto text-[11px]">
        {report.findings.map((finding) => (
          <li
            key={finding.check}
            className="flex items-baseline gap-2.5 border-b border-line/60 py-1.5 last:border-0"
          >
            <span
              className="w-3 shrink-0"
              style={{
                color:
                  finding.verdict === "consistent"
                    ? "var(--permit)"
                    : finding.verdict === "contradicted"
                      ? "var(--reject)"
                      : "var(--p4)",
              }}
            >
              {finding.verdict === "consistent" ? "✓" : finding.verdict === "contradicted" ? "✗" : "?"}
            </span>
            <span className="min-w-0 flex-1 truncate text-ink-soft" title={finding.check}>
              {finding.check}
            </span>
          </li>
        ))}
      </ul>

      <p className="mt-3 text-[11.5px] leading-relaxed text-ink-faint">{report.note}</p>
    </div>
  );
}

function Field({
  term,
  children,
  wide,
}: {
  term: string;
  children: React.ReactNode;
  wide?: boolean;
}) {
  return (
    <div className={wide ? "min-w-0 sm:col-span-2" : "min-w-0"}>
      <dt className="label">{term}</dt>
      <dd className="mt-1.5 min-w-0 text-ink-soft">{children}</dd>
    </div>
  );
}
