"use client";

import type { DecisionEventData } from "@/lib/api";

/**
 * What the payment API decided, and — shown separately — what the issuer claimed.
 *
 * The two are never merged. A relying party that honoured the issuer's verdict would have
 * learned nothing from the warrant that an HTTP 200 could not have told it, so the
 * issuer's decision is rendered as a *claim* and visibly not as the authority.
 */
export function Verdict({
  decision,
  issued,
  logged,
  className = "",
}: {
  decision: DecisionEventData;
  issued?: { warrant_id: string; issuer_decision: string };
  logged?: { leaf_index: number; tree_size: number; root_hash: string };
  className?: string;
}) {
  const admitted = decision.verdict === "PERMIT";

  return (
    <div
      className={`overflow-hidden rounded-xl border bg-ink-raised ${className}`}
      style={{ borderColor: admitted ? "var(--permit)" : "var(--reject)" }}
    >
      <div
        className="flex flex-wrap items-center justify-between gap-4 px-6 py-5"
        style={{ background: admitted ? "rgba(52,211,153,0.06)" : "rgba(251,113,133,0.06)" }}
      >
        <div>
          <p className="mono text-[11px] uppercase tracking-[0.18em] text-text-faint">
            The payment API decides
          </p>
          {/* Written out rather than interpolated: Tailwind resolves class names
              statically, so a constructed `text-${tone}` is never generated. */}
          <p
            className="display mt-1 text-5xl uppercase"
            style={{ color: admitted ? "var(--permit)" : "var(--reject)" }}
          >
            {decision.verdict}
          </p>
        </div>
        {issued && (
          <div className="text-right">
            <p className="mono text-[11px] uppercase tracking-[0.18em] text-text-faint">
              The issuer merely claimed
            </p>
            <p className="mono mt-1 text-lg text-text-dim">{issued.issuer_decision}</p>
            <p className="mono mt-0.5 text-[10px] text-text-faint">a claim, not authority</p>
          </div>
        )}
      </div>

      <div className="border-t border-line px-6 py-5">
        {decision.reasons.length > 0 && (
          <ul className="space-y-1.5">
            {decision.reasons.map((reason) => (
              <li key={reason} className="flex gap-2.5 text-sm leading-relaxed text-text-dim">
                <span aria-hidden style={{ color: admitted ? "var(--permit)" : "var(--reject)" }}>
                  ›
                </span>
                {reason}
              </li>
            ))}
          </ul>
        )}

        <dl className="mono mt-5 flex flex-wrap gap-x-8 gap-y-3 border-t border-line pt-4 text-[11px]">
          {decision.failed_steps.length > 0 && (
            <div>
              <dt className="uppercase tracking-[0.14em] text-text-faint">Failed steps</dt>
              <dd className="mt-1 text-reject">{decision.failed_steps.join(", ")}</dd>
            </div>
          )}
          {issued && (
            <div className="min-w-0">
              <dt className="uppercase tracking-[0.14em] text-text-faint">Warrant</dt>
              <dd className="mt-1 truncate text-text-dim">{issued.warrant_id}</dd>
            </div>
          )}
          {logged && (
            <>
              <div>
                <dt className="uppercase tracking-[0.14em] text-text-faint">Log leaf</dt>
                <dd className="mt-1 text-text-dim">
                  {logged.leaf_index} of {logged.tree_size}
                </dd>
              </div>
              <div className="min-w-0 basis-full">
                <dt className="uppercase tracking-[0.14em] text-text-faint">Root</dt>
                <dd className="mt-1 truncate text-text-dim">{logged.root_hash}</dd>
              </div>
            </>
          )}
        </dl>
      </div>
    </div>
  );
}
