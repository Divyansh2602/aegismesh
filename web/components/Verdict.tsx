"use client";

import type { DecisionEventData } from "@/lib/api";
import { Hash } from "@/components/Hash";

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
}: {
  decision: DecisionEventData;
  issued?: { warrant_id: string; issuer_decision: string };
  logged?: { leaf_index: number; tree_size: number; root_hash: string };
}) {
  const admitted = decision.verdict === "PERMIT";
  const colour = admitted ? "var(--permit)" : "var(--reject)";

  return (
    <section className="card overflow-hidden">
      <div className="flex flex-wrap items-start justify-between gap-6 border-b border-line p-6">
        <div>
          <p className="label">The payment API decides</p>
          {/* Colour is applied inline from the CSS custom property: Tailwind resolves class
              names statically, so a constructed `text-${tone}` is never generated. */}
          <p className="serif mt-1.5 text-4xl leading-none" style={{ color: colour }}>
            {admitted ? "Permit" : "Reject"}
          </p>
        </div>
        {issued && (
          <div className="sm:text-right">
            <p className="label">The issuer merely claimed</p>
            <p className="mono mt-2 text-sm text-ink-soft">{issued.issuer_decision}</p>
            <p className="mt-1 text-[11.5px] text-ink-faint">a claim, not authority</p>
          </div>
        )}
      </div>

      <div className="p-6">
        {decision.reasons.length > 0 && (
          <ul className="space-y-2">
            {decision.reasons.map((reason) => (
              <li
                key={reason}
                className="flex gap-2.5 text-[13px] leading-relaxed text-ink-soft"
              >
                <span aria-hidden style={{ color: colour }}>
                  ›
                </span>
                {reason}
              </li>
            ))}
          </ul>
        )}

        <dl className="mono tnum mt-6 grid gap-x-8 gap-y-4 border-t border-line pt-5 text-[11px] sm:grid-cols-3">
          {decision.failed_steps.length > 0 && (
            <Field term="Failed steps">
              <span style={{ color: "var(--reject)" }}>{decision.failed_steps.join(", ")}</span>
            </Field>
          )}
          {logged && (
            <Field term="Log leaf">
              {logged.leaf_index} of {logged.tree_size}
            </Field>
          )}
          {issued && (
            <Field term="Warrant" wide>
              <Hash value={issued.warrant_id} head={22} tail={8} label="warrant id" />
            </Field>
          )}
          {logged && (
            <Field term="Witnessed root" wide>
              <Hash value={logged.root_hash} head={24} tail={10} label="root hash" />
            </Field>
          )}
        </dl>
      </div>
    </section>
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
    <div className={wide ? "min-w-0 sm:col-span-3" : "min-w-0"}>
      <dt className="label">{term}</dt>
      <dd className="mt-1.5 min-w-0 text-ink-soft">{children}</dd>
    </div>
  );
}
