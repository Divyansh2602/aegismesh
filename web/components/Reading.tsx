"use client";

import type { AttributedEventData } from "@/lib/api";
import { classColour, classLabel } from "@/lib/provenance";

/**
 * The measurement, in a sentence a non-technical reader can act on.
 *
 * Every clause is **derived from the measurement**, never written in advance. The words
 * come from the per-argument distribution the engine actually produced, so this cannot
 * describe a finding the run did not reach — which matters more here than anywhere else
 * on the page, because prose is the easiest place to smuggle in a claim nobody measured.
 *
 * It exists because "P3 1.0000 on destination_account" is the whole argument of this
 * project and is unreadable to the person who most needs to understand it.
 */
export function Reading({ attributed }: { attributed: AttributedEventData }) {
  const claims = Object.entries(attributed.argument_status)
    .filter(([, status]) => status === "attributed")
    .map(([field]) => {
      const shares = attributed.per_argument[field] ?? {};
      const [cls] =
        Object.entries(shares).sort((a, b) => Number(b[1]) - Number(a[1]))[0] ?? [];
      return cls ? { field, cls } : null;
    })
    .filter((c): c is { field: string; cls: string } => c !== null);

  if (claims.length === 0) return null;

  const distinct = new Set(claims.map((c) => c.cls));
  const split = distinct.size > 1;

  return (
    <div className="rounded-lg border border-line bg-sunken/60 px-5 py-4">
      <p className="text-[13.5px] leading-[1.7] text-ink-soft">
        {claims.map((claim, index) => (
          <span key={claim.field}>
            {index > 0 && <span className="text-ink-faint"> · </span>}
            <span style={{ color: classColour(claim.cls) }}>{classLabel(claim.cls)}</span>
            <span className="text-ink-faint"> set </span>
            <span className="mono text-ink">{claim.field}</span>
          </span>
        ))}
      </p>
      {split && (
        <p className="mt-2 text-[12px] leading-relaxed text-ink-faint">
          Two different causes inside one action. This is the case action-level attribution
          cannot express — averaged together, the untrusted contribution disappears into a
          number that looks acceptable.
        </p>
      )}
    </div>
  );
}
